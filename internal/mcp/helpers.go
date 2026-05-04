package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// defaultListLimit is the default number of sessions returned when limit is not specified.
const defaultListLimit = 50

// maxListLimit is the maximum allowed value for limit to prevent OOM from unbounded queries.
const maxListLimit = 1000

// defaultReplayTimeout is the default timeout for replay HTTP requests.
const defaultReplayTimeout = 30 * time.Second

// allowedSchemes are the URL schemes permitted for replay requests.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// validateHeaderValues checks that header keys and values do not contain CR or LF
// characters, which would enable HTTP header injection (CWE-113).
func validateHeaderValues(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("header key %q contains CR/LF characters", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("header value for %q contains CR/LF characters", k)
		}
	}
	return nil
}

// validateHeaderKeys checks that header key names do not contain CR or LF characters.
func validateHeaderKeys(keys []string) error {
	for _, k := range keys {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("header key %q contains CR/LF characters", k)
		}
	}
	return nil
}

// httpDoer abstracts HTTP request execution for testability.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// rawDialer abstracts raw TCP/TLS connection creation for testability.
type rawDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// validateURLScheme checks that the URL uses an allowed scheme (http or https).
func validateURLScheme(u *url.URL) error {
	if !allowedSchemes[u.Scheme] {
		return fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", u.Scheme)
	}
	return nil
}

// encodeBody returns the body as a string with its encoding type.
// If the body is valid UTF-8 text, it is returned as-is with encoding "text".
// Otherwise, it is Base64-encoded with encoding "base64".
func encodeBody(body []byte) (string, string) {
	if len(body) == 0 {
		return "", "text"
	}
	if utf8.Valid(body) {
		return string(body), "text"
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

// formatFingerprint formats a byte slice as a colon-separated uppercase hex string.
// For example: "AB:CD:EF:01:23:45:...".
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// connInfoResult is the connection metadata in the get_session/query response.
type connInfoResult struct {
	// ClientAddr is the client's remote address (e.g., "192.168.1.100:54321").
	ClientAddr string `json:"client_addr,omitempty"`
	// ServerAddr is the upstream server's resolved address.
	ServerAddr string `json:"server_addr,omitempty"`
	// TLSVersion is the negotiated TLS version (e.g., "TLS 1.3").
	TLSVersion string `json:"tls_version,omitempty"`
	// TLSCipher is the negotiated TLS cipher suite name.
	TLSCipher string `json:"tls_cipher,omitempty"`
	// TLSALPN is the negotiated ALPN protocol.
	TLSALPN string `json:"tls_alpn,omitempty"`
	// TLSServerCertSubject is the subject DN of the upstream server certificate.
	TLSServerCertSubject string `json:"tls_server_cert_subject,omitempty"`
}

// checkTargetScopeURL checks a URL against the target scope rules.
// Returns nil if the target is allowed or if no rules are configured (open mode).
// Returns a descriptive error if the target is blocked.
func (s *Server) checkTargetScopeURL(u *url.URL) error {
	return checkTargetScopeURLHelper(s.connector.targetScope, u)
}

// checkTargetScopeURLHelper checks a URL against the given target scope rules.
// This is a standalone version of Server.checkTargetScopeURL for use by handler structs.
func checkTargetScopeURLHelper(ts *proxy.TargetScope, u *url.URL) error {
	if ts == nil || !ts.HasRules() {
		return nil
	}
	allowed, reason := ts.CheckURL(u)
	if !allowed {
		return fmt.Errorf("request blocked by target scope: host %q is %s", u.Hostname(), reason)
	}
	return nil
}

// checkTargetScopeAddr checks a host:port address against the target scope rules.
// The scheme is used for default port inference (e.g., "https" -> 443).
// Returns nil if the target is allowed or if no rules are configured (open mode).
// Returns a descriptive error if the target is blocked.
func (s *Server) checkTargetScopeAddr(scheme, addr string) error {
	return checkTargetScopeAddrHelper(s.connector.targetScope, scheme, addr)
}

// checkTargetScopeAddrHelper checks a host:port address against the given target scope rules.
// This is a standalone version of Server.checkTargetScopeAddr for use by handler structs.
func checkTargetScopeAddrHelper(ts *proxy.TargetScope, scheme, addr string) error {
	if ts == nil || !ts.HasRules() {
		return nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port, treat whole addr as hostname.
		host = addr
		portStr = ""
	}
	port := targetDefaultPort(scheme, portStr)
	allowed, reason := ts.CheckTarget(scheme, host, port, "")
	if !allowed {
		return fmt.Errorf("request blocked by target scope: host %q is %s", host, reason)
	}
	return nil
}

// checkSafetyInput validates request data against the safety filter engine.
// Returns nil if no safety engine is configured or if the input passes.
// Returns an InputViolation if the input is blocked.
func (s *Server) checkSafetyInput(body []byte, rawURL string, headers []exchange.KeyValue) *safety.InputViolation {
	if s.pipeline.safetyEngine == nil {
		return nil
	}
	return s.pipeline.safetyEngine.CheckInput(body, rawURL, headers)
}

// safetyViolationError returns a generic error message for MCP clients when a safety
// filter violation occurs. Details (rule ID, target, pattern) are logged server-side
// to prevent leaking filter internals to the AI agent, which could enable bypass attempts.
func safetyViolationError(v *safety.InputViolation) string {
	slog.Warn("SafetyFilter violation",
		"rule_id", v.RuleID,
		"rule_name", v.RuleName,
		"target", v.Target,
		"matched_on", v.MatchedOn,
	)
	return "SafetyFilter blocked this operation: request blocked by safety policy. " +
		"This payload was classified as destructive and cannot be sent."
}
