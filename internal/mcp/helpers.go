package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// defaultListLimit is the default number of sessions returned when limit is not specified.
const defaultListLimit = 50

// maxListLimit is the maximum allowed value for limit to prevent OOM from unbounded queries.
const maxListLimit = 1000

// defaultReplayTimeout is the default timeout for replay HTTP requests.
const defaultReplayTimeout = 30 * time.Second

// maxRedirects is the maximum number of HTTP redirects to follow.
const maxRedirects = 10

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

// validateHeaderEntries checks that header entries do not contain CR or LF
// characters in keys or values, which would enable HTTP header injection (CWE-113).
func validateHeaderEntries(entries HeaderEntries) error {
	for _, e := range entries {
		if strings.ContainsAny(e.Key, "\r\n") {
			return fmt.Errorf("header key %q contains CR/LF characters", e.Key)
		}
		if strings.ContainsAny(e.Value, "\r\n") {
			return fmt.Errorf("header value for %q contains CR/LF characters", e.Key)
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

// safeCheckRedirect validates redirect targets when follow_redirects is enabled.
// It enforces HTTP/HTTPS-only schemes and a maximum hop limit.
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("too many redirects: %d", len(via))
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-HTTP scheme: %s", req.URL.Scheme)
	}
	return nil
}

// NewDefaultHTTPClient returns an *http.Client with an explicit timeout and
// redirect suppression. It should be used for outbound HTTP requests initiated
// by user input (fuzz, resend, macro, etc.). Access control is handled at a
// higher level by the target scope enforcement layer (TargetScope).
func NewDefaultHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: defaultReplayTimeout,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   defaultReplayTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// rawDialerFunc returns the raw dialer to use for replay_raw connections.
// If a custom dialer is set (for testing), it is returned; otherwise,
// a default dialer with the replay timeout is returned.
// Access control is handled by the target scope enforcement layer.
func (s *Server) rawDialerFunc() rawDialer {
	if s.deps.rawReplayDialer != nil {
		return s.deps.rawReplayDialer
	}
	return &net.Dialer{
		Timeout: defaultReplayTimeout,
	}
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

// scopeRuleInput is the JSON representation of a scope rule for MCP tool input.
type scopeRuleInput struct {
	// Hostname matches the request's hostname (case-insensitive, exact match).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	Hostname string `json:"hostname,omitempty" jsonschema:"hostname pattern (e.g. example.com, *.example.com)"`

	// URLPrefix matches the beginning of the request URL path (case-sensitive).
	URLPrefix string `json:"url_prefix,omitempty" jsonschema:"URL path prefix (e.g. /api/)"`

	// Method matches the HTTP method (case-insensitive, exact match).
	Method string `json:"method,omitempty" jsonschema:"HTTP method (e.g. GET, POST)"`
}

// scopeRuleOutput is the JSON representation of a scope rule in MCP tool output.
type scopeRuleOutput struct {
	Hostname  string `json:"hostname,omitempty"`
	URLPrefix string `json:"url_prefix,omitempty"`
	Method    string `json:"method,omitempty"`
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

// toScopeRules converts MCP input rules to proxy.ScopeRule slice.
func toScopeRules(inputs []scopeRuleInput) []proxy.ScopeRule {
	rules := make([]proxy.ScopeRule, len(inputs))
	for i, in := range inputs {
		rules[i] = proxy.ScopeRule{
			Hostname:  in.Hostname,
			URLPrefix: in.URLPrefix,
			Method:    in.Method,
		}
	}
	return rules
}

// fromScopeRules converts proxy.ScopeRule slice to MCP output rules.
func fromScopeRules(rules []proxy.ScopeRule) []scopeRuleOutput {
	out := make([]scopeRuleOutput, len(rules))
	for i, r := range rules {
		out[i] = scopeRuleOutput{
			Hostname:  r.Hostname,
			URLPrefix: r.URLPrefix,
			Method:    r.Method,
		}
	}
	return out
}

// checkTargetScopeURL checks a URL against the target scope rules.
// Returns nil if the target is allowed or if no rules are configured (open mode).
// Returns a descriptive error if the target is blocked.
func (s *Server) checkTargetScopeURL(u *url.URL) error {
	return checkTargetScopeURLHelper(s.deps.targetScope, u)
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
	return checkTargetScopeAddrHelper(s.deps.targetScope, scheme, addr)
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

// targetScopeCheckRedirect returns a CheckRedirect function that enforces
// both the standard redirect safety checks and target scope rules.
// If ts is nil or has no rules, it falls back to safeCheckRedirect.
func targetScopeCheckRedirect(ts *proxy.TargetScope) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// Apply standard redirect safety checks first.
		if err := safeCheckRedirect(req, via); err != nil {
			return err
		}
		// Apply target scope check on the redirect target.
		if ts != nil && ts.HasRules() {
			allowed, reason := ts.CheckURL(req.URL)
			if !allowed {
				return fmt.Errorf("redirect blocked by target scope: host %q is %s", req.URL.Hostname(), reason)
			}
		}
		return nil
	}
}

// checkSafetyInput validates request data against the safety filter engine.
// Returns nil if no safety engine is configured or if the input passes.
// Returns an MCP error CallToolResult with isError=true if the input is blocked.
func (s *Server) checkSafetyInput(body []byte, rawURL string, headers http.Header) *safety.InputViolation {
	if s.deps.safetyEngine == nil {
		return nil
	}
	return s.deps.safetyEngine.CheckInput(body, rawURL, headers)
}

// safetyViolationError formats a safety filter violation into an MCP error string.
func safetyViolationError(v *safety.InputViolation) string {
	return fmt.Sprintf(
		"SafetyFilter blocked this operation: Destructive payload detected.\n"+
			"Rule: %s\n"+
			"Matched in: %s\n"+
			"Pattern: %s\n\n"+
			"This payload was classified as destructive and cannot be sent. "+
			"If this is intentional, review the safety_filter configuration.",
		v.RuleID, v.Target, v.RuleName,
	)
}
