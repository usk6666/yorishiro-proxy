package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// defaultListLimit is the default number of sessions returned when limit is not specified.
const defaultListLimit = 50

// maxListLimit is the maximum allowed value for limit to prevent OOM from unbounded queries.
const maxListLimit = 1000

// defaultReplayTimeout is the default timeout for replay HTTP requests.
const defaultReplayTimeout = 30 * time.Second

// maxReplayResponseSize is the maximum response body size (1 MB) to prevent OOM.
const maxReplayResponseSize = 1 << 20

// allowedSchemes are the URL schemes permitted for replay requests.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
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

// denyPrivateNetwork returns an error if the resolved IP is a private, loopback,
// link-local, or otherwise internal address. This prevents SSRF attacks.
func denyPrivateNetwork(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("connections to private/internal networks are not allowed: %s", ip)
	}
	return nil
}

// httpClient returns the HTTP client to use for replay requests.
// If a custom doer is set (for testing), it wraps it; otherwise,
// it returns a client with the default replay timeout and SSRF protection.
func (s *Server) httpClient() httpDoer {
	if s.replayDoer != nil {
		return s.replayDoer
	}
	// S-2: Use a custom Dialer with a Control function to block connections
	// to private/internal networks, preventing SSRF and DNS rebinding attacks.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: defaultReplayTimeout,
			Control: denyPrivateNetwork,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   defaultReplayTimeout,
		Transport: transport,
		// Do not follow redirects automatically; record the raw redirect response.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// rawDialerFunc returns the raw dialer to use for replay_raw connections.
// If a custom dialer is set (for testing), it is returned; otherwise,
// a dialer with SSRF protection is returned.
func (s *Server) rawDialerFunc() rawDialer {
	if s.rawReplayDialer != nil {
		return s.rawReplayDialer
	}
	return &net.Dialer{
		Timeout: defaultReplayTimeout,
		Control: denyPrivateNetwork,
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
