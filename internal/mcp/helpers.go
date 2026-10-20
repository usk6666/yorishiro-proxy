package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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
	// ServerAddr is the wire-observed peer of the upstream socket — the
	// upstream proxy when UpstreamProxy is set.
	ServerAddr string `json:"server_addr,omitempty"`
	// UpstreamProxy is the upstream proxy the upstream socket was dialed
	// through ("scheme://host:port", credentials stripped); empty for a
	// direct dial.
	UpstreamProxy string `json:"upstream_proxy,omitempty"`
	// TLSVersion is the negotiated TLS version (e.g., "TLS 1.3").
	TLSVersion string `json:"tls_version,omitempty"`
	// TLSCipher is the negotiated TLS cipher suite name.
	TLSCipher string `json:"tls_cipher,omitempty"`
	// TLSALPN is the negotiated ALPN protocol.
	TLSALPN string `json:"tls_alpn,omitempty"`
	// TLSServerCertSubject is the subject DN of the upstream server certificate.
	TLSServerCertSubject string `json:"tls_server_cert_subject,omitempty"`
	// TLSClientJA3 is the JA3 fingerprint of the client's TLS ClientHello.
	TLSClientJA3 string `json:"tls_client_ja3,omitempty"`
	// TLSClientJA4 is the JA4 fingerprint of the client's TLS ClientHello.
	TLSClientJA4 string `json:"tls_client_ja4,omitempty"`
}

// checkTargetScopeURL checks a URL against the target scope rules.
// Returns nil if the target is allowed or if no rules are configured (open mode).
// Returns a descriptive error if the target is blocked.
func (s *Server) checkTargetScopeURL(u *url.URL) error {
	return checkTargetScopeURLHelper(s.connector.targetScope, u)
}

// checkTargetScopeURLHelper checks a URL against the given target scope rules.
// This is a standalone version of Server.checkTargetScopeURL for use by handler structs.
func checkTargetScopeURLHelper(ts *connector.TargetScope, u *url.URL) error {
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
// Returns nil if the target is allowed or if no rules are configured (open mode).
// Returns a descriptive error if the target is blocked.
//
// # The scheme argument has two effects, not one (USK-1061)
//
// It is easy to read this parameter as a port-inference hint only — it does
// feed targetDefaultPort (e.g. "https" -> 443 when the address carries no
// port) — but it is also matched against every rule's `schemes` condition by
// connector.matchTargetRule. Passing a scheme the caller has not actually
// resolved therefore silently changes the verdict in BOTH directions:
//
//   - a blank scheme makes every `schemes`-bearing DENY rule stop matching,
//     so evaluation falls through to the allow check and an
//     otherwise-blocked target is ALLOWED;
//   - a blank scheme makes every `schemes`-bearing ALLOW rule stop matching,
//     so a legitimate target is rejected with "not in ... allow list".
//
// There is no fail-safe blank value: deny wants "unknown matches
// everything" and allow wants "unknown matches nothing", so any single
// semantic is fail-open in exactly one direction. Callers must pass the
// scheme they resolved. `schemes` is spelled in the `http` / `https`
// vocabulary and means transport confidentiality (plaintext vs TLS), not
// the L7 application protocol — see RFC-001 §3.8. A caller that terminates
// TLS passes "https"; a plaintext dial passes "http"; a WebSocket caller
// maps ws -> http and wss -> https (no rule on either layer can contain
// "ws"/"wss": config.ValidateTargetRule rejects them for Agent-layer rules
// and, since USK-1084, for Policy-layer rules at startup).
//
// Blank is deliberately NOT defaulted to "http" here: connector.socks5.go
// passes "" because at handshake time it genuinely does not know the
// tunneled transport, and silently scoping that as plaintext would be a
// different wrong answer. The blank-scheme trade-off is pinned by
// TestCheckTarget_BlankScheme_DoesNotMatchSchemeRule.
func (s *Server) checkTargetScopeAddr(scheme, addr string) error {
	return checkTargetScopeAddrHelper(s.connector.targetScope, scheme, addr)
}

// checkTargetScopeAddrPath is checkTargetScopeAddr plus the request path
// that is sent over the connection to addr. Use it when the caller knows
// the path that reaches addr (an HTTP request target), so `path_prefix`
// rules apply to that leg: an address-only check can never match a
// path_prefix allow (false deny) nor a path_prefix deny (bypass).
func (s *Server) checkTargetScopeAddrPath(scheme, addr, path string) error {
	return checkTargetScopeAddrPathHelper(s.connector.targetScope, scheme, addr, path)
}

// checkTargetScopeAddrHelper checks a host:port address against the given target scope rules.
// This is a standalone version of Server.checkTargetScopeAddr for use by handler structs.
// See Server.checkTargetScopeAddr for the scheme argument's contract.
func checkTargetScopeAddrHelper(ts *connector.TargetScope, scheme, addr string) error {
	return checkTargetScopeAddrPathHelper(ts, scheme, addr, "")
}

// checkTargetScopeAddrPathHelper is the shared body of the address checks;
// path "" is the address-only form. See Server.checkTargetScopeAddrPath.
func checkTargetScopeAddrPathHelper(ts *connector.TargetScope, scheme, addr, path string) error {
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
	allowed, reason := ts.CheckTarget(scheme, host, port, path)
	if !allowed {
		return fmt.Errorf("request blocked by target scope: host %q is %s", host, reason)
	}
	return nil
}

// checkHostHeaderLegs checks every Host header value in headers
// (envelope.HostHeaderValues: every casing, wire order, OWS trimmed, no
// dedup) as a TargetScope name leg against the dial address dialAddr
// (connector.TargetScope.CheckHostHeader, USK-1167). Deny rules always
// apply; an allow layer that admitted dialAddr through an IP-literal rule
// does not require the Host value to be allow-listed, so a Host naming a
// different (non-denied) vhost on an allowed address can still be sent.
// headers is only read. Returns nil in open mode.
func checkHostHeaderLegs(ts *connector.TargetScope, scheme string, headers []envelope.KeyValue, path, dialAddr string) error {
	if ts == nil || !ts.HasRules() {
		return nil
	}
	for _, v := range envelope.HostHeaderValues(headers) {
		if allowed, reason := ts.CheckHostHeader(scheme, v, path, dialAddr); !allowed {
			return fmt.Errorf("request blocked by target scope: Host header %q is %s", v, reason)
		}
	}
	return nil
}

// isDecimalPort reports whether a port string taken from net.SplitHostPort is
// a decimal TCP port number the scope engine can resolve.
//
// USK-1085: net.SplitHostPort leaves whatever followed the colon in the port
// position, including a service name — "169.254.169.254:http" splits cleanly.
// The dial then resolves that name through net.LookupPort ("http" -> 80,
// "https" -> 443), but targetDefaultPort returns 0 for any non-digit port, so
// every `ports`-bearing rule stops matching while the socket still lands on
// the real port. This predicate is the shared gate that keeps the two parsers
// from disagreeing; callers reject up front rather than letting the scope
// check see a port it cannot resolve. Port 0 is rejected too: it is not a
// dialable destination and targetDefaultPort cannot distinguish it from its
// own "unparseable" return value.
//
// The digit loop mirrors targetDefaultPort's rather than delegating the whole
// job to strconv.Atoi: Atoi accepts a leading sign, so "+80" would pass here
// and still make targetDefaultPort return 0 — re-opening the very
// discrepancy this predicate exists to close.
func isDecimalPort(port string) bool {
	if port == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return n >= 1 && n <= 65535
}

// checkSafetyInput validates request data against the safety filter engine.
// Returns nil if no safety engine is configured or if the input passes.
// Returns an InputViolation if the input is blocked. u is the request URL
// (nil for protocols without one, e.g. raw TCP).
//
// USK-1139 either-form matching: u's path is wire form, so the url / query
// targets are checked against both envelope.WireURLString(u) and
// envelope.DecodedPathURLString(u). Input Safety is deny-only, so a match
// on either form blocks (fail closed). The decoded form is a matching aid
// only; what is sent stays the wire path.
func (s *Server) checkSafetyInput(body []byte, u *url.URL, headers []envelope.KeyValue) *safety.InputViolation {
	if s.pipeline.safetyEngine == nil {
		return nil
	}
	wire := envelope.WireURLString(u)
	if v := s.pipeline.safetyEngine.CheckInput(body, wire, headers); v != nil {
		return v
	}
	if decoded := envelope.DecodedPathURLString(u); decoded != wire {
		// body / headers were already checked above; only the URL differs.
		return s.pipeline.safetyEngine.CheckInput(nil, decoded, nil)
	}
	return nil
}

// safetyViolationError returns a generic error message for MCP clients when a safety
// filter violation occurs. Details (rule ID, target, matched-fragment digest) are logged
// server-side to prevent leaking filter internals to the AI agent, which could enable
// bypass attempts.
func safetyViolationError(v *safety.InputViolation) string {
	slog.Warn("SafetyFilter violation",
		"rule_id", v.RuleID,
		"rule_name", v.RuleName,
		"target", v.Target,
		"matched_on", redactMatchedFragment(v.MatchedOn),
	)
	return "SafetyFilter blocked this operation: request blocked by safety policy. " +
		"This payload was classified as destructive and cannot be sent."
}

// redactMatchedFragment obfuscates a safety-filter matched fragment for
// logging (CWE-312). It delegates to safety.RedactFragment so the MCP plane
// and the live-wire SafetyStep produce the same digest for the same bytes.
func redactMatchedFragment(fragment string) string {
	return safety.RedactFragment(fragment)
}
