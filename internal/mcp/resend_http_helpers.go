// Package mcp resend_http_helpers.go holds the building blocks used by
// resend_http.go: input validation, synthetic envelope construction,
// dial-target resolution, scope checking, the resend pipeline factory, the
// upstream DialFunc, the one-shot run loop, and result formatting.
//
// These are split out so resend_http.go reads as a top-level orchestration
// while every step has a single responsibility documented in isolation.
package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	httputilpkg "github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// resendHTTPSupportedProtocols lists the flow.Stream.Protocol values that
// resend_http accepts via flow_id. Non-HTTP protocols are rejected with an
// explicit pointer to the protocol-typed counterpart tool. The set covers
// the HTTP variants plus SOCKS5-prefixed projections.
var resendHTTPSupportedProtocols = map[string]bool{
	"HTTP":          true,
	"HTTPS":         true,
	"HTTP/1.x":      true,
	"HTTP/1.1":      true,
	"HTTP/2":        true,
	"SOCKS5+HTTP":   true,
	"SOCKS5+HTTPS":  true,
	"SOCKS5+HTTP/2": true,
	// envelope.Protocol projection ("http") for streams created on the
	// new Layer stack.
	"http": true,
}

// validateOverrideHost validates that override_host is in host:port format
// with an explicit decimal port.
//
// USK-1085: the port must be decimal, not a service name. net.SplitHostPort
// accepts "169.254.169.254:http", and so does the dial — net.Dial resolves
// the port through net.LookupPort, whose builtin table maps "http" -> 80.
// targetDefaultPort (security_tool.go) does not: it returns 0 for any
// non-digit port, so every `ports`-bearing rule stops matching while the
// socket still lands on 80. That validate/use parsing discrepancy is the
// same silent-non-match shape as the blank scheme, one field over. Mirrors
// validateRawTargetAddr, which enforces the identical rule on the raw
// tools' target_addr.
func validateOverrideHost(host string) error {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("must be host:port format: %w", err)
	}
	if h == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if p == "" {
		return fmt.Errorf("port cannot be empty")
	}
	if !isDecimalPort(p) {
		return fmt.Errorf("port %q must be a decimal number in 1-65535 (a service name resolves at dial time but not in the scope check)", p)
	}
	return nil
}

// validateResendHTTPInput rejects malformed inputs at the schema boundary
// before any expensive lookups (flow store, dial) run. Header CR/LF guards,
// body-encoding parse, body_patch shape, the http/https allowlist on a
// user-supplied scheme, and required-field rules live here.
func validateResendHTTPInput(input *resendHTTPInput) error {
	if input.FollowRedirects != nil && *input.FollowRedirects {
		return errors.New("follow_redirects is not supported by resend_http")
	}
	if err := validateHeaderKVList(input.Headers, "headers"); err != nil {
		return err
	}
	for i, p := range input.BodyPatches {
		if err := validateBodyPatch(p); err != nil {
			return fmt.Errorf("body_patches[%d]: %w", i, err)
		}
	}
	if input.OverrideHost != "" {
		if err := validateOverrideHost(input.OverrideHost); err != nil {
			return fmt.Errorf("invalid override_host %q: %w", input.OverrideHost, err)
		}
	}
	if err := validateResendHTTPScheme(input.Scheme); err != nil {
		return err
	}
	if err := validateResendHTTPVersion(input.HTTPVersion, input.Scheme); err != nil {
		return err
	}
	if input.FlowID == "" {
		return validateResendHTTPFromScratch(input)
	}
	return nil
}

// validateResendHTTPScheme applies the http/https allowlist to a
// user-supplied scheme. An empty value is accepted here — it means "not
// supplied", and validateResendHTTPFromScratch separately requires one on
// the from-scratch path.
//
// USK-1061: the allowlist lives here — not in validateResendHTTPFromScratch
// — because it must cover the flow_id path too, applying the USK-1051
// precedent already in force for resend_grpc (see
// validateResendGRPCStringFields). input.Scheme takes precedence over the
// recovered Flow.URL scheme in buildResendHTTPEnvelopeWithMeta, so on the
// flow_id path an arbitrary value used to reach the canonical *url.URL that
// checkResendHTTPScope matches rules against. `resend_http {flow_id: "f",
// scheme: "gopher", authority: "169.254.169.254:80"}` therefore walked past
// a deny rule of {"hostname": "169.254.169.254", "schemes": ["http"]}: the
// rule's scheme condition did not match "gopher", evaluation fell through
// to the allow check, and with no allow rules configured the metadata
// service was reachable. fuzz_http rebuilds the same canonical URL per
// variant, so an unvalidated value would also make the checked URL and the
// dial disagree.
//
// The recovered-from-flow scheme is deliberately left unchecked: recorded
// wire values must not be sanitized (MITM Principle 1). Unlike gRPC, the
// resolved value never reaches the wire here — internal/layer/http1 emits
// an origin-form request line and never serializes .Scheme — so this guards
// the scope check and the Flow projection, not the bytes.
//
// The comparison is case-insensitive, matching validateResendWSScheme and
// validateResendGRPCStringFields. RFC 3986 §3.1 makes URL schemes
// case-insensitive and nothing downstream disagrees: resolveResendHTTPDial
// uses strings.EqualFold, TargetScope.CheckURL lowercases before matching,
// and matchTargetRule compares `schemes` with containsStringFold. A
// byte-exact check would have turned `resend_http {flow_id, scheme:
// "HTTPS"}` into a NEW rejection on the flow_id path this allowlist newly
// covers — a divergence introduced by the hoist itself, and one that
// `resend_ws {flow_id, scheme: "WSS"}` would not share.
func validateResendHTTPScheme(scheme string) error {
	if s := strings.ToLower(scheme); s != "" && s != "http" && s != "https" {
		return fmt.Errorf("unsupported scheme %q: only http and https are allowed", scheme)
	}
	return nil
}

// validateResendHTTPVersion applies the http_version allowlist (http/1.1,
// h2, h2c — the canonical envelope.HTTPVersion* values minus http/1.0,
// which the synthetic HTTP/1 send path does not emit) and, when the caller
// also supplied a scheme, the scheme compatibility rule. On the flow_id
// path without a scheme the rule is re-checked against the resolved scheme
// by resolveResendHTTPVersion.
func validateResendHTTPVersion(version, scheme string) error {
	if version == "" {
		return nil
	}
	v := strings.ToLower(version)
	switch v {
	case envelope.HTTPVersion11, envelope.HTTPVersionH2, envelope.HTTPVersionH2C:
	default:
		return fmt.Errorf("unsupported http_version %q: must be http/1.1, h2 or h2c", version)
	}
	return checkResendHTTPVersionScheme(v, scheme)
}

// checkResendHTTPVersionScheme rejects the two contradictory combinations:
// h2 is HTTP/2 negotiated through TLS ALPN (RFC 9113 §3.2) and so needs
// https; h2c is HTTP/2 over cleartext with prior knowledge (RFC 9113 §3.3)
// and so needs http. version must already be lowercased; an empty scheme
// means "not known yet" and passes.
func checkResendHTTPVersionScheme(version, scheme string) error {
	s := strings.ToLower(scheme)
	switch {
	case s == "":
		return nil
	case version == envelope.HTTPVersionH2 && s != "https":
		return fmt.Errorf("http_version h2 requires scheme https (got %q); use h2c for cleartext HTTP/2", scheme)
	case version == envelope.HTTPVersionH2C && s != "http":
		return fmt.Errorf("http_version h2c requires scheme http (got %q); use h2 for HTTP/2 over TLS", scheme)
	}
	return nil
}

// resolveResendHTTPVersion decides the wire protocol of a resend (USK-1198):
// an explicit http_version wins (re-checked against the resolved scheme),
// then the recorded flow's version, then http/1.1. A recorded h2 or h2c
// flow is sent over HTTP/2; whether that is h2 (TLS + ALPN) or h2c (prior
// knowledge) follows the resolved scheme, the same value that decides
// whether the dial uses TLS (resolveResendHTTPDial).
func resolveResendHTTPVersion(explicit, recorded, scheme string) (string, error) {
	if explicit != "" {
		v := strings.ToLower(explicit)
		if err := checkResendHTTPVersionScheme(v, scheme); err != nil {
			return "", fmt.Errorf("resend_http: %w", err)
		}
		return v, nil
	}
	switch strings.ToLower(recorded) {
	case envelope.HTTPVersionH2, envelope.HTTPVersionH2C:
		if strings.EqualFold(scheme, "https") {
			return envelope.HTTPVersionH2, nil
		}
		return envelope.HTTPVersionH2C, nil
	}
	return envelope.HTTPVersion11, nil
}

// isResendHTTP2 reports whether a resolved resend version is sent over
// HTTP/2.
func isResendHTTP2(version string) bool {
	return version == envelope.HTTPVersionH2 || version == envelope.HTTPVersionH2C
}

// validateResendHTTPFromScratch checks that all required HTTPMessage fields
// are present when flow_id is omitted (the from-scratch path). The scheme's
// value is allowlist-checked on both paths by validateResendHTTPScheme,
// which runs unconditionally; only its presence is enforced here.
func validateResendHTTPFromScratch(input *resendHTTPInput) error {
	missing := []string{}
	if input.Method == "" {
		missing = append(missing, "method")
	}
	if input.Scheme == "" {
		missing = append(missing, "scheme")
	}
	if input.Authority == "" {
		missing = append(missing, "authority")
	}
	if input.Path == "" {
		missing = append(missing, "path")
	}
	if len(missing) > 0 {
		return fmt.Errorf("flow_id is empty; %s required", strings.Join(missing, ", "))
	}
	return nil
}

// buildResendHTTPEnvelope synthesises the *envelope.Envelope that the resend
// pipeline runs on. When flow_id is set, the original send Flow's
// fields fill any user-omitted slots; the user's overrides win on every
// supplied field. When flow_id is empty, every field comes from the user.
//
// The one slot that is never left empty is the scheme — see
// resendHTTPFallbackScheme for why the scope check cannot be handed a blank.
//
// StreamID is freshly generated so RecordStep creates a new Stream row;
// FlowID is generated by http1.BuildSendEnvelope. The envelope carries no
// Opaque (synthetic-send path inside http1.Channel.Send) and no Raw
// (Layer.Send re-encodes from Message at write time).
func (s *Server) buildResendHTTPEnvelope(ctx context.Context, input *resendHTTPInput) (*envelope.Envelope, error) {
	env, _, err := s.buildResendHTTPEnvelopeWithMeta(ctx, input)
	return env, err
}

// resendHTTPEnvelopeMeta carries auxiliary information produced while
// building the base envelope that the basic builder return value does
// not surface. Today this captures only the synthetic-Host-injection
// flag — fuzz_http needs it to align `headers[N]` position indexes
// against the user-supplied input headers array rather than the
// post-injection envelope wire order (USK-830). UserHeaderCount is the
// length of the pre-injection user/flow header list, i.e. the operator-
// visible upper bound for valid `headers[N]` indexes.
type resendHTTPEnvelopeMeta struct {
	HostInjected    bool
	UserHeaderCount int
}

// buildResendHTTPEnvelopeWithMeta is the metadata-bearing variant of
// buildResendHTTPEnvelope. The two functions share the same core logic;
// callers that need the metadata (fuzz_http) use this one, while resend
// keeps the simpler signature.
func (s *Server) buildResendHTTPEnvelopeWithMeta(ctx context.Context, input *resendHTTPInput) (*envelope.Envelope, resendHTTPEnvelopeMeta, error) {
	path, rawQuery, err := splitResendHTTPPathQuery(input.Path, input.RawQuery)
	if err != nil {
		return nil, resendHTTPEnvelopeMeta{}, err
	}
	f := resendHTTPBaseFields{
		method:    input.Method,
		scheme:    input.Scheme,
		authority: input.Authority,
		path:      path,
		rawQuery:  rawQuery,
	}
	if input.FlowID != "" {
		if err := s.inheritResendHTTPFlow(ctx, input.FlowID, &f); err != nil {
			return nil, resendHTTPEnvelopeMeta{}, err
		}
	}
	method, scheme, authority := f.method, f.scheme, f.authority
	path, rawQuery = f.path, f.rawQuery
	origHeaders, origBody, recordedVersion := f.headers, f.body, f.httpVersion

	httpVersion, err := resolveResendHTTPVersion(input.HTTPVersion, recordedVersion, scheme)
	if err != nil {
		return nil, resendHTTPEnvelopeMeta{}, err
	}

	headers := origHeaders
	if input.Headers != nil {
		headers = headerKVsToKeyValues(input.Headers)
	}
	// preInjectionCount is the operator-visible length of the headers
	// array — what `headers[N]` should resolve against in fuzz positions.
	preInjectionCount := len(headers)
	var injected bool
	if !isResendHTTP2(httpVersion) {
		// HTTP/2 carries the target in :authority (RFC 9113 §8.3.1), which
		// the h2 encoder builds from HTTPMessage.Authority; a synthetic
		// host header there would be a header nobody asked to send.
		headers, injected = ensureResendHTTPHostHeader(headers, authority)
	}

	body, err := resolveResendHTTPBody(input, origBody)
	if err != nil {
		return nil, resendHTTPEnvelopeMeta{}, err
	}

	env := http1.BuildSendEnvelope(method, scheme, authority, path, rawQuery, headers, body)
	// The resolved version is the send plan: the dial and the encoder
	// registry key off it, and RecordStep projects it onto the new Send
	// Flow's http_version (USK-1198 — that used to be "").
	env.Message.(*envelope.HTTPMessage).HTTPVersion = httpVersion
	// BuildSendEnvelope does not set StreamID — RecordStep needs one to
	// open the new Stream row, so generate it here. RFC-001 streams are
	// per-resend (each invocation creates a fresh Stream + Flow pair).
	env.StreamID = uuid.NewString()
	return env, resendHTTPEnvelopeMeta{
		HostInjected:    injected,
		UserHeaderCount: preInjectionCount,
	}, nil
}

// resendHTTPBaseFields are the request fields a resend starts from: the
// caller's values, with the gaps filled from the recorded flow by
// inheritResendHTTPFlow.
type resendHTTPBaseFields struct {
	method, scheme, authority, path, rawQuery string
	headers                                   []envelope.KeyValue
	body                                      []byte
	// httpVersion is the recorded send Flow's http_version ("" when
	// unknown); resolveResendHTTPVersion turns it into the send plan.
	httpVersion string
}

// inheritResendHTTPFlow loads flowID's first send Flow and fills every
// empty field of f from it. The scheme never stays empty — see
// resendHTTPFallbackScheme. Headers, body and the recorded http_version
// are always taken from the flow; the caller decides whether user input
// replaces them.
func (s *Server) inheritResendHTTPFlow(ctx context.Context, flowID string, f *resendHTTPBaseFields) error {
	stream, sendFlow, err := s.loadResendHTTPSendFlow(ctx, flowID)
	if err != nil {
		return err
	}
	if !resendHTTPSupportedProtocols[stream.Protocol] {
		return fmt.Errorf("resend_http: protocol %q not supported by this tool — use resend_ws / resend_grpc / resend_raw for non-HTTP flows", stream.Protocol)
	}
	if f.method == "" {
		f.method = sendFlow.Method
	}
	if sendFlow.URL != nil {
		if f.scheme == "" {
			f.scheme = sendFlow.URL.Scheme
		}
		if f.authority == "" {
			f.authority = sendFlow.URL.Host
		}
		if f.path == "" {
			f.path = envelope.WirePath(sendFlow.URL)
			if f.path == "" {
				f.path = "/"
			}
		}
		if f.rawQuery == "" {
			f.rawQuery = sendFlow.URL.RawQuery
		}
	}
	if f.scheme == "" {
		f.scheme = resendHTTPFallbackScheme(stream)
	}
	f.headers = flowMapToKeyValues(sendFlow.Headers)
	f.body = sendFlow.Body
	f.httpVersion = sendFlow.HTTPVersion
	return nil
}

// resendHTTPFallbackScheme resolves the scheme for a flow_id-based resend
// whose recorded Flow.URL carried none. Never returns "".
//
// USK-1061 (review round 1): resend_http was the one of the five fixed call
// sites whose resolved scheme could still be empty, so the bypass the Issue
// closes stayed reachable through it. A blank is planted by ordinary wire
// traffic, not by a hypothetical: internal/layer/http2's assembler records
// `:scheme` verbatim and flags a missing one only for extended CONNECT
// (RFC 8441 §4), so a normal h2 request that simply omits `:scheme` is
// recorded with Scheme=="" and no anomaly; httpaggregator copies it into
// HTTPMessage.Scheme, RecordStep projects it into Flow.URL, and the SQLite
// round-trip ("//host/path") preserves the blank. Handing that "" to
// checkResendHTTPScope makes every `schemes`-bearing rule stop matching in
// both directions, and drives targetDefaultPort("","") to 0 so
// `ports`-bearing rules degrade with it.
//
// The two sibling tools already default — finalizeResendGRPCAuthorityScheme
// to "https", resolveResendWSAddress to "ws" — and the contract written on
// checkTargetScopeAddr by this PR ("callers must pass the scheme they
// resolved … a plaintext dial passes http") requires it of this caller too.
//
// Resolution order mirrors resend_grpc's USK-920 fallback: prefer the
// recorded Stream's handshake transport, allowlisted to the scope engine's
// {http, https} vocabulary (flow.Stream.Scheme's canonical live values are
// "https" / "http" / "tcp"), then fall back to "http". "http" is the
// conservative default because a schemeless resend dials plaintext —
// resolveResendHTTPDial derives useTLS from this same value — so declaring
// it as plaintext is what makes a plaintext-scoped deny fire.
//
// Flow.URL.Scheme itself is deliberately left untouched (MITM Principle 1):
// the default belongs to the resend *plan*, not to the recorded value.
func resendHTTPFallbackScheme(stream *flow.Stream) string {
	if stream != nil {
		if s := strings.ToLower(stream.Scheme); s == "http" || s == "https" {
			return s
		}
	}
	return "http"
}

// splitResendHTTPPathQuery normalises the user-supplied (path, raw_query)
// pair so a `?` embedded in `path` is auto-routed to `raw_query` instead of
// being percent-encoded to `%3F` at record time (USK-859).
//
// The wire-send path already concatenates `Path + "?" + RawQuery` verbatim
// — so a literal `?` in `Path` did emit correctly on the wire. The
// corruption was downstream: `envelopeToFlow` (`internal/pipeline/record_step.go`)
// projected `{Path, RawQuery}` into a `&url.URL{}` whose `String()` then
// percent-encoded the literal `?` inside `Path` to `%3F`. Since USK-1139 the
// projection stores the wire path verbatim, so an unsplit `?` would instead
// read back as the query delimiter — the split is still required. Splitting at the
// MCP control-plane edge keeps wire-observed raw bytes untouched and only
// fixes the L7 projection (CLAUDE.md MITM Principle 1).
//
// Behaviour:
//   - No `?` in path → returns inputs unchanged (also covers the empty-path
//     case, which the from-scratch validator catches separately).
//   - `?` in path AND raw_query is empty → split on the first literal `?`:
//     prefix becomes the new path, suffix becomes raw_query.
//   - `?` in path AND raw_query is non-empty → return an explicit error.
//     Silently picking a precedence or merging would surprise the operator;
//     the caller should drop one or the other and resubmit. Matches
//     MITM Principle 5 (handle ambiguous input gracefully and explicitly).
//
// Note: split is on the first literal `?` byte only. A literal `%3F` in
// `path` (already percent-encoded) is not a delimiter and is left alone —
// callers that want a verbatim `?` in the path segment can escape it.
func splitResendHTTPPathQuery(path, rawQuery string) (string, string, error) {
	idx := strings.IndexByte(path, '?')
	if idx < 0 {
		return path, rawQuery, nil
	}
	if rawQuery != "" {
		return "", "", fmt.Errorf("resend_http: path contains '?'; pass the query in raw_query or remove raw_query (got path=%q, raw_query=%q)", path, rawQuery)
	}
	return path[:idx], path[idx+1:], nil
}

// loadResendHTTPSendFlow fetches the Stream and its first send Flow for a
// given flow_id. Returns an explicit error when the store is unset or the
// stream has no send-direction flows.
func (s *Server) loadResendHTTPSendFlow(ctx context.Context, flowID string) (*flow.Stream, *flow.Flow, error) {
	if s.flowStore.store == nil {
		return nil, nil, errors.New("resend_http: flow store is not initialized")
	}
	stream, err := s.flowStore.store.GetStream(ctx, flowID)
	if err != nil {
		return nil, nil, fmt.Errorf("resend_http: get stream %s: %w", flowID, err)
	}
	// USK-930: pass explicit semantic so future SSE-over-h1-chunked
	// / WS-over-h2 overlay rows do not bleed into the resend helper's
	// [0]-index assumption (the projection invariant guarantees the
	// canonical HTTP request envelope is the first semantic send Flow).
	flows, err := s.flowStore.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "send", WireLevel: flow.WireLevelSemantic})
	if err != nil {
		return nil, nil, fmt.Errorf("resend_http: get flows %s: %w", flowID, err)
	}
	if len(flows) == 0 {
		return nil, nil, fmt.Errorf("resend_http: stream %s has no send-direction flows", flowID)
	}
	return stream, flows[0], nil
}

// resolveResendHTTPBody decodes the user-supplied body or applies
// body_patches on top of the original Flow.Body, in that priority order.
// body_set distinguishes "omit body — keep original" from "override to empty
// body" so callers can deliberately blank a body without nil/empty
// ambiguity.
func resolveResendHTTPBody(input *resendHTTPInput, original []byte) ([]byte, error) {
	body := original
	if input.Body != "" || input.BodySet {
		decoded, err := decodeBodyEncoded(input.Body, input.BodyEncoding, "body")
		if err != nil {
			return nil, err
		}
		body = decoded
	}
	if len(input.BodyPatches) > 0 {
		patched, err := applyBodyPatches(body, input.BodyPatches)
		if err != nil {
			return nil, fmt.Errorf("body_patches: %w", err)
		}
		body = patched
	}
	return body, nil
}

// ensureResendHTTPHostHeader prepends a Host header derived from the
// authority field when the user-supplied or inherited header list does not
// already carry one (case-insensitive). HTTP/1.1 requires a Host header on
// every request; the synthetic-send wire path will not invent one, so a
// resend whose source flow recorded headers without a captured Host (a
// common shape in MITM Flow.Headers map projection) would otherwise produce
// a 400 from the upstream. Smuggling tests that need a missing or differing
// Host must override the headers list explicitly.
//
// Returns (headers, injected) so callers (notably fuzz_http) can align
// `headers[N]` position indexes against the user-input array — see
// USK-830. injected is true iff a synthetic Host was prepended at index 0.
func ensureResendHTTPHostHeader(headers []envelope.KeyValue, authority string) ([]envelope.KeyValue, bool) {
	if authority == "" {
		return headers, false
	}
	for _, kv := range headers {
		if strings.EqualFold(kv.Name, "Host") {
			return headers, false
		}
	}
	out := make([]envelope.KeyValue, 0, len(headers)+1)
	out = append(out, envelope.KeyValue{Name: "Host", Value: authority})
	out = append(out, headers...)
	return out, true
}

// flowMapToKeyValues projects a flow.Flow.Headers multimap into an ordered
// envelope.KeyValue slice. The flow store is already lossy on inter-name
// order (map iteration is undefined); this helper preserves intra-name
// duplicate order as recorded. Header-list ordered overrides supplied via
// the input schema bypass this lossy projection.
func flowMapToKeyValues(headers map[string][]string) []envelope.KeyValue {
	if len(headers) == 0 {
		return nil
	}
	var out []envelope.KeyValue
	for name, values := range headers {
		for _, v := range values {
			out = append(out, envelope.KeyValue{Name: name, Value: v})
		}
	}
	return out
}

// resolveResendHTTPDial computes the upstream dial target, useTLS flag and
// SNI server name from the synthesised HTTPMessage and the optional
// override_host. override_host wins for the dial target while the request's
// :authority stays untouched (the smuggling / wrong-server-routing pattern).
func resolveResendHTTPDial(msg *envelope.HTTPMessage, overrideHost string) (addr string, useTLS bool, sni string, err error) {
	if msg.Authority == "" {
		return "", false, "", errors.New("resend_http: authority is empty")
	}
	useTLS = strings.EqualFold(msg.Scheme, "https")
	host := msg.Authority
	if h, _, splitErr := net.SplitHostPort(msg.Authority); splitErr == nil {
		host = h
	}
	sni = host
	port := ""
	if _, p, splitErr := net.SplitHostPort(msg.Authority); splitErr == nil {
		port = p
	}
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr = net.JoinHostPort(host, port)

	if overrideHost != "" {
		addr = overrideHost
		if h, _, splitErr := net.SplitHostPort(overrideHost); splitErr == nil {
			sni = h
		}
	}
	return addr, useTLS, sni, nil
}

// checkResendHTTPScope enforces TargetScope rules on both the canonical
// request URL and (when override_host is supplied) the override target. Both
// must pass; an override that bypasses scope is rejected even when the
// canonical authority is in-scope.
//
// Constructs the *url.URL directly from validated HTTPMessage fields rather
// than round-tripping via String → Parse: net/url's String() percent-encodes
// problematic Host bytes (whitespace, NUL, control chars) and the resulting
// "%XX" sequence in the host position is then rejected by Parse, silently
// swallowing the canonical-leg scope check (USK-672 review S-1, CWE-918).
// Falling through to the override leg only is not enough — the canonical
// authority is the path the dial actually takes when override_host is empty.
//
// USK-1061: the override leg is handed the same scheme the canonical leg
// matched on. It previously derived "https" or "" from msg.Scheme, and that
// blank made every `schemes`-bearing rule stop matching on the override leg
// — a deny rule scoped to plaintext no-opped (bypass), and an allow rule
// scoped to plaintext false-blocked. Two legs of one check must not disagree
// on the scheme axis. Lowercasing mirrors TargetScope.CheckURL, which
// lowercases before matching, so targetDefaultPort's inference lands too.
//
// USK-1158: the override leg is also handed the request path, because that
// path is what the HTTP/1 encoder writes as the request target on the
// connection to the override target. Address-only, a path_prefix deny on
// the override target never matched (bypass) and a path_prefix allow on it
// never matched either (false deny). The path is handed in wire form
// (envelope.WirePath, == msg.Path), the same form TargetScope.CheckURL and
// the live HTTPScopeStep match on; canonical.Path is only the lenient
// decoding since USK-1139, and CheckTarget decodes once more itself.
func (s *Server) checkResendHTTPScope(msg *envelope.HTTPMessage, addr, overrideHost string) error {
	canonical := resendHTTPRequestURL(msg)
	if err := s.checkTargetScopeURL(canonical); err != nil {
		return err
	}
	if overrideHost != "" {
		if err := s.checkTargetScopeAddrPath(strings.ToLower(canonical.Scheme), addr, envelope.WirePath(canonical)); err != nil {
			return err
		}
	}
	return nil
}

// resendHTTPRequestURL composes the canonical *url.URL used for scope
// matching and safety filter input. Built directly from validated
// HTTPMessage fields without a String → Parse round-trip; see
// checkResendHTTPScope for the rationale. msg.Path is wire form (USK-1139),
// so the URL is built with envelope.URLFromWirePath and serialized with
// envelope.WireURLString — never url.URL.String(), which re-escapes it.
func resendHTTPRequestURL(msg *envelope.HTTPMessage) *url.URL {
	return envelope.URLFromWirePath(msg.Scheme, msg.Authority, msg.Path, msg.RawQuery)
}

// buildResendHTTPPipeline constructs the resend Pipeline:
//
//	PluginStepPost → RecordStep
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass). HostScope and Safety are handled at the handler level
// before the envelope reaches the pipeline; constructing them here would
// require engine wiring that the production data path does not yet plumb
// (those checks would no-op against the still-legacy production pipeline
// state). The wire encoder for HTTP is registered on a shared
// WireEncoderRegistry so PluginStepPost MessageOnly mutations regenerate
// env.Raw consistently with what RecordStep records as the modified
// variant's bytes. The encoder follows the resend's wire protocol
// (resendHTTPEncoderRegistry).
func (s *Server) buildResendHTTPPipeline(httpVersion string) *pipeline.Pipeline {
	encoders := resendHTTPEncoderRegistry(httpVersion)

	steps := []pipeline.Step{
		// USK-818: BudgetStep at position #1 so resend dispatches are
		// counted toward and gated by the same MaxTotalRequests /
		// MaxDuration policy as the live data path. Drop short-circuits
		// the rest of the pipeline; the inline drop recorder in
		// runResendHTTP writes a state="error" + blocked_by="budget"
		// audit Stream.
		pipeline.NewBudgetStep(s.misc.budgetManager),
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(
			s.flowStore.store,
			slog.Default(),
			pipeline.WithWireEncoderRegistry(encoders),
			// USK-785: stamp resend-originated streams so the query tool
			// (USK-786) can filter them from live capture views.
			pipeline.WithOrigin(flow.OriginResend),
		),
	}
	return pipeline.New(steps...)
}

// resendHTTPEncoderRegistry returns the WireEncoderRegistry shared by
// PluginStepPost and RecordStep for one resend / fuzz run: HTTP/1 framing
// for an http/1.1 send, HPACK-encoded HTTP/2 frames for h2 / h2c — the same
// per-route choice proxybuild makes for the live path
// (defaultHTTP1WireEncoderRegistry / defaultHTTP2WireEncoderRegistry).
func resendHTTPEncoderRegistry(httpVersion string) *pipeline.WireEncoderRegistry {
	encoders := pipeline.NewWireEncoderRegistry()
	if isResendHTTP2(httpVersion) {
		encoders.Register(envelope.ProtocolHTTP, httpaggregator.EncodeWireBytes)
	} else {
		encoders.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)
	}
	return encoders
}

// pluginEngineForResend returns the pluginv2.Engine to feed PluginStepPost.
// nil is acceptable — PluginStepPost no-ops when the engine is unset, which
// matches the test fixture (no plugins loaded → no hooks fire) and
// production until pluginv2 is wired into the live data path.
func pluginEngineForResend(s *Server) *pluginv2.Engine {
	if s.pluginEngine == nil {
		return nil
	}
	return s.pluginEngine.pluginv2
}

// resendHTTPDialConfig is everything buildResendHTTPDialFunc needs to open
// the upstream connection for one resend (or one fuzz variant).
//
// httpVersion is the resolved send plan (resolveResendHTTPVersion):
// http/1.1, h2 or h2c. h2Fingerprint is the server's TLS fingerprint
// profile, which also shapes the HTTP/2 SETTINGS / pseudo-header order the
// way the live upstream path does (USK-1007).
type resendHTTPDialConfig struct {
	transport     httputilpkg.TLSTransport
	addr          string
	useTLS        bool
	sni           string
	httpVersion   string
	h2Fingerprint string
}

// buildResendHTTPDialFunc returns a session.DialFunc that dials cfg.addr,
// optionally upgrades to TLS via the configured TLSTransport, then wraps the
// connection in the Layer matching cfg.httpVersion in client role. The
// returned Channel feeds the Job: Channel.Send writes the request,
// Channel.Next reads the response. Every call opens a fresh connection —
// no pooling — so upstream proxy rotation keeps working per variant.
//
// useTLS is decided by the caller from msg.Scheme + override_host. SNI is
// the override host when provided so that wrong-server routing produces a
// matching ClientHello.
//
// HTTP/1.1: the TLSTransport is cloned with NextProtos=["http/1.1"] before
// use. The post-handshake conn is wrapped in an http1 Layer, so a server
// that negotiated h2 over the default ALPN (StandardTransport offers
// ["h2","http/1.1"], uTLS Chrome offers the same as part of the browser
// fingerprint) would silently break the receive side. Pinning to http/1.1
// keeps the rest of the fingerprint (cipher suites, extensions order) intact
// while guaranteeing the negotiated wire matches the Layer we drive
// (USK-717); anything but "http/1.1" or no ALPN at all is refused.
//
// HTTP/2 (USK-1198): see dialResendHTTP2.
func buildResendHTTPDialFunc(cfg resendHTTPDialConfig) session.DialFunc {
	return func(ctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		// MaybeDialViaUpstreamProxy consults ctx for a per-flow upstream
		// proxy override (ContextWithUpstreamProxyOverride) — used by the
		// fuzz / resend per-iteration rotation path. When ctx carries no
		// override, this falls through to a plain net.Dialer dial,
		// preserving the historical direct-dial behaviour.
		conn, err := connector.MaybeDialViaUpstreamProxy(ctx, cfg.addr, defaultReplayTimeout)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", cfg.addr, err)
		}
		if isResendHTTP2(cfg.httpVersion) {
			return dialResendHTTP2(ctx, cfg, conn)
		}
		if cfg.useTLS {
			http1Transport := httputilpkg.WithNextProtos(cfg.transport, []string{"http/1.1"})
			tlsConn, alpn, tlsErr := upgradeResendTLS(ctx, http1Transport, conn, cfg.sni)
			if tlsErr != nil {
				_ = conn.Close()
				return nil, tlsErr
			}
			if alpn != "" && alpn != "http/1.1" {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("upstream negotiated ALPN %q for an http/1.1 send", alpn)
			}
			conn = tlsConn
		}
		l := http1.New(conn, "", envelope.Receive)
		ch := <-l.Channels()
		return ch, nil
	}
}

// dialResendHTTP2 runs the HTTP/2 leg of buildResendHTTPDialFunc on an
// already-dialled conn, which it owns from here on.
//
// h2 (TLS): the configured TLSTransport is used as-is — its ALPN offer is
// the browser profile's own list (uTLS) or ["h2","http/1.1"] (standard), so
// the ClientHello stays identical to the live path's. The negotiated value
// is then required to be exactly "h2": checking the value rather than the
// error matters because crypto/tls can complete a handshake with no
// protocol selected. Anything else is a hard error naming the negotiated
// ALPN — no silent fallback to HTTP/1.1, which is what this Issue fixed.
//
// h2c (cleartext): HTTP/2 with prior knowledge (RFC 9113 §3.3) — the
// client preface goes straight onto the TCP connection.
//
// The connection-level http2 Layer is built like the live upstream one
// (internal/connector/stack_builder.go) and the single request stream is
// wrapped in an httpaggregator so Send / Next speak HTTPMessage envelopes,
// exactly like the HTTP/1 path.
func dialResendHTTP2(ctx context.Context, cfg resendHTTPDialConfig, conn net.Conn) (layer.Channel, error) {
	scheme := "http"
	if cfg.useTLS {
		scheme = "https"
		tlsConn, alpn, err := upgradeResendTLS(ctx, cfg.transport, conn, cfg.sni)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if alpn != "h2" {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("upstream negotiated ALPN %q, but the request is sent over HTTP/2 (h2); pass http_version \"http/1.1\" to send it over HTTP/1.1 explicitly", alpn)
		}
		conn = tlsConn
	}
	l, err := http2.New(conn, "", http2.ClientRole,
		http2.WithScheme(scheme),
		http2.WithH2Fingerprint(cfg.h2Fingerprint),
	)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http2 layer: %w", err)
	}
	stream, err := l.OpenStream(ctx)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("http2 open stream: %w", err)
	}
	agg := httpaggregator.Wrap(stream, httpaggregator.RoleClient, nil, httpaggregator.OptionsFromLayer(l))
	return &resendH2Channel{Channel: agg, h2Layer: l, httpVersion: cfg.httpVersion}, nil
}

// resendH2Channel is the Channel a resend drives over HTTP/2: the
// aggregated request stream plus the connection-level Layer it rides on,
// so that the caller's single `defer ch.Close()` tears both down.
//
// Close runs once: the aggregator first (cascading to the stream, which
// resets it if the exchange did not complete), then the Layer (GOAWAY,
// then the connection is closed and the Layer's reader/writer goroutines
// are waited for).
type resendH2Channel struct {
	layer.Channel
	h2Layer     *http2.Layer
	httpVersion string
	closeOnce   sync.Once
}

// Next returns the next aggregated response, labelled with the protocol
// this channel actually spoke. The aggregator labels every Receive
// envelope "h2" (it derives the label from :scheme, which responses do not
// carry), so the h2c leg would otherwise record its responses as h2.
func (c *resendH2Channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	env, err := c.Channel.Next(ctx)
	if err != nil {
		return nil, err
	}
	if msg, ok := env.Message.(*envelope.HTTPMessage); ok {
		msg.HTTPVersion = c.httpVersion
	}
	return env, nil
}

// Close tears down the stream and the connection exactly once.
func (c *resendH2Channel) Close() error {
	c.closeOnce.Do(func() {
		_ = c.Channel.Close()
		_ = c.h2Layer.Close()
	})
	return nil
}

// upgradeResendTLS performs the TLS handshake using the configured
// TLSTransport. A nil transport is rejected — the production wiring always
// supplies one (StandardTransport or UTLSTransport) and silently falling
// back to InsecureSkipVerify=true would defeat MITM diagnostics on the
// resend leg (review-gate S-2). Tests that exercise resend over plain HTTP
// take the useTLS=false path and never reach this function.
func upgradeResendTLS(ctx context.Context, transport httputilpkg.TLSTransport, conn net.Conn, sni string) (net.Conn, string, error) {
	if transport == nil {
		return nil, "", errors.New("resend_http: TLS upstream requires a configured TLSTransport")
	}
	out, alpn, err := transport.TLSConnect(ctx, conn, sni)
	if err != nil {
		return nil, "", fmt.Errorf("tls handshake %s: %w", sni, err)
	}
	return out, alpn, nil
}

// runResendHTTP runs the one-shot send/receive cycle. It dials, runs the
// send envelope through the resend pipeline, writes the request, reads the
// response, ties the response envelope to the same StreamID + Sequence=1,
// runs it through the same pipeline, and returns the response envelope.
//
// If the pipeline drops or responds short-circuits the send, runResendHTTP
// returns the produced response envelope (or nil for Drop) without
// performing the network round-trip.
//
// USK-818: send-direction Drops with BlockedBy="budget" trigger a
// minimal state="error" + blocked_by="budget" audit Stream via the
// supplied store. Other Drop attributions (or Drop with empty BlockedBy)
// fall through to the legacy "dropped by pipeline" error without
// recording an audit row — matches the live data path's selective
// recording policy.
func (s *Server) runResendHTTP(ctx context.Context, env *envelope.Envelope, dial session.DialFunc, p *pipeline.Pipeline) (*envelope.Envelope, error) {
	if p == nil {
		return nil, errors.New("resend pipeline is nil")
	}

	sendEnv, action, custom, blockedBy := p.RunWithBlockedBy(ctx, env)
	switch action {
	case pipeline.Drop:
		if blockedBy == pipeline.BlockedByBudget {
			recordBudgetBlockedStream(ctx, s.flowStore.store, sendEnv, sendEnv.StreamID, flow.OriginResend)
			return nil, errBudgetExhausted
		}
		return nil, errors.New("send envelope dropped by pipeline")
	case pipeline.Respond:
		// Custom response short-circuit. Tie the response to the send's
		// StreamID and record it so analysts see the synthetic reply
		// alongside the request.
		if custom == nil {
			return nil, errors.New("pipeline returned Respond with nil response envelope")
		}
		custom.StreamID = sendEnv.StreamID
		custom.Sequence = 1
		_, _, _ = p.Run(ctx, custom)
		return custom, nil
	}

	ch, err := dial(ctx, sendEnv)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer ch.Close()

	if err := ch.Send(ctx, sendEnv); err != nil {
		return nil, fmt.Errorf("upstream send: %w", err)
	}
	return receiveResendHTTPResponse(ctx, ch, p, sendEnv.StreamID)
}

// maxResendHTTPInterimResponses bounds how many 1xx interim responses
// receiveResendHTTPResponse records before giving up on a final one, so an
// upstream streaming 1xx forever cannot pin the call until its timeout.
const maxResendHTTPInterimResponses = 32

// receiveResendHTTPResponse reads the upstream's response(s) for one
// resend exchange and returns the final one. Each 1xx interim response
// (100 Continue, 103 Early Hints, ...) is recorded as its own receive Flow
// ahead of the final response, in wire order (Sequence 1, 2, ...); 101 is
// final — it ends the HTTP exchange. Shared by resend_http and fuzz_http.
//
// The upstream Channel was created with an empty connID, so the response
// envelopes carry no StreamID. Each is pinned to the send envelope's
// StreamID so RecordStep records it under the same Stream row.
//
// Pipeline.Run on a response envelope is purely for RecordStep + any
// post_pipeline plugin that wants to observe it. Drop / Respond on the
// receive side has no meaningful semantics here (the response is already
// on the wire to us); discarding the action keeps the tools' contract
// simple — the caller always sees the upstream reply, masking applied when
// the result is formatted.
func receiveResendHTTPResponse(ctx context.Context, ch layer.Channel, p *pipeline.Pipeline, streamID string) (*envelope.Envelope, error) {
	for seq := 1; ; seq++ {
		respEnv, err := ch.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("upstream receive: %w", err)
		}
		respEnv.StreamID = streamID
		respEnv.Sequence = seq
		msg, _ := respEnv.Message.(*envelope.HTTPMessage)
		interim := msg != nil && msg.Status >= 100 && msg.Status < 200 && msg.Status != 101
		respEnv, _, _ = p.Run(ctx, respEnv)
		if !interim {
			return respEnv, nil
		}
		if seq > maxResendHTTPInterimResponses {
			return nil, fmt.Errorf("upstream receive: more than %d interim (1xx) responses without a final response", maxResendHTTPInterimResponses)
		}
	}
}

// applyResendHTTPTag persists the user-supplied tag on the new Stream row
// after the pipeline-driven RecordStep has created it. RecordStep does not
// observe the tag (resend is the only path that surfaces it today), so this
// post-pipeline UpdateStream is the cleanest place to set it.
func (s *Server) applyResendHTTPTag(ctx context.Context, streamID, tag string) {
	update := flow.StreamUpdate{Tags: map[string]string{"tag": tag}}
	if err := s.flowStore.store.UpdateStream(ctx, streamID, update); err != nil {
		slog.WarnContext(ctx, "resend_http: tag update failed",
			"stream_id", streamID,
			"tag", tag,
			"error", err,
		)
	}
}

// formatResendHTTPResult turns the response envelope into the wire-shape MCP
// result. SafetyFilter output masking is applied to body and headers before
// they leave the proxy boundary; the unmasked variant is already on disk via
// RecordStep so analysts retain the raw evidence.
func (s *Server) formatResendHTTPResult(streamID string, respEnv *envelope.Envelope, tag string, duration time.Duration) *resendHTTPResult {
	result := &resendHTTPResult{
		StreamID:   streamID,
		DurationMs: duration.Milliseconds(),
		Tag:        tag,
	}
	if respEnv == nil {
		return result
	}
	msg, ok := respEnv.Message.(*envelope.HTTPMessage)
	if !ok {
		return result
	}
	result.StatusCode = msg.Status
	maskedBody := s.filterOutputBody(msg.Body)
	result.Body, result.BodyEncoding = encodeResendHTTPBody(maskedBody)
	result.Headers = filterResendHTTPHeaders(s, msg.Headers)
	return result
}

// encodeResendHTTPBody returns the body string and its declared encoding.
// Empty bodies report encoding "text" so result schemas stay consistent.
func encodeResendHTTPBody(body []byte) (string, string) {
	if len(body) == 0 {
		return "", "text"
	}
	if utf8.Valid(body) {
		return string(body), "text"
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

// filterResendHTTPHeaders applies SafetyFilter output masking to headers
// while preserving order, casing, and duplicates. Uses the raw-headers code
// path so the canonicalisation done by net/http.Header.Add never touches
// our wire-fidelity output. The filter is order-preserving on the parser
// RawHeaders type, so a positional copy back to envelope.KeyValue is exact.
func filterResendHTTPHeaders(s *Server, kvs []envelope.KeyValue) []headerKV {
	if len(kvs) == 0 {
		return nil
	}
	rh := keyValuesToRawHeaders(kvs)
	masked := s.filterOutputRawHeaders(rh)
	out := make([]headerKV, len(masked))
	for i, h := range masked {
		out[i] = headerKV{Name: h.Name, Value: h.Value}
	}
	return out
}
