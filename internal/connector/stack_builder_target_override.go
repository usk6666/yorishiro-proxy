package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
)

// ForwardProtocol selects the L7 wire shape a caller of
// BuildConnectionStackWithTarget expects to flow through the assembled stack.
// It mirrors the ForwardConfig.Protocol semantic from internal/config so the
// MCP-facing forward selector and the connector-side stack builder share one
// vocabulary.
//
// Only ForwardProtocolRaw is wired in USK-912; the other variants are
// reserved for the L7 dispatch / TLS-terminate / upstream-TLS dial Issues
// (USK-913/914/915/916). Passing a reserved variant to
// BuildConnectionStackWithTarget returns a "not yet wired" error so the
// API surface for downstream Issues is locked in but the implementation
// can land incrementally.
type ForwardProtocol string

const (
	// ForwardProtocolAuto requests peek-based inner-protocol detection on
	// the accepted connection. The auto-detection wire-up is owned by
	// USK-913 and is NOT implemented by USK-912; passing this value
	// currently returns a "not yet wired" error.
	ForwardProtocolAuto ForwardProtocol = "auto"

	// ForwardProtocolRaw builds a [bytechunk → bytechunk] stack — the
	// only protocol fully wired in USK-912. Equivalent to the bytechunk
	// case of buildStackFromRoute but with the target supplied verbatim
	// by the caller (no CONNECT/SNI derivation).
	ForwardProtocolRaw ForwardProtocol = "raw"

	// ForwardProtocolHTTP requests a plain HTTP/1.x stack. Reserved for
	// USK-913 (L7 dispatch); currently returns a "not yet wired" error.
	ForwardProtocolHTTP ForwardProtocol = "http"

	// ForwardProtocolHTTP2 requests an h2c stack. Reserved for USK-913;
	// currently returns a "not yet wired" error.
	ForwardProtocolHTTP2 ForwardProtocol = "http2"

	// ForwardProtocolGRPC requests an h2c + gRPC stack. Reserved for
	// USK-914; currently returns a "not yet wired" error.
	ForwardProtocolGRPC ForwardProtocol = "grpc"

	// ForwardProtocolWebSocket requests an HTTP/1.x stack that may
	// Upgrade to WebSocket. Reserved for USK-914; currently returns a
	// "not yet wired" error.
	ForwardProtocolWebSocket ForwardProtocol = "websocket"

	// ForwardProtocolSSE requests an HTTP/1.x stack that may switch to
	// SSE on response. Reserved for USK-914; currently returns a "not
	// yet wired" error.
	ForwardProtocolSSE ForwardProtocol = "sse"
)

// validForwardProtocols enumerates the protocol selectors
// BuildConnectionStackWithTarget will accept (without erroring on the
// validation step). The set mirrors the config.validForwardProtocols set
// plus "sse" to anticipate USK-915's split. Unknown values are rejected
// at validation time with a clear error.
var validForwardProtocols = map[ForwardProtocol]bool{
	ForwardProtocolAuto:      true,
	ForwardProtocolRaw:       true,
	ForwardProtocolHTTP:      true,
	ForwardProtocolHTTP2:     true,
	ForwardProtocolGRPC:      true,
	ForwardProtocolWebSocket: true,
	ForwardProtocolSSE:       true,
}

// TargetOverrideParams bundles the inputs to BuildConnectionStackWithTarget.
// It is a struct rather than a positional argument list because the parameter
// set is expected to grow (TLS SNI, cert.Issuer, plugin engine, etc.) when
// USK-913/914/915/916 wire in the deferred branches; new fields are then
// additive and do not force a callsite churn pass on USK-912's diff.
//
// The "Target" is operator-declared: the L7 TCP forward listener is told by
// config (or by an MCP tool) what host:port to send the accepted connection
// to. This differs from BuildConnectionStack, which derives Target from
// CONNECT (the client picked the target) or SOCKS5. Both shapes have
// legitimate use cases — see RFC-001 §3.3 and CLAUDE.md MITM Principle 2
// (do not unify protocols / call paths into one shared representation).
type TargetOverrideParams struct {
	// Target is the upstream "host:port" the assembled stack will be
	// connected to. Required and non-empty. Caller supplies this verbatim
	// from operator config; no CONNECT-host or SNI derivation happens
	// here.
	Target string

	// Protocol selects the L7 wire shape. See ForwardProtocol* constants.
	// An empty string is treated as ForwardProtocolAuto. Unknown values
	// are rejected with an error.
	Protocol ForwardProtocol

	// ALPNOffers is the verbatim ALPN advertisement list the caller wants
	// to send on the upstream TLS handshake (when UpstreamTLS=true) or
	// on the client-facing MITM handshake (when TLSTerminate=true). An
	// empty / nil slice means "no ALPN extension on the wire", matching
	// the dialUpstreamWithALPN / performClientMITM existing semantic.
	//
	// Caller-supplied because forward callers have an explicit policy
	// (operator declared which protocol to advertise) rather than the
	// MITM-side "advertise the upstream-negotiated list to the client"
	// heuristic owned by stack_builder.go.
	ALPNOffers []string

	// TLSTerminate, when true, indicates the caller wants the accepted
	// client connection's TLS handshake to be terminated by this builder
	// (with a MITM cert issued via cfg.Issuer). The TLS terminate wire-up
	// is owned by USK-915 and is NOT implemented by USK-912; setting
	// TLSTerminate=true currently returns a "not yet wired" error.
	TLSTerminate bool

	// UpstreamTLS, when true, indicates the caller wants the upstream
	// dial to perform a TLS handshake. The upstream-TLS dial wire-up is
	// owned by USK-916 and is NOT implemented by USK-912; setting
	// UpstreamTLS=true currently returns a "not yet wired" error.
	UpstreamTLS bool
}

// validate sanity-checks the params before any I/O. Returns a wrapped error
// on failure so callsites can compare via errors.Is once specific sentinel
// values are introduced by USK-913+.
func (p *TargetOverrideParams) validate() error {
	if p == nil {
		return fmt.Errorf("connector: BuildConnectionStackWithTarget: nil params")
	}
	if p.Target == "" {
		return fmt.Errorf("connector: BuildConnectionStackWithTarget: empty Target")
	}
	if _, _, err := net.SplitHostPort(p.Target); err != nil {
		return fmt.Errorf("connector: BuildConnectionStackWithTarget: invalid Target %q: %w", p.Target, err)
	}
	protocol := p.Protocol
	if protocol == "" {
		protocol = ForwardProtocolAuto
	}
	if !validForwardProtocols[protocol] {
		return fmt.Errorf("connector: BuildConnectionStackWithTarget: invalid protocol %q (valid: auto, raw, http, http2, grpc, websocket, sse)", p.Protocol)
	}
	return nil
}

// BuildConnectionStackWithTarget assembles a per-connection ConnectionStack
// for an operator-declared "target" — the L7 TCP forward use case, where the
// listener was configured to forward accepted connections to a fixed upstream
// host:port rather than CONNECT-deriving the target from the client. It is
// the forward-side sibling of BuildConnectionStack and shares stack_builder.go's
// private helpers (PerformClientMITM, DialUpstreamWithALPN) for the branches
// that perform TLS.
//
// Contract (USK-912 minimum-viable surface):
//
//   - target is fixed by the caller. This function does NOT consult CONNECT
//     headers, SOCKS5 negotiation results, or any other source of "what host
//     does the client want to reach". The caller obtained the target from
//     operator config (config.ForwardConfig.Target).
//
//   - No SNI is derived from target. When USK-915 wires in TLS termination,
//     the caller will pass the SNI value separately (likely as an additional
//     field on TargetOverrideParams) — the operator-declared target may be
//     an IP literal or a name that differs from the SNI the client would
//     present.
//
//   - ALPN advertise list is caller-supplied verbatim. An empty / nil
//     ALPNOffers slice means "no ALPN extension on the wire" (no defaulting
//     to [h2, http/1.1] like BuildConnectionStack does for the MITM-routed
//     case). Forward callers know what protocol they declared and what they
//     want to advertise to the client / upstream.
//
//   - Protocol selectors other than "raw" return a "not yet wired" error
//     citing the responsible follow-up Issue (USK-913 for L7 dispatch,
//     USK-914 for protocol-specific dispatch, USK-915 for TLS terminate,
//     USK-916 for upstream TLS dial). The signature and the validation pass
//     are real today so downstream Issues can wire in their branch without
//     re-litigating the API surface.
//
//   - upstreamConn must be a dialed, plain (or TLS, when the caller has its
//     own dial path) net.Conn. This builder does NOT dial; it takes the
//     pre-dialed conn so callers retain control of dial timeouts,
//     upstream-proxy resolution, and per-host TLS material (consistent with
//     BuildPlainHTTPStack / BuildPlainH2CStack / BuildBytechunkStack).
//
//   - Returns *ConnectionStack only (vs. the MITM builder's three-value
//     return) because there are no TLS snapshots to surface in the raw case.
//     When USK-915 / USK-916 add TLS termination this signature will be
//     extended (or a sibling builder added — see the seam discipline in
//     CLAUDE.md MITM Principle 2).
//
// Ownership: the returned ConnectionStack owns clientConn and upstreamConn
// via its Layers; callers must defer stack.Close() exactly as the existing
// sibling builders document.
//
// USK-912 implementation scope: the function validates inputs, returns a
// bytechunk stack for ForwardProtocolRaw, and errors for every other
// branch. No client-side TLS terminate happens; no L7 protocol dispatch
// happens; no upstream TLS handshake happens. The "API ready, not yet
// wired" stance is intentional — see the design review record on USK-912.
func BuildConnectionStackWithTarget(
	ctx context.Context,
	clientConn net.Conn,
	upstreamConn net.Conn,
	params TargetOverrideParams,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: nil config")
	}
	if clientConn == nil || upstreamConn == nil {
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: nil conn")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	if params.TLSTerminate {
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: TLSTerminate=true not yet wired (deferred to USK-915)")
	}
	if params.UpstreamTLS {
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: UpstreamTLS=true not yet wired (deferred to USK-916)")
	}

	protocol := params.Protocol
	if protocol == "" {
		protocol = ForwardProtocolAuto
	}

	switch protocol {
	case ForwardProtocolRaw:
		return buildTargetOverrideRawStack(ctx, clientConn, upstreamConn, params.Target, cfg)
	case ForwardProtocolAuto:
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: protocol %q not yet wired (auto-detection deferred to USK-913)", protocol)
	case ForwardProtocolHTTP, ForwardProtocolHTTP2:
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: protocol %q not yet wired (L7 dispatch deferred to USK-913/USK-914)", protocol)
	case ForwardProtocolGRPC, ForwardProtocolWebSocket, ForwardProtocolSSE:
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: protocol %q not yet wired (protocol-specific dispatch deferred to USK-914/USK-915)", protocol)
	default:
		// Unreachable: params.validate already rejects unknown values.
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: unhandled protocol %q", protocol)
	}
}

// buildTargetOverrideRawStack builds the [bytechunk client → bytechunk upstream]
// stack used by ForwardProtocolRaw. It is the target-override counterpart of
// BuildBytechunkStack (connect_inner_dispatch.go); BuildBytechunkStack stays
// the entry point for CONNECT-inner / SOCKS5-inner callers so that the seam
// between MITM-derived and operator-declared targets remains visible in the
// code structure (CLAUDE.md MITM Principle 2).
//
// _ ctx is retained on the signature to give downstream Issues a stable
// callsite shape when they add ctx-aware behaviour (e.g. ctx-cancel-aware
// dial in USK-916). The current bytechunk path performs no I/O so ctx is
// not consulted today.
func buildTargetOverrideRawStack(
	_ context.Context,
	clientConn, upstreamConn net.Conn,
	target string,
	_ *BuildConfig,
) (*ConnectionStack, error) {
	connID := uuid.New().String()
	stack := NewConnectionStack(connID)

	clientLayer := bytechunk.New(clientConn, connID+"/client", envelope.Send)
	stack.PushClient(clientLayer)

	upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
	stack.PushUpstream(upstreamLayer)

	_ = target // bytechunk does not stamp target into envelopes; field is informational
	return stack, nil
}

// PerformClientMITM is the exported wrapper for the package-private
// performClientMITM helper. It performs the client-side TLS MITM handshake,
// issuing a certificate for the given host and offering the specified ALPN
// protocols. The returned TLS-wrapped connection MUST be used for subsequent
// I/O instead of the original plain connection.
//
// Contract for forward callers (USK-912 minimum-viable export):
//
//   - host is the SNI-equivalent name the proxy issues the MITM cert for.
//     Forward callers supply this themselves — there is no SNI to observe
//     because the accepted connection's first TLS bytes are about to be
//     consumed by tlslayer.Server here.
//
//   - alpnOffers is verbatim. An empty / nil slice leaves NextProtos unset
//     so the client never sees the ALPN extension. Forward callers that
//     declared a specific protocol in config (e.g. "http") should pass
//     [http/1.1]; callers that declared "auto" should pass [h2, http/1.1].
//
//   - cfg supplies the cert Issuer and the (tls, on_handshake) PluginV2Engine
//     wiring. It is the same BuildConfig used elsewhere in the package.
//
//   - Observability: this wrapper preserves the test-only
//     ClientMITMHandshakeCount counter incremented by performClientMITM
//     (USK-813). Forward callers that drive their own test harness can
//     read the counter via cfg.ClientMITMHandshakeCount() just like the
//     MITM path does.
//
// USK-912 deliberately does NOT export the lower-level helpers
// (resolvePerHostTLS, alpnRoute, buildStackFromRoute) — they will be
// exported on demand by USK-913/USK-914/USK-915 as actual callsites land,
// not pre-emptively.
func PerformClientMITM(
	ctx context.Context,
	clientConn net.Conn,
	host string,
	alpnOffers []string,
	cfg *BuildConfig,
) (net.Conn, *envelope.TLSSnapshot, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("connector: PerformClientMITM: nil config")
	}
	if cfg.Issuer == nil {
		return nil, nil, fmt.Errorf("connector: PerformClientMITM: nil issuer")
	}
	if clientConn == nil {
		return nil, nil, fmt.Errorf("connector: PerformClientMITM: nil clientConn")
	}
	if host == "" {
		return nil, nil, fmt.Errorf("connector: PerformClientMITM: empty host")
	}
	return performClientMITM(ctx, clientConn, host, alpnOffers, cfg)
}

// DialUpstreamWithALPN is the exported wrapper for the package-private
// dialUpstreamWithALPN helper. It dials upstream and performs TLS, returning
// the connection plus the TLS snapshot whose ALPN field carries the
// negotiated protocol.
//
// Contract for forward callers (USK-912 minimum-viable export):
//
//   - target is the operator-declared "host:port". No SNI is derived from
//     target; pass host (the SNI name) separately. Caller obtained both
//     from operator config (config.ForwardConfig.Target plus future SNI
//     field expected in USK-915).
//
//   - offerALPN is verbatim. An empty / nil slice still produces a TLS
//     handshake (no ALPN extension on the wire) — useful for forward
//     callers that declared "raw" but still want upstream TLS termination.
//
//   - insecureSkip, clientCert, rootCAsConfig are per-call overrides; the
//     caller resolves these against its own per-host policy. Forward
//     callers will typically read them from
//     cfg.ResolvePerHostTLS(target) — which remains private until a
//     downstream Issue (USK-915) needs it.
//
//   - cfg.EffectiveTLSFingerprint and cfg.EffectiveUpstreamProxyForCtx
//     continue to govern uTLS profile selection and upstream-proxy
//     traversal exactly as in the BuildConnectionStack callsite.
//
//   - Observability: the (tls, on_handshake) hook fires for the "client"
//     side (proxy dialing upstream) when snap is non-nil. Forward callers
//     get plugin hook dispatch for free.
//
// USK-912 deliberately does NOT export DialUpstreamRaw at this seam — the
// MITM helper is the right export because it bundles the snapshot-handling
// and plugin-hook-firing in one place. Forward callers that need plain
// TCP dial without TLS continue to use DialUpstreamRaw directly (it is
// already exported).
func DialUpstreamWithALPN(
	ctx context.Context,
	target, host string,
	offerALPN []string,
	insecureSkip bool,
	clientCert *tls.Certificate,
	rootCAsConfig *tls.Config,
	cfg *BuildConfig,
) (net.Conn, *envelope.TLSSnapshot, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("connector: DialUpstreamWithALPN: nil config")
	}
	if target == "" {
		return nil, nil, fmt.Errorf("connector: DialUpstreamWithALPN: empty target")
	}
	if host == "" {
		return nil, nil, fmt.Errorf("connector: DialUpstreamWithALPN: empty host")
	}
	return dialUpstreamWithALPN(ctx, target, host, offerALPN, insecureSkip, clientCert, rootCAsConfig, cfg)
}
