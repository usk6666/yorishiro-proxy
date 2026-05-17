package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
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
	// the accepted connection. Wired by USK-913: a short bounded peek on
	// clientConn picks HTTP/1.x → HTTP arm, h2c preface → reject with
	// USK-914 citation, TLS first byte → warn + Raw fallback,
	// everything else → Raw fallback. Callers that need true H2C should
	// declare Protocol="http2" explicitly (USK-914).
	ForwardProtocolAuto ForwardProtocol = "auto"

	// ForwardProtocolRaw builds a [bytechunk → bytechunk] stack — the
	// only protocol fully wired in USK-912. Equivalent to the bytechunk
	// case of buildStackFromRoute but with the target supplied verbatim
	// by the caller (no CONNECT/SNI derivation).
	ForwardProtocolRaw ForwardProtocol = "raw"

	// ForwardProtocolHTTP requests a plain HTTP/1.x stack. Wired by
	// USK-913: assembles [http1 client → http1 upstream] with scheme="http"
	// matching the BuildPlainHTTPStack shape. Per-exchange dispatch and
	// the WS/SSE Upgrade swap are driven by the caller via
	// session.RunStackSessionExchange + the Pipeline-mounted UpgradeStep.
	ForwardProtocolHTTP ForwardProtocol = "http"

	// ForwardProtocolHTTP2 requests an h2c stack. Wired by USK-914 —
	// builds [http2 ServerRole client → http2 ClientRole upstream] with
	// scheme="http" and SETTINGS_ENABLE_CONNECT_PROTOCOL mirrored from
	// upstream. Both gRPC and gRPC-Web auto-route via DispatchH2Stream at
	// the per-stream proxybuild dispatch layer (no filter).
	ForwardProtocolHTTP2 ForwardProtocol = "http2"

	// ForwardProtocolGRPC requests an h2c + gRPC content-type filter
	// stack. Wired by USK-914 — assembles the same h2c stack as
	// ForwardProtocolHTTP2; the per-stream dispatch layer additionally
	// validates each stream's content-type against application/grpc[+...]
	// and rejects non-gRPC traffic (including gRPC-Web) with
	// RST_STREAM(REFUSED_STREAM).
	ForwardProtocolGRPC ForwardProtocol = "grpc"

	// ForwardProtocolWebSocket requests an HTTP/1.x stack whose first
	// exchange is expected to initiate an RFC 6455 Upgrade. Wired by
	// USK-913: the stack assembly is identical to ForwardProtocolHTTP;
	// the filter ("first request must be a WS upgrade or 502") is applied
	// at the proxybuild handler layer, not inside this builder.
	ForwardProtocolWebSocket ForwardProtocol = "websocket"

	// ForwardProtocolSSE requests an HTTP/1.x stack whose first response
	// is expected to carry text/event-stream. Wired by USK-913: stack
	// assembly is identical to ForwardProtocolHTTP; the filter ("first
	// response must be SSE or 502") is applied at the proxybuild handler
	// layer.
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
	//
	// USK-915: in-builder TLS termination remains deferred. The forward
	// path performs TLS termination BEFORE calling this builder (using
	// connector.PerformClientMITM or an SNI-honoring sibling), then passes
	// the wrapped *tls.Conn as clientConn together with Scheme="https"
	// and (optionally) ClientTLSSnapshot. This keeps the builder a single-
	// purpose stack assembler and matches the seam discipline in
	// CLAUDE.md MITM Principle 2.
	TLSTerminate bool

	// UpstreamTLS, when true, indicates the caller wants the upstream
	// dial to perform a TLS handshake. The upstream-TLS dial wire-up is
	// owned by USK-916 and is NOT implemented by USK-912; setting
	// UpstreamTLS=true currently returns a "not yet wired" error.
	UpstreamTLS bool

	// Scheme overrides the envelope Scheme stamped by the assembled L7
	// Layers. Defaults to "http" when unset, matching the cleartext
	// forward path (USK-913 / USK-914). The forward TCP path sets this to
	// "https" once it has terminated TLS on the client conn (USK-915);
	// downstream Issues that wire upstream-TLS-only forwards may keep
	// "http" here when the client conn is cleartext but the upstream is
	// encrypted (the recorded Scheme reflects the client-facing wire,
	// matching the rest of the proxy's per-Layer Scheme convention).
	//
	// Validation: must be empty (treated as "http"), "http", or "https".
	// Unknown values are rejected at validate() with a clear error so
	// typos surface at the API boundary rather than at envelope-stamping
	// time deep inside the Layer.
	Scheme string

	// ClientTLSSnapshot, when non-nil, is plumbed into the client-side
	// EnvelopeContext.TLS field of the assembled L7 Layers so plugin hooks
	// and recordings see the negotiated SNI / ALPN / cipher for the
	// terminated client TLS handshake. Forward callers that terminate TLS
	// themselves (USK-915) own this field; cleartext forward callers leave
	// it nil and Scheme="" (or "http"). Mirrors the per-Layer TLS wiring
	// in stack_builder.go::buildStackFromRoute (live MITM CONNECT path).
	ClientTLSSnapshot *envelope.TLSSnapshot
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
	switch p.Scheme {
	case "", "http", "https":
		// valid
	default:
		return fmt.Errorf("connector: BuildConnectionStackWithTarget: invalid Scheme %q (valid: \"\", http, https)", p.Scheme)
	}
	return nil
}

// effectiveScheme resolves the Scheme override declared by the caller into
// the concrete "http" / "https" value the L7 Layers stamp onto envelopes.
// Empty is treated as "http" — the cleartext default that matches USK-913
// and USK-914 callers.
func (p *TargetOverrideParams) effectiveScheme() string {
	if p == nil || p.Scheme == "" {
		return "http"
	}
	return p.Scheme
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
	case ForwardProtocolHTTP, ForwardProtocolWebSocket, ForwardProtocolSSE:
		// USK-913: HTTP/1.x stack assembly is identical across the three
		// arms. The "websocket"/"sse" expectation filter is applied at the
		// proxybuild handler layer (it must observe the first request /
		// first response, which is per-exchange Pipeline territory rather
		// than per-stack-builder territory).
		return buildTargetOverrideHTTPStack(ctx, clientConn, upstreamConn, params.Target, params.effectiveScheme(), params.ClientTLSSnapshot, cfg)
	case ForwardProtocolAuto:
		// USK-913: peek the first inner byte on clientConn to disambiguate
		// HTTP/1.x → http arm, h2c → reject with USK-914 citation, TLS →
		// warn + raw fallback, everything else → raw fallback.
		return buildTargetOverrideAutoStack(ctx, clientConn, upstreamConn, params.Target, params.effectiveScheme(), params.ClientTLSSnapshot, cfg)
	case ForwardProtocolHTTP2, ForwardProtocolGRPC:
		// USK-914: h2c forward stack. The GRPC selector reuses the same
		// h2c stack assembly; the gRPC content-type filter is applied at
		// the per-stream proxybuild dispatch layer (see
		// internal/proxybuild/tcp_forward_h2.go).
		return buildTargetOverrideH2CStack(ctx, clientConn, upstreamConn, params.Target, params.effectiveScheme(), params.ClientTLSSnapshot, cfg)
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

// targetOverrideH2CPrefaceReadDeadline bounds how long the ServerRole HTTP/2
// Layer's preface validation waits for the 24-byte client preface
// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", RFC 9113 §3.4). Forward callers
// accept arbitrary TCP and pass it straight to http2.New(ServerRole) when
// Protocol="http2" or "grpc"; without a read deadline a slow or never-
// sending client could pin the per-conn goroutine indefinitely. Defensive
// default; future Issues may surface this as a config knob.
const targetOverrideH2CPrefaceReadDeadline = 30 * time.Second

// buildTargetOverrideH2CStack assembles the [http2 ServerRole client →
// http2 ClientRole upstream] h2c stack used by ForwardProtocolHTTP2 and
// ForwardProtocolGRPC. Modelled on BuildPlainH2CStack (the
// CONNECT-inner-h2c sibling) with two operational adjustments for the
// forward path:
//
//  1. clientConn carries a 30 s read deadline across the ServerRole
//     preface validation (slow-handshake DoS defence — the CONNECT-inner
//     path is already protected by the inner-byte peek timeout).
//  2. SETTINGS_ENABLE_CONNECT_PROTOCOL mirror runs the same way; advertising
//     1 to the client is harmless when extended-CONNECT is unused.
//
// The gRPC content-type filter that distinguishes ForwardProtocolHTTP2
// from ForwardProtocolGRPC is applied at the per-stream proxybuild
// dispatch layer (proxybuild.runTCPForwardH2Loop). This builder is
// protocol-agnostic between the two.
//
// Ownership: the returned stack owns both conns; callers must defer
// stack.Close(). On any constructor failure both conns are closed.
func buildTargetOverrideH2CStack(
	ctx context.Context,
	clientConn, upstreamConn net.Conn,
	target string,
	scheme string,
	clientTLS *envelope.TLSSnapshot,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if scheme == "" {
		scheme = "http"
	}
	connID := uuid.New().String()

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// USK-915: client-side TLS snapshot is stamped here when the forward
		// path terminated TLS before calling this builder. Upstream stays
		// cleartext (h2c) — upstream-TLS dial is owned by USK-916.
		TLS: clientTLS,
	}
	upstreamEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
	}

	stack := NewConnectionStack(connID)

	// Upstream first so we can sniff its SETTINGS_ENABLE_CONNECT_PROTOCOL
	// value (mirrors BuildPlainH2CStack USK-871 commentary).
	upstreamLayer, err := http2.New(upstreamConn, connID+"/upstream", http2.ClientRole,
		http2.WithScheme(scheme),
		http2.WithEnvelopeContext(upstreamEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
	)
	if err != nil {
		// http2.New already closed upstreamConn on failure; close the
		// client conn to release resources.
		_ = clientConn.Close()
		return nil, fmt.Errorf("connector: buildTargetOverrideH2CStack: upstream h2 layer: %w", err)
	}

	enableConnectProtocol := resolveEnableConnectProtocol(ctx, upstreamLayer, false, connID, target)

	// Apply a bounded read deadline across the ServerRole preface
	// validation. Cleared before the function returns so the Layer's
	// own reads behave normally afterwards. This is the forward-path
	// equivalent of the CONNECT inner-byte peek timeout (which already
	// protects the CONNECT-inner h2c path before BuildPlainH2CStack
	// runs).
	if conn, ok := clientConn.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		_ = conn.SetReadDeadline(time.Now().Add(targetOverrideH2CPrefaceReadDeadline))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}

	clientH2Opts := []http2.Option{
		http2.WithScheme(scheme),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
		http2.WithEnableConnectProtocol(enableConnectProtocol),
	}
	if mcsOpt := clientH2MaxConcurrentStreamsOption(cfg); mcsOpt != nil {
		clientH2Opts = append(clientH2Opts, mcsOpt)
	}
	clientLayer, err := http2.New(clientConn, connID+"/client", http2.ServerRole, clientH2Opts...)
	if err != nil {
		_ = upstreamLayer.Close()
		_ = clientConn.Close()
		return nil, fmt.Errorf("connector: buildTargetOverrideH2CStack: client h2 layer: %w", err)
	}
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)

	return stack, nil
}

// buildTargetOverrideHTTPStack is the target-override sibling of
// BuildPlainHTTPStack: it assembles [http1 client → http1 upstream] with
// scheme="http", the canonical Send/Receive direction wiring, and the
// SSE streaming-response detect predicate so the Upgrade swap orchestrator
// can take over the body without the http1 Layer draining it first.
//
// USK-913: this is the shared assembly used by ForwardProtocolHTTP /
// ForwardProtocolWebSocket / ForwardProtocolSSE. The three differ only in
// the operator's declared expectation; the wire shape is identical
// (HTTP/1.x request → upstream HTTP/1.x response, optionally followed by
// a 101 + WS / 200 + SSE swap). The expectation filter lives at the
// proxybuild handler layer (the per-exchange Pipeline + envelope inspection
// territory).
//
// Body buffering and StateReleaser wiring mirror BuildPlainHTTPStack so
// plugin hooks (http1.on_request / http1.on_response, ws.on_message after
// swap, sse.on_event after swap) fire identically to the MITM-routed
// plain-HTTP path.
//
// Ownership: the returned stack owns clientConn and upstreamConn via its
// Layers; the caller MUST defer stack.Close().
//
// _ ctx is currently unused (assembly is synchronous) but retained on the
// signature so downstream Issues (USK-916 upstream TLS) can wire ctx-aware
// behaviour without churning the callsite.
func buildTargetOverrideHTTPStack(
	_ context.Context,
	clientConn, upstreamConn net.Conn,
	target string,
	scheme string,
	clientTLS *envelope.TLSSnapshot,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if scheme == "" {
		scheme = "http"
	}
	connID := uuid.New().String()

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// USK-915: client-side TLS snapshot is stamped here when the forward
		// path terminated TLS before calling this builder. Upstream stays
		// cleartext — upstream-TLS dial is owned by USK-916.
		TLS: clientTLS,
	}
	upstreamEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// TLS intentionally nil: no handshake happened on the upstream side.
	}

	stack := NewConnectionStack(connID)

	clientLayer := http1.New(clientConn, connID+"/client", envelope.Send,
		http1.WithScheme(scheme),
		http1.WithEnvelopeContext(clientEnvCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
	)
	stack.PushClient(clientLayer)

	upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
		http1.WithScheme(scheme),
		http1.WithEnvelopeContext(upstreamEnvCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
		// USK-655 / mirror BuildPlainHTTPStack: bypass body draining for SSE
		// responses so the swap orchestrator (session.runUpgradeSSE) can hand
		// the still-open body to sse.Wrap without blocking on a never-ending
		// drain. Required for both Protocol="http" (upstream may opt into SSE)
		// and Protocol="sse" (upstream is expected to produce SSE).
		http1.WithStreamingResponseDetect(http1.IsSSEResponse),
	)
	stack.PushUpstream(upstreamLayer)

	return stack, nil
}

// targetOverrideAutoPeekTimeout bounds the inner-byte peek used by the
// Auto arm. Mirrors connector.DefaultInnerPeekTimeout so behaviour is
// consistent with the CONNECT-inner peek; kept as a package-private const
// so it can be tuned without touching the public surface.
const targetOverrideAutoPeekTimeout = 5 * time.Second

// buildTargetOverrideAutoStack peeks the first inner byte on clientConn and
// dispatches to the HTTP or Raw arm. The peek mirrors connector.peekInnerProtocol
// (CONNECT/SOCKS5 inner classification), with the differences that:
//
//   - The peek happens on clientConn directly (it has not been negotiated
//     through a CONNECT tunnel) — we wrap it in a PeekConn ourselves so the
//     bytes flow through to the inner http1 Layer's parser exactly like
//     the inner-byte fallthrough in connect_inner_dispatch.dispatchInnerHTTP1.
//
//   - InnerH2C is rejected with a USK-914 citation (Auto does NOT
//     opportunistically negotiate h2c — operators that want h2c must
//     declare Protocol="http2" explicitly).
//
//   - InnerTLS triggers a Warn log + Raw fallback. The operator did not
//     declare TLS termination (TLSTerminate=true is the only path that
//     terminates client-side TLS — deferred to USK-915), so the most we
//     can offer is byte-faithful recording via bytechunk.
//
//   - InnerUnknown / InnerBytechunk falls through to Raw.
//
// On HTTP routing the wrapped PeekConn replaces clientConn in the assembled
// stack so the peeked bytes are still available to the http1 parser. The
// caller's handler does NOT have to know about the PeekConn — it sees the
// returned ConnectionStack identically to a direct HTTP arm invocation.
func buildTargetOverrideAutoStack(
	ctx context.Context,
	clientConn, upstreamConn net.Conn,
	target string,
	scheme string,
	clientTLS *envelope.TLSSnapshot,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	pc, ok := clientConn.(*PeekConn)
	if !ok {
		pc = NewPeekConn(clientConn)
	}

	kind, _ := peekInnerProtocol(pc, targetOverrideAutoPeekTimeout)

	// BuildConfig has no logger slot today; pick up the per-connection logger
	// from ctx (proxybuild.handleTCPForwardConn calls ContextWithLogger before
	// dispatching) and fall back to slog.Default() otherwise.
	logger := LoggerFromContext(ctx, slog.Default())

	switch kind {
	case InnerHTTP1:
		logger.Debug("connector: target-override Auto resolved to HTTP/1.x",
			"target", target)
		return buildTargetOverrideHTTPStack(ctx, pc, upstreamConn, target, scheme, clientTLS, cfg)
	case InnerH2C:
		// Don't opportunistically negotiate h2c — operators must declare
		// Protocol="http2" explicitly. USK-914 wired the h2c arm; we still
		// require an explicit declaration here so Auto stays predictable
		// (operators that want h2c forwarding declare it; Auto never
		// silently upgrades to h2c on the basis of a connection preface).
		return nil, fmt.Errorf("connector: BuildConnectionStackWithTarget: Auto peek observed h2c connection preface; explicit Protocol=\"http2\" required")
	case InnerTLS:
		// Auto saw TLS without TLSTerminate=true. Most we can offer is
		// byte-faithful recording — fall through to Raw. Log at Warn since
		// this is an unexpected-but-recoverable shape per CLAUDE.md
		// log-level guidance.
		logger.Warn("connector: target-override Auto observed TLS first byte without TLSTerminate; falling back to Raw (declare TLSTerminate=true for MITM — deferred to USK-915)",
			"target", target)
		return buildTargetOverrideRawStack(ctx, pc, upstreamConn, target, cfg)
	default:
		// InnerUnknown / InnerBytechunk — fall through to Raw. Log at
		// Debug because this is the design-intended graceful fallback;
		// raw recording is still useful (L4-capable principle).
		logger.Debug("connector: target-override Auto fell back to Raw",
			"target", target, "peek_kind", kind.String())
		return buildTargetOverrideRawStack(ctx, pc, upstreamConn, target, cfg)
	}
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
