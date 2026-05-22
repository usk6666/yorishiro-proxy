package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// InnerProtocolKind identifies the protocol observed on the inner byte stream
// of a CONNECT (or SOCKS5) tunnel after the negotiation completed. Unlike
// ProtocolKind it never matches CONNECT or SOCKS5 — those are tunnel
// negotiations, not inner protocols — and it adds a TLS branch since the TLS
// ClientHello is the most common inner-byte pattern.
type InnerProtocolKind int

const (
	// InnerUnknown means the peek timed out, errored, or returned no bytes.
	// Callers fall back to bytechunk passthrough so that the connection is
	// still recorded.
	InnerUnknown InnerProtocolKind = iota

	// InnerTLS means the first inner byte is 0x16 (TLS Handshake record
	// content type, RFC 8446 §5). The caller should drive the existing TLS
	// MITM path (BuildConnectionStack).
	InnerTLS

	// InnerHTTP1 means the first inner bytes look like an HTTP/1.x request
	// line (GET / POST / ...). The caller should build a plain-HTTP stack
	// (BuildPlainHTTPStack) with scheme="http".
	InnerHTTP1

	// InnerH2C means the first inner bytes are the HTTP/2 connection preface
	// (RFC 9113 §3.4). The caller should build a plain h2c stack
	// (BuildPlainH2CStack) with scheme="http".
	InnerH2C

	// InnerBytechunk is the fall-through: bytes that look like none of the
	// above. The caller should build a bytechunk pass-through stack so the
	// data is still recorded for diagnostic purposes.
	InnerBytechunk
)

// String returns a human-readable name for the InnerProtocolKind.
func (k InnerProtocolKind) String() string {
	switch k {
	case InnerTLS:
		return "TLS"
	case InnerHTTP1:
		return "HTTP/1.x"
	case InnerH2C:
		return "h2c"
	case InnerBytechunk:
		return "TCP"
	default:
		return "unknown"
	}
}

// DefaultInnerPeekTimeout bounds how long the inner-byte peek waits for the
// client's first byte after the CONNECT 200 reply. Some clients (notably
// browsers reusing a CONNECT tunnel for keep-alive) may pause briefly; some
// clients (notably misconfigured ones) never send anything. The timeout is
// short enough to release the goroutine quickly when the latter happens.
const DefaultInnerPeekTimeout = 5 * time.Second

// classifyInnerByte maps a peeked-bytes prefix to an InnerProtocolKind. The
// rules are:
//
//  1. peek[0] == 0x16 → TLS Handshake (existing MITM path).
//  2. DetectKind result == ProtocolHTTP1 → plain-HTTP-over-CONNECT.
//  3. DetectKind result == ProtocolHTTP2 → h2c-over-CONNECT.
//  4. else → bytechunk passthrough.
//
// SOCKS5 / HTTP CONNECT prefixes that DetectKind returns are not legal inner
// protocols (we already negotiated CONNECT or SOCKS5 to get here) so they
// fold into the bytechunk fallback rather than re-entering the negotiator.
//
// classifyInnerByte never returns InnerUnknown; callers separately detect the
// "no bytes peeked" case and return InnerUnknown themselves.
func classifyInnerByte(peek []byte) InnerProtocolKind {
	if len(peek) == 0 {
		// Defensive — callers should have returned InnerUnknown already,
		// but classify-with-empty-peek is safe to treat as bytechunk.
		return InnerBytechunk
	}
	// TLS Handshake content type (RFC 8446 §5). One byte is sufficient: no
	// HTTP method or h2c preface starts with 0x16.
	if peek[0] == 0x16 {
		return InnerTLS
	}
	switch DetectKind(peek) {
	case ProtocolHTTP1:
		return InnerHTTP1
	case ProtocolHTTP2:
		return InnerH2C
	default:
		return InnerBytechunk
	}
}

// peekInnerProtocol peeks up to PeekSize bytes from pc with a bounded
// deadline and returns the InnerProtocolKind. The caller MUST have negotiated
// the tunnel (CONNECT or SOCKS5) before invoking peekInnerProtocol; the peek
// happens on the inner byte stream the client sends after the 200 reply.
//
// The deadline is set on the underlying conn only for the first single-byte
// peek; it is cleared before the optional larger-window peek so a partial
// read does not contaminate the bufio.Reader's sticky error field. After the
// function returns the conn has no deadline so the inner Layer's own reads
// behave normally.
//
// Errors are not propagated separately from the kind: a failed or empty peek
// collapses to InnerUnknown so the caller can fall through to bytechunk
// recording (or close the connection).
//
// This function does NOT consume any bytes — bytes peeked via PeekConn remain
// in the buffer and are read again by the inner Layer's reader.
//
// Why two stages: bufio.Reader.Peek(n) blocks until n bytes are available OR
// an error occurs. Asking for PeekSize (16) bytes when the client only sends
// a 6-byte payload would block until the deadline fires, AND would leave the
// bufio.Reader's internal err field set to the timeout error — making every
// subsequent Read return "i/o timeout" even after we clear the conn deadline.
// Stage 1 asks for 1 byte (always succeeds when any byte is present); stage 2
// uses Buffered() to inspect bytes the kernel already delivered without
// triggering a second blocking read.
func peekInnerProtocol(pc *PeekConn, timeout time.Duration) (InnerProtocolKind, []byte) {
	// Stage 1: bound the wait for the first byte by the deadline. Once a
	// byte arrives the deadline serves no further purpose; reset it before
	// the second peek so a stage-1 timeout does not stick to the bufio
	// reader's err field via partial-read semantics.
	if timeout > 0 {
		_ = pc.SetReadDeadline(time.Now().Add(timeout))
	}
	peek, err := pc.Peek(QuickPeekSize)
	if timeout > 0 {
		_ = pc.SetReadDeadline(time.Time{})
	}
	if len(peek) == 0 {
		_ = err
		return InnerUnknown, nil
	}

	// Stage 2: opportunistically widen the peek using bytes the kernel has
	// already delivered into the bufio buffer (no extra Read syscall). We
	// never block here: Peek(buffered) returns instantly because the bytes
	// are already in memory. This lets us disambiguate "GE" vs "GET" /
	// "PRI * HT" vs "PRI" when more than one byte arrived in the same TCP
	// segment, which is the common case.
	if buffered := pc.Buffered(); buffered > QuickPeekSize {
		n := buffered
		if n > PeekSize {
			n = PeekSize
		}
		if widePeek, werr := pc.Peek(n); werr == nil && len(widePeek) > 0 {
			peek = widePeek
		}
	}
	return classifyInnerByte(peek), peek
}

// errInnerPeekFailed is returned by dispatchInnerProtocol when the peek
// returned no bytes. Callers may log it at Debug; the connection has been
// closed already.
var errInnerPeekFailed = errors.New("connector: inner-byte peek returned no bytes")

// BuildPlainH2CStack constructs a ConnectionStack for a cleartext HTTP/2
// (h2c) connection that rides inside a CONNECT (or SOCKS5) tunnel. Both
// sides are plain TCP — no TLS handshake on either side — so EnvelopeContext.
// TLS is nil per RFC-001 §3.1.
//
// The stack is [http2 ServerRole (client) → http2 ClientRole (upstream)]
// with scheme="http". It mirrors the h2 case of buildH2Stack
// (stack_builder.go) but without the TLS layers: the wire-fidelity principle
// says the proxy must not pretend TLS happened when it did not.
//
// Pool integration is intentionally omitted: the HTTP/2 connection pool
// (cfg.HTTP2Pool) keys on (host:port, TLS config hash). A cleartext h2c
// connection has no TLS material to hash; folding it into the same pool
// would require a second key shape and is out of scope for USK-762.
//
// Ownership: the returned ConnectionStack owns clientConn and upstreamConn
// via its layers; callers must defer stack.Close() exactly as the
// CONNECT-MITM path does. The stack does not register an upstream H2 Layer
// via setUpstreamH2 — both layers are in the standard sideStacks so
// stack.Close() closes them both.
func BuildPlainH2CStack(
	ctx context.Context,
	clientConn net.Conn,
	upstreamConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: BuildPlainH2CStack: nil config")
	}
	if clientConn == nil || upstreamConn == nil {
		return nil, fmt.Errorf("connector: BuildPlainH2CStack: nil conn")
	}

	connID := uuid.New().String()

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// TLS intentionally nil: no handshake happened on the client side.
	}
	upstreamEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// TLS intentionally nil: no handshake happened on the upstream side.
	}

	stack := NewConnectionStack(connID)

	// USK-871: construct upstream first so we can sniff its
	// SETTINGS_ENABLE_CONNECT_PROTOCOL value before building the
	// client-facing ServerRole, mirroring it into our advertise.
	upstreamLayer, err := http2.New(upstreamConn, connID+"/upstream", http2.ClientRole,
		http2.WithScheme("http"),
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
		return nil, fmt.Errorf("connector: BuildPlainH2CStack: upstream h2 layer: %w", err)
	}

	enableConnectProtocol := resolveEnableConnectProtocol(ctx, upstreamLayer, false, connID, target)

	clientH2Opts := []http2.Option{
		http2.WithScheme("http"),
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
		return nil, fmt.Errorf("connector: BuildPlainH2CStack: client h2 layer: %w", err)
	}
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)

	return stack, nil
}

// BuildBytechunkStack constructs a ConnectionStack with a bytechunk Layer on
// each side. It is the fallback used inside CONNECT / SOCKS5 tunnels when
// inner-byte peek returns bytes that match no known L7 protocol — observation
// only, no L7 parsing.
//
// Both sides are plain TCP (no TLS handshake), and EnvelopeContext.TLS is nil
// per RFC-001 §3.1. Used by the inner-protocol fallback branch in CONNECT /
// SOCKS5 handlers when peek reveals neither TLS nor an HTTP family byte.
//
// Ownership: the returned stack owns both conns; callers must defer
// stack.Close().
func BuildBytechunkStack(
	clientConn net.Conn,
	upstreamConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if clientConn == nil || upstreamConn == nil {
		return nil, fmt.Errorf("connector: BuildBytechunkStack: nil conn")
	}
	_ = cfg // reserved for future per-stack config; bytechunk has no knobs

	connID := uuid.New().String()
	stack := NewConnectionStack(connID)

	stack.PushClient(bytechunk.New(clientConn, connID+"/client", envelope.Send))
	stack.PushUpstream(bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive))
	_ = target // target is informational; bytechunk does not stamp it
	return stack, nil
}

// dialPlainUpstream dials upstream plain TCP for inner-protocol branches that
// do not perform a TLS handshake (plain HTTP/1.x, h2c, bytechunk). The
// upstream proxy URL (cfg.EffectiveUpstreamProxy) is honored when configured.
//
// The dial timeout is the package-level defaultDialTimeout; the inner-peek
// timeout that brackets the client-side peek is independent.
func dialPlainUpstream(ctx context.Context, target string, cfg *BuildConfig) (net.Conn, error) {
	var dialOpts DialRawOpts
	if cfg != nil {
		u, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
		if err != nil {
			// USK-959: fail-closed on rotation resolver error.
			return nil, fmt.Errorf("connector: plain upstream dial for %s: upstream proxy rotation: %w", target, err)
		}
		dialOpts.UpstreamProxy = u
	}
	conn, _, err := DialUpstreamRaw(ctx, target, dialOpts)
	if err != nil {
		return nil, fmt.Errorf("connector: plain upstream dial for %s: %w", target, err)
	}
	return conn, nil
}

// innerDispatchConfig bundles the parameters dispatchInnerProtocol needs.
// Kept separate from CONNECTHandlerConfig / SOCKS5HandlerConfig so that both
// negotiator entry points can share the same dispatcher without depending
// on each other's config struct.
type innerDispatchConfig struct {
	// PeekTimeout bounds the inner-byte peek. Zero means
	// DefaultInnerPeekTimeout.
	PeekTimeout time.Duration

	// PeekTimeoutProvider, when non-nil, is consulted on every dispatch
	// so a runtime SetRequestTimeout on the owning Listener (USK-844)
	// takes effect on the next accepted tunnel without rebuilding the
	// handler. Returning <=0 falls back to the static PeekTimeout /
	// DefaultInnerPeekTimeout.
	PeekTimeoutProvider func() time.Duration

	// BuildCfg supplies stack construction options (issuer, body spill, etc).
	BuildCfg *BuildConfig

	// OnStack is invoked for HTTP/1.x and bytechunk inner stacks (no
	// per-stream fan-out at the connector level). Required.
	OnStack OnStackFunc

	// OnHTTP2Stack is invoked for h2c inner stacks. Required when h2c
	// dispatch is desired; nil falls back to bytechunk for h2c traffic.
	OnHTTP2Stack OnHTTP2StackFunc

	// Logger receives diagnostic output. Nil uses slog.Default().
	Logger *slog.Logger
}

// resolveInnerPeekTimeout returns the effective inner-byte peek deadline.
// Precedence (USK-844):
//  1. cfg.PeekTimeoutProvider (runtime hot-reload via Manager).
//  2. cfg.PeekTimeout (boot-time / static value).
//  3. DefaultInnerPeekTimeout package default.
//
// Non-positive values from the provider or the static field collapse to the
// next tier so the "0 = default" wire shape is preserved end-to-end.
func resolveInnerPeekTimeout(cfg innerDispatchConfig) time.Duration {
	if cfg.PeekTimeoutProvider != nil {
		if d := cfg.PeekTimeoutProvider(); d > 0 {
			return d
		}
	}
	if cfg.PeekTimeout > 0 {
		return cfg.PeekTimeout
	}
	return DefaultInnerPeekTimeout
}

// dispatchInnerProtocol peeks the inner byte stream of an already-negotiated
// CONNECT or SOCKS5 tunnel and routes the connection to the appropriate
// stack builder.
//
// The TLS branch hands the work back to the caller via runTLSPath because
// the TLS path needs the BuildConnectionStack-level integration with the
// pluginv2 (tls, on_handshake) hook. Plain HTTP/1.x, h2c, and bytechunk
// are dispatched in-place.
//
// dispatchInnerProtocol does NOT close pc on the TLS branch — runTLSPath
// owns that. On every other branch, the returned stack owns pc; OnStack /
// OnHTTP2Stack is responsible for stack.Close.
//
// Returns true if the inner-byte peek resolved to TLS and the caller should
// run the TLS MITM path (via BuildConnectionStack); false in every other
// case (the inner protocol was already dispatched, or the peek failed and
// the connection has been closed).
func dispatchInnerProtocol(
	ctx context.Context,
	pc *PeekConn,
	target string,
	cfg innerDispatchConfig,
) (handleAsTLS bool) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := resolveInnerPeekTimeout(cfg)

	kind, peek := peekInnerProtocol(pc, timeout)
	if kind == InnerUnknown {
		logger.Debug("inner-byte peek failed; closing tunnel",
			"target", target, "error", errInnerPeekFailed)
		// Caller's deferred PeekConn.Close in FullListener handles teardown.
		return false
	}

	logger.Debug("inner-byte peek classified",
		"target", target, "inner_kind", kind.String(), "peek_len", len(peek))

	switch kind {
	case InnerTLS:
		// The TLS MITM path needs Issuer + ALPN cache + plugin hooks; the
		// caller (NewCONNECTHandler / NewSOCKS5Handler) owns that wiring
		// because it has access to BuildConnectionStack.
		return true

	case InnerHTTP1:
		dispatchPlainInner(ctx, pc, target, cfg, logger, dispatchInnerHTTP1)
		return false

	case InnerH2C:
		if cfg.OnHTTP2Stack == nil {
			// No h2c handler wired — fall through to bytechunk so the
			// connection is still observable.
			logger.Debug("h2c inner detected but OnHTTP2Stack not wired; falling back to bytechunk",
				"target", target)
			dispatchPlainInner(ctx, pc, target, cfg, logger, dispatchInnerBytechunk)
			return false
		}
		dispatchPlainInner(ctx, pc, target, cfg, logger, dispatchInnerH2C)
		return false

	case InnerBytechunk:
		dispatchPlainInner(ctx, pc, target, cfg, logger, dispatchInnerBytechunk)
		return false
	}

	return false
}

// innerDispatcherFn is the signature shared by per-protocol inner-stack
// dispatchers. Each implementation builds the protocol-specific stack and
// invokes the appropriate callback (OnStack / OnHTTP2Stack).
type innerDispatcherFn func(
	ctx context.Context,
	pc *PeekConn,
	upstreamConn net.Conn,
	target string,
	cfg innerDispatchConfig,
	logger *slog.Logger,
)

// dispatchPlainInner is the shared "dial upstream then build stack" wrapper
// used by HTTP/1.x, h2c, and bytechunk branches. It dials the upstream plain
// TCP connection then delegates to the per-protocol dispatcher; on dial
// failure it closes pc (the listener's defer would also close it, but
// closing here makes the failure mode explicit).
func dispatchPlainInner(
	ctx context.Context,
	pc *PeekConn,
	target string,
	cfg innerDispatchConfig,
	logger *slog.Logger,
	dispatcher innerDispatcherFn,
) {
	upstreamConn, err := dialPlainUpstream(ctx, target, cfg.BuildCfg)
	if err != nil {
		logger.Debug("inner plain upstream dial failed",
			"target", target, "error", err)
		_ = pc.Close()
		return
	}

	dispatcher(ctx, pc, upstreamConn, target, cfg, logger)
}

func dispatchInnerHTTP1(
	ctx context.Context,
	pc *PeekConn,
	upstreamConn net.Conn,
	target string,
	cfg innerDispatchConfig,
	logger *slog.Logger,
) {
	stack, err := BuildPlainHTTPStack(pc, upstreamConn, target, cfg.BuildCfg)
	if err != nil {
		_ = upstreamConn.Close()
		logger.Warn("inner plain-HTTP stack build failed",
			"target", target, "error", err)
		return
	}
	logger.Debug("inner plain-HTTP stack built", "target", target)
	if cfg.OnStack != nil {
		cfg.OnStack(ctx, stack, nil, nil, target)
	} else {
		_ = stack.Close()
	}
}

func dispatchInnerH2C(
	ctx context.Context,
	pc *PeekConn,
	upstreamConn net.Conn,
	target string,
	cfg innerDispatchConfig,
	logger *slog.Logger,
) {
	stack, err := BuildPlainH2CStack(ctx, pc, upstreamConn, target, cfg.BuildCfg)
	if err != nil {
		_ = upstreamConn.Close()
		logger.Warn("inner h2c stack build failed",
			"target", target, "error", err)
		return
	}
	logger.Debug("inner h2c stack built", "target", target)

	// h2c uses the OnHTTP2Stack callback so per-stream dispatch goes through
	// the existing buildOnHTTP2Stack wiring. The upstream Layer is the
	// stack's UpstreamTopmost (since BuildPlainH2CStack uses PushUpstream
	// rather than setUpstreamH2 — there is no pool to integrate with for
	// cleartext h2c yet).
	upstreamH2, ok := stack.UpstreamTopmost().(*http2.Layer)
	if !ok {
		_ = stack.Close()
		logger.Warn("inner h2c upstream layer is not *http2.Layer",
			"target", target, "type", fmt.Sprintf("%T", stack.UpstreamTopmost()))
		return
	}
	if cfg.OnHTTP2Stack != nil {
		cfg.OnHTTP2Stack(ctx, stack, upstreamH2, nil, nil, target)
	}
	// dispatchStack-style ownership: client-side stack always closed on
	// exit. The upstream Layer for h2c is in the stack itself (no pool),
	// so stack.Close handles it too.
	_ = stack.Close()
}

func dispatchInnerBytechunk(
	ctx context.Context,
	pc *PeekConn,
	upstreamConn net.Conn,
	target string,
	cfg innerDispatchConfig,
	logger *slog.Logger,
) {
	stack, err := BuildBytechunkStack(pc, upstreamConn, target, cfg.BuildCfg)
	if err != nil {
		_ = upstreamConn.Close()
		logger.Warn("inner bytechunk stack build failed",
			"target", target, "error", err)
		return
	}
	logger.Debug("inner bytechunk stack built", "target", target)
	if cfg.OnStack != nil {
		cfg.OnStack(ctx, stack, nil, nil, target)
	} else {
		_ = stack.Close()
	}
}
