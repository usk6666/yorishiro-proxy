package connector

import (
	"context"
	"fmt"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// PlainHTTPStackOption configures BuildPlainHTTPStack.
type PlainHTTPStackOption func(*plainHTTPStackOptions)

type plainHTTPStackOptions struct {
	forwardOriginForm bool
	forwardRouter     *ForwardRouter
}

// WithForwardProxyOriginForm makes the stack's client-side http1 Layer the
// ingress of the explicit plain-HTTP forward proxy (USK-1117): requests
// are sent upstream in origin-form without Proxy-Connection /
// Proxy-Authorization, while the recording stays as received. Only the
// forward handler passes it; plaintext inside a CONNECT / SOCKS5 tunnel
// (dispatchInnerHTTP1) is relayed in the form the client chose.
func WithForwardProxyOriginForm() PlainHTTPStackOption {
	return func(o *plainHTTPStackOptions) { o.forwardOriginForm = true }
}

// WithForwardRouting routes every request of the stack to the upstream it
// names (USK-1410): the client-side http1 Layer resolves each request's
// target (resolveForwardTarget, the rule the first request was dialed by)
// and stamps it as the request's TargetHost, and router is attached to the
// stack (ConnectionStack.ForwardRouter) so the session's upstream dial
// switches the connection's upstream when a request names another host.
// Only the forward handler passes it, independent of
// WithForwardProxyOriginForm. Plaintext inside a CONNECT / SOCKS5 tunnel,
// transparent mode and tcp_forwards never do: their connection is pinned
// to the target the client tunnelled to or the listener names.
func WithForwardRouting(router *ForwardRouter) PlainHTTPStackOption {
	return func(o *plainHTTPStackOptions) { o.forwardRouter = router }
}

// BuildPlainHTTPStack constructs a ConnectionStack for a plain HTTP/1.x
// forward-proxy connection. Unlike BuildConnectionStack it performs NO TLS
// handshake on either side: clientConn and upstreamConn are plain TCP
// connections, and EnvelopeContext.TLS is nil per RFC-001 §3.1 (TLS is
// per-Layer, never synthesized when no handshake happened).
//
// The stack is [http1 ServerRole (client) → http1 ClientRole (upstream)]
// with scheme="http". It mirrors the http1 case of BuildConnectionStack /
// buildStackFromRoute (lines 573-598 in stack_builder.go) but without the
// TLS layers — the wire-fidelity principle says the proxy must not pretend
// TLS happened when it did not.
//
// Ownership: the returned ConnectionStack owns clientConn and upstreamConn
// via its layers; callers must defer stack.Close() exactly as the
// CONNECT-MITM path does.
//
// ctx carries a value, not cancellation: the stack and both Layers adopt
// the connection's ConnID from it (ConnIDOrGenerate), so the Streams they
// record join the accept-time conn_id in the logs. Construction is purely
// synchronous (no I/O, no dial); cancellation belongs to the caller's dial
// step and to the per-Layer session loop.
func BuildPlainHTTPStack(
	ctx context.Context,
	clientConn net.Conn,
	upstreamConn net.Conn,
	target string,
	cfg *BuildConfig,
	opts ...PlainHTTPStackOption,
) (*ConnectionStack, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: BuildPlainHTTPStack: nil config")
	}
	if clientConn == nil || upstreamConn == nil {
		return nil, fmt.Errorf("connector: BuildPlainHTTPStack: nil conn")
	}

	var o plainHTTPStackOptions
	for _, opt := range opts {
		opt(&o)
	}

	connID := ConnIDOrGenerate(ctx)

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// TLS intentionally nil: no handshake happened on the client side.
	}
	upstreamEnvCtx := WithUpstreamPeer(envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		// TLS intentionally nil: no handshake happened on the upstream side.
	}, upstreamConn)

	stack := NewConnectionStack(connID)

	clientOpts := []http1.Option{
		http1.WithScheme("http"),
		http1.WithEnvelopeContext(clientEnvCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithMaxRawCaptureSize(cfg.MaxRawCaptureSize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
		// USK-1162: bound the client request head (request_timeout_ms).
		http1.WithRequestHeaderTimeout(cfg.ClientRequestHeadDeadline),
		// USK-1185: keep-alive wait for the next request (client_idle_timeout_ms).
		http1.WithKeepAliveIdleTimeout(cfg.ClientIdleDeadline),
	}
	if o.forwardOriginForm {
		clientOpts = append(clientOpts, http1.WithForwardProxyOriginForm())
	}
	if o.forwardRouter != nil {
		clientOpts = append(clientOpts, http1.WithForwardTargetResolver(resolveForwardTarget, forwardTargetRefusal()))
		stack.setForwardRouter(o.forwardRouter)
	}
	clientLayer := http1.New(clientConn, connID+"/client", envelope.Send, clientOpts...)
	stack.PushClient(clientLayer)

	stack.PushUpstream(newUpstreamH1Layer(upstreamConn, connID+"/upstream", "http", upstreamEnvCtx, cfg))

	return stack, nil
}

// newUpstreamH1Layer constructs an upstream (Receive-direction) HTTP/1.x
// Layer over conn: label is its stream-ID label, scheme its scheme and
// envCtx its envelope context template. It is the single option set of
// every upstream http1 Layer the plain-HTTP stack and its successors use —
// BuildPlainHTTPStack, RedialUpstreamH1 (stale / write-EPIPE redial) and
// ForwardRouter.Retarget (USK-1410) — so a per-Layer option added for the
// upstream side is added once.
func newUpstreamH1Layer(conn net.Conn, label, scheme string, envCtx envelope.EnvelopeContext, cfg *BuildConfig) *http1.Layer {
	return http1.New(conn, label, envelope.Receive,
		http1.WithScheme(scheme),
		http1.WithEnvelopeContext(envCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithMaxRawCaptureSize(cfg.MaxRawCaptureSize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
		// USK-655: bypass body draining for SSE responses so the swap
		// orchestrator (session.runUpgradeSSE) can hand the still-open body
		// to sse.Wrap without blocking on a never-ending drain. Plain-HTTP
		// SSE through a forward proxy is a real use case (HTTP back-channel
		// to legacy services), so the same predicate applies here.
		http1.WithStreamingResponseDetect(http1.IsSSEResponse),
		// USK-1409: stream response bodies no rule / plugin needs whole.
		http1.WithResponseBodyMode(cfg.ResponseBodyMode),
	)
}
