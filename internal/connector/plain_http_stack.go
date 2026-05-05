package connector

import (
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

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
// No context.Context parameter: stack construction is purely synchronous
// (no I/O, no dial). Cancellation belongs to the caller's dial step and
// to the per-Layer session loop, not to this constructor.
func BuildPlainHTTPStack(
	clientConn net.Conn,
	upstreamConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: BuildPlainHTTPStack: nil config")
	}
	if clientConn == nil || upstreamConn == nil {
		return nil, fmt.Errorf("connector: BuildPlainHTTPStack: nil conn")
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

	clientLayer := http1.New(clientConn, connID+"/client", envelope.Send,
		http1.WithScheme("http"),
		http1.WithEnvelopeContext(clientEnvCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
	)
	stack.PushClient(clientLayer)

	upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
		http1.WithScheme("http"),
		http1.WithEnvelopeContext(upstreamEnvCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
		// USK-655: bypass body draining for SSE responses so the swap
		// orchestrator (session.runUpgradeSSE) can hand the still-open body
		// to sse.Wrap without blocking on a never-ending drain. Plain-HTTP
		// SSE through a forward proxy is a real use case (HTTP back-channel
		// to legacy services), so the same predicate applies here.
		http1.WithStreamingResponseDetect(http1.IsSSEResponse),
	)
	stack.PushUpstream(upstreamLayer)

	return stack, nil
}
