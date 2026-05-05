package grpc

import (
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// options holds the resolved per-Channel configuration applied by Wrap.
type options struct {
	// maxMessageSize caps the declared LPM length on Receive (and the
	// gunzip-decoded length when grpc-encoding=gzip). Zero is replaced
	// with config.MaxGRPCMessageSize at Wrap time so the on-Channel
	// value is always positive.
	maxMessageSize uint32

	// lifecycleEngine is the optional pluginv2 Engine consulted on End
	// emission to fire (grpc, on_end) hooks per RFC §9.3 PhaseSupportNone.
	// nil = no-op. The hook fires exactly once per Channel via sync.Once,
	// at the moment the End envelope is queued for emission (synchronous
	// with absorb), so the hook runs before the inner HTTP/2 channel
	// terminates and clears stream_state.
	lifecycleEngine *pluginv2.Engine
}

// Option tunes a Channel produced by Wrap. The Option type intentionally
// mirrors the shape used by sibling Layers (internal/layer/ws,
// internal/layer/http2): a function over an internal options struct.
type Option func(*options)

// WithMaxMessageSize caps the per-LPM payload size enforced by the
// reassembler and the gzip decoder. n=0 leaves the default
// (config.MaxGRPCMessageSize, 254 MiB) in place. The cap exists to defend
// against memory exhaustion (CWE-400) and decompression bombs (CWE-409);
// operators can lower it via ProxyConfig.GRPC.MaxMessageSize.
func WithMaxMessageSize(n uint32) Option {
	return func(o *options) {
		if n > 0 {
			o.maxMessageSize = n
		}
	}
}

// WithLifecycleEngine injects a pluginv2 Engine the wrapper consults on
// End emission to fire (grpc, on_end) hooks per RFC §9.3 PhaseSupportNone.
// The hook fires once per Channel — at the queue point of the first
// emitted GRPCEndMessage, before the inner HTTP/2 channel terminates and
// stream_state is released — so plugin code observing on_end still sees
// live stream_state from earlier on_data hooks. nil = no-op.
func WithLifecycleEngine(e *pluginv2.Engine) Option {
	return func(o *options) { o.lifecycleEngine = e }
}

// Role identifies whether the wrapped Channel is server-side (the local
// endpoint behaves as the gRPC server) or client-side (the local endpoint
// behaves as the gRPC client). Mirrors the convention used by
// internal/layer/http2 and internal/layer/httpaggregator: in RoleServer,
// request HEADERS arrive on the inner Channel with Direction=Send, and the
// response HEADERS / DATA / TRAILERS travel back with Direction=Receive.
//
// The Layer does not need Role for translation — gRPC events keep the
// inner envelope's Direction unchanged — but the Role is recorded on the
// wrapper for symmetry with sibling Layers and for future extensions
// (e.g., per-direction metadata caches).
type Role uint8

const (
	// RoleServer: the local endpoint is the gRPC server. Request envelopes
	// arrive with Direction=Send; response envelopes are sent back with
	// Direction=Receive.
	RoleServer Role = iota
	// RoleClient: the local endpoint is the gRPC client. Response envelopes
	// arrive with Direction=Receive; request envelopes are sent with
	// Direction=Send.
	RoleClient
)

// Wrap consumes a single event-granular HTTP/2 stream Channel and returns
// a Channel that yields per-RPC-event gRPC envelopes (GRPCStartMessage /
// GRPCDataMessage / GRPCEndMessage).
//
// firstHeaders is the pre-peeked H2HeadersEvent envelope obtained by the
// connector when detecting the application/grpc content-type. Per RFC-001
// §3.3.2 / Friction 4-A, the wrapper queues it as if it had been the next
// envelope read from inner.Next() — i.e., it becomes the source of the
// first emitted GRPCStartMessage envelope.
//
// As a special case (D5), if firstHeaders is nil or has empty Raw bytes
// the wrapper treats it as a synthetic startup signal and discards it;
// the first Next call then reads a real envelope from inner. This shape
// is used by the upstream-side dispatcher in N7 U2 where the upstream
// connection is established before any wire bytes are exchanged.
//
// role records the direction convention of the wrapped channel; see Role.
//
// Close on the returned Channel cascades to inner.Close (per N6.7
// cascade discipline); idempotent via sync.Once.
//
// Optional Options tune per-Channel behavior such as the wire-LPM cap
// (WithMaxMessageSize). Pass none to use defaults.
func Wrap(stream layer.Channel, firstHeaders *envelope.Envelope, role Role, opts ...Option) layer.Channel {
	o := options{
		maxMessageSize: config.MaxGRPCMessageSize,
	}
	for _, opt := range opts {
		opt(&o)
	}

	gc := &grpcChannel{
		inner:           stream,
		role:            role,
		streamID:        stream.StreamID(),
		recvDone:        make(chan struct{}),
		maxMessageSize:  o.maxMessageSize,
		lifecycleEngine: o.lifecycleEngine,
	}
	// Apply D5: only replay firstHeaders when it carries real wire bytes.
	if firstHeaders != nil && len(firstHeaders.Raw) > 0 {
		gc.peeked = firstHeaders
	}
	// Watcher goroutine: propagate inner termination to recvDone so callers
	// parking on Closed() observe late RST_STREAM-style events even when no
	// Next is in flight. Mirrors the contract that internal/session's
	// clientToUpstreamCascade depends on. The goroutine exits naturally
	// when either inner terminates (then it calls terminate, which closes
	// recvDone) or our own Close fires terminate first (the goroutine then
	// observes inner.Closed soon after Close cascades inner.Close, and
	// terminate's sync.Once makes the second call a no-op).
	go gc.watchInnerClose()
	return gc
}
