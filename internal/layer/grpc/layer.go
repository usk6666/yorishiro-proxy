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

	// lpmFrameRecordCallback is the optional per-LPM wire-record callback
	// installed by the session orchestrator (USK-896). When non-nil, the
	// channel invokes it synchronously from absorbData with a pre-built
	// envelope carrying:
	//
	//   - Protocol  = envelope.ProtocolGRPC
	//   - StreamID  = the inner channel's StreamID
	//   - Direction = the LPM's Direction (Send or Receive)
	//   - Raw       = LPM wire bytes (5-byte prefix + payload, BEFORE
	//                 decompression)
	//   - Message   = nil (LPM wire envelopes have no L7 structured view
	//                 by design — the GRPCDataMessage envelope queued
	//                 immediately AFTER provides the decompressed view)
	//   - Context   = the inner event's Context with WireLevel left at
	//                 the zero value (the callback is expected to stamp
	//                 flow.WireLevelGRPCLPMFrame before forwarding to
	//                 the record-only Pipeline)
	//
	// Order: callback fires BEFORE the GRPCDataMessage envelope is queued
	// for emission (per CLAUDE.md MITM Principle 3 — wire-record first,
	// semantic-record second).
	//
	// nil = no-op (the channel skips the wire-record step entirely).
	lpmFrameRecordCallback func(*envelope.Envelope)

	// h2DataFrameRecordCallback is the optional per-H2-DATA-frame
	// wire-record callback installed by the session orchestrator (USK-899).
	// When non-nil, the channel invokes it synchronously from absorbData
	// BEFORE LPM reassembly with a pre-built envelope carrying:
	//
	//   - Protocol  = envelope.ProtocolHTTP (per the H2DataEvent
	//                 provenance — the wire bytes are an HTTP/2 DATA frame
	//                 payload, NOT a gRPC LPM)
	//   - StreamID  = the inner channel's StreamID
	//   - Direction = the H2DataEvent's Direction (Send or Receive)
	//   - Raw       = the DATA frame payload bytes (defensive copy of
	//                 evt.Payload; no 9-byte frame header — matches the
	//                 USK-889 detach-path / USK-897 aggregator-path
	//                 envelope shape)
	//   - Message   = nil (DATA frame wire envelopes have no L7
	//                 structured view; the LPM wire envelope and the
	//                 GRPCDataMessage envelope queued AFTER reassembly
	//                 provide the gRPC-side views)
	//   - Context   = the inner event's Context with WireLevel left at
	//                 the zero value (the callback is expected to stamp
	//                 flow.WireLevelH2Frame before forwarding to the
	//                 record-only Pipeline)
	//
	// Order: callback fires BEFORE acquiring c.mu, so BEFORE the LPM
	// reassembler consumes any of the payload bytes, and BEFORE the
	// lpmFrameRecordCallback (which in turn fires before the
	// GRPCDataMessage envelope is queued). The progression is h2-frame
	// → grpc-lpm-frame → semantic, matching CLAUDE.md MITM Principle 3
	// (wire-record first, semantic-record second) at every framing
	// layer.
	//
	// Unconditional fire: the callback fires for EVERY absorbed
	// H2DataEvent regardless of whether downstream LPM reassembly /
	// gzip-decode / mid-LPM-EOS detection succeeds. The smuggling /
	// attack-signature scenarios the wire_level=h2-frame view exists
	// to surface (LPM length-prefix smuggling, decompression bombs,
	// mid-LPM truncation) are precisely the error paths — recording
	// those wire frames is the whole point. Mirrors USK-897's
	// aggregator-path behavior (the aggregator fires its h2-frame
	// callback BEFORE the MaxBodySize gate).
	//
	// Closes the wire_level=h2-frame producer gap left by USK-897: the
	// native-gRPC path bypasses httpaggregator.Wrap, so the aggregator's
	// h2-frame callback never fires here. With this callback installed,
	// native gRPC streams produce three wire_level rows per direction
	// (semantic + grpc-lpm-frame + h2-frame) matching gRPC-Web-over-h2
	// and aggregator-path coverage.
	//
	// nil = no-op (the channel skips the h2-frame wire-record step
	// entirely).
	h2DataFrameRecordCallback func(*envelope.Envelope)
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

// WithLPMFrameRecordCallback installs a synchronous per-LPM wire-record
// callback on the Channel (USK-896 v2 wave #2 — defense-in-depth gRPC
// LPM smuggling visibility). The callback fires once per fully reassembled
// LPM, from grpcChannel.absorbData, BEFORE the corresponding semantic
// GRPCDataMessage envelope is queued for emission. See the documentation
// on options.lpmFrameRecordCallback for the envelope contract.
//
// Mirrors the per-Layer Option shape used by
// http2.WithFrameRecordCallback (USK-889) and
// http1.WithChunkRecordCallback (USK-895). A common WireLevelTap
// interface is intentionally deferred to a follow-up Issue (USK-896 hits
// the Rule of Three; the refactor is scoped separately).
//
// The callback contract:
//
//   - Non-blocking: runs synchronously on the grpc channel's Next
//     goroutine (the LPM reassembly path). A slow callback delays semantic
//     envelope emission.
//   - Single-goroutine fire: the callback is invoked from absorbData only,
//     AFTER c.mu has been released (the LPM wire envelopes are collected
//     while the mutex is held, then dispatched outside the critical
//     section so a record-only Pipeline that writes to SQLite does not
//     block the channel mutex). The callback MUST NOT call back into the
//     grpc channel — taking c.mu from the callback would race with the
//     channel's own Next goroutine rather than deadlocking, but either
//     way the channel is treated as an opaque resource by callback
//     consumers.
//   - Lifetime: the LPM Raw bytes are a fresh slice owned by the channel.
//     The callback may retain the slice across return — the channel does
//     not mutate it after invocation.
//   - nil = no-op (no wire-record envelope is produced).
//
// The Option is layered onto the standard grpcOpts chain assembled by
// connector.GRPCOptionsFromBuildConfig. See
// internal/session/grpc_lpm_record.go for the production builder that
// constructs the callback closure + record-only Pipeline.
func WithLPMFrameRecordCallback(cb func(*envelope.Envelope)) Option {
	return func(o *options) { o.lpmFrameRecordCallback = cb }
}

// WithH2DataFrameRecordCallback installs a synchronous per-H2-DATA-frame
// wire-record callback on the Channel (USK-899 v2 wave #5 — native-gRPC
// h2-frame coverage gap close).
//
// Native gRPC over h2 is wrapped by grpc.Wrap directly and bypasses
// httpaggregator.Wrap, so USK-897's aggregator-path h2-frame callback
// never fires on this path. With this Option installed, the channel
// invokes cb once per absorbed H2DataEvent BEFORE LPM reassembly and
// BEFORE the per-LPM callback installed by WithLPMFrameRecordCallback.
// The result is symmetric wire_level=h2-frame coverage across all three
// HTTP/2 consumers — http2 detach (USK-889), httpaggregator (USK-897),
// and native gRPC (this Option).
//
// See the documentation on options.h2DataFrameRecordCallback for the
// envelope contract.
//
// Mirrors the per-Layer Option shape used by
// http2.WithFrameRecordCallback (USK-889),
// http1.WithChunkRecordCallback (USK-895),
// grpc.WithLPMFrameRecordCallback (USK-896), and
// httpaggregator.WithH2FrameRecordCallback (USK-897).
// A common WireLevelTap interface is intentionally deferred to a
// follow-up Issue (after USK-899 this is the fifth sibling — the
// Rule-of-Three trigger fired at USK-896; refactor is scoped
// separately for PR size control).
//
// The callback contract:
//
//   - Non-blocking: runs synchronously on the grpc channel's Next
//     goroutine (the LPM-absorb path). A slow callback delays LPM
//     reassembly and downstream semantic envelope emission.
//   - Single-goroutine fire: the callback is invoked from absorbData
//     only, BEFORE c.mu is acquired (the h2-frame wire envelope reads
//     only the per-event ev/evt args, not any locked channel state).
//     The callback MUST NOT call back into the grpc channel.
//   - Unconditional fire: invoked for every absorbed H2DataEvent —
//     including the LPM-cap-trip / gzip-decode-fail / mid-LPM-EOS
//     error paths that return *layer.StreamError without queuing any
//     semantic envelope. The wire DATA frame was observed; recording
//     it is the point of wire_level=h2-frame.
//   - Defensive copy: env.Raw is a fresh slice independent of
//     evt.Payload. The HTTP/2 frame engine may reuse the underlying
//     buffer once the event is consumed; the copy decouples the
//     callback's lifetime from that ownership boundary.
//   - Lifetime: the callback may retain env across return — the channel
//     does not mutate it after invocation.
//   - nil = no-op (no h2-frame wire-record envelope is produced).
//
// The Option is layered onto the standard grpcOpts chain assembled by
// connector.GRPCOptionsFromBuildConfig. See
// internal/session/grpc_h2_data_frame_record.go for the production
// builder that constructs the callback closure + record-only Pipeline.
func WithH2DataFrameRecordCallback(cb func(*envelope.Envelope)) Option {
	return func(o *options) { o.h2DataFrameRecordCallback = cb }
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
		inner:                     stream,
		role:                      role,
		streamID:                  stream.StreamID(),
		recvDone:                  make(chan struct{}),
		maxMessageSize:            o.maxMessageSize,
		lifecycleEngine:           o.lifecycleEngine,
		lpmFrameRecordCallback:    o.lpmFrameRecordCallback,
		h2DataFrameRecordCallback: o.h2DataFrameRecordCallback,
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
