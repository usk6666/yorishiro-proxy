package grpcweb

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
	// emission to fire (grpc-web, on_end) hooks per RFC §9.3
	// PhaseSupportNone. The hook fires once per Channel via sync.Once
	// at the queue point of the End envelope. nil = no-op.
	lifecycleEngine *pluginv2.Engine

	// encodedFormRecordCallback is the optional per-body wire-record
	// callback installed by the session orchestrator (USK-898). When non-
	// nil, the channel invokes it synchronously from
	// refillFromHTTPMessage with a pre-built envelope carrying:
	//
	//   - Protocol  = envelope.ProtocolGRPCWeb
	//   - StreamID  = the inbound HTTPMessage envelope's StreamID
	//   - Direction = the HTTPMessage's Direction (Send or Receive)
	//   - Raw       = the on-wire base64-encoded body bytes (BEFORE the
	//                 layer's in-place base64 decode + LPM frame parse)
	//   - Message   = nil (base64 wire envelopes have no L7 structured
	//                 view by design — the GRPCStartMessage /
	//                 GRPCDataMessage / GRPCEndMessage envelopes queued
	//                 immediately AFTER provide the decoded view)
	//   - Context   = the inner envelope's Context with WireLevel left at
	//                 the zero value (the callback is expected to stamp
	//                 flow.WireLevelGRPCWebBase64 before forwarding to
	//                 the record-only Pipeline)
	//
	// Fired only on the text branch (IsBase64Encoded returns true for
	// the inbound content-type). Binary variants
	// (application/grpc-web[+proto]) do NOT fire the callback because
	// they never pass through the base64 decode path. The negative
	// behaviour is enforced by code structure — the callback site lives
	// inside the isBase64 branch in refillFromHTTPMessage.
	//
	// Order: callback fires BEFORE DecodeBodyWithMaxMessageSize is
	// invoked (per CLAUDE.md MITM Principle 3 — wire-record first,
	// semantic-record second). The callback is fired even when the
	// subsequent decode fails so the wire snapshot is preserved
	// alongside the parser.Anomaly that the failure surfaces.
	//
	// nil = no-op (the channel skips the wire-record step entirely).
	encodedFormRecordCallback func(*envelope.Envelope)
}

// Option tunes a Channel produced by Wrap. The Option type intentionally
// mirrors the shape used by sibling Layers (internal/layer/grpc,
// internal/layer/ws): a function over an internal options struct.
type Option func(*options)

// WithMaxMessageSize caps the per-LPM payload size enforced by the
// gRPC-Web frame parser and the gzip decoder. n=0 leaves the default
// (config.MaxGRPCMessageSize, 254 MiB) in place. Operators tune this
// via ProxyConfig.GRPC.MaxMessageSize (gRPC-Web shares the limit
// substruct with the gRPC Layer since they enforce identical wire-LPM
// caps).
func WithMaxMessageSize(n uint32) Option {
	return func(o *options) {
		if n > 0 {
			o.maxMessageSize = n
		}
	}
}

// WithLifecycleEngine injects a pluginv2 Engine the wrapper consults on
// End emission to fire (grpc-web, on_end) hooks per RFC §9.3
// PhaseSupportNone. nil = no-op. Hook firing is sync.Once-gated to one
// invocation per Channel even when both the natural-trailer and the
// missing-trailer-anomaly paths produce End envelopes.
func WithLifecycleEngine(e *pluginv2.Engine) Option {
	return func(o *options) { o.lifecycleEngine = e }
}

// WithEncodedFormRecordCallback installs a synchronous per-body wire-record
// callback on the Channel (USK-898 v2 wave #4 — defense-in-depth gRPC-Web
// base64 wire visibility). The callback fires once per inbound HTTPMessage
// that arrives with a text content-type (application/grpc-web-text[+proto]),
// from refillFromHTTPMessage, BEFORE the body is base64-decoded and the
// LPM frame parser runs. See the documentation on
// options.encodedFormRecordCallback for the envelope contract.
//
// Mirrors the per-Layer Option shape used by
// http2.WithFrameRecordCallback (USK-889), http1.WithChunkRecordCallback
// (USK-895), grpc.WithLPMFrameRecordCallback (USK-896), and
// httpaggregator.WithH2FrameRecordCallback (USK-897). A common
// WireLevelTap interface is intentionally deferred to a follow-up Issue
// (the existing four implementations satisfy Rule of Three; the refactor
// is scoped separately).
//
// The callback contract:
//
//   - Non-blocking: runs synchronously on the grpcweb channel's Next
//     goroutine (refillFromHTTPMessage). A slow callback delays Start /
//     Data / End envelope emission to the consumer.
//   - Single-goroutine fire: the callback is invoked from
//     refillFromHTTPMessage exactly once per inbound text-variant
//     HTTPMessage. The grpcweb channel is single-consumer (Next is the
//     only path that pulls from inner) so the callback observes a
//     deterministic invocation order.
//   - Lifetime: the body bytes passed to the callback are a fresh
//     defensive copy owned by the callback after return — the channel
//     does not mutate the slice afterward.
//   - Negative path: text-variant content-types fire the callback;
//     binary variants do NOT (the callback site lives inside the
//     isBase64 branch). The negative behaviour is enforced by code
//     structure, not by absence of tests, so a future refactor that
//     accidentally moves the call out of the isBase64 branch surfaces
//     as a test failure rather than as silent over-recording.
//   - Anomaly: the callback fires BEFORE DecodeBody attempts the
//     base64-decode. When the decode fails (ErrMalformedBase64 et al.),
//     the wire snapshot is already captured — the parser.Anomaly
//     produced by classifyParseError records the failure separately on
//     the semantic Start envelope.
//   - nil = no-op (no wire-record envelope is produced).
//
// The Option is layered onto the standard grpcwebOpts chain assembled by
// connector.GRPCWebOptionsFromBuildConfig. See
// internal/session/grpcweb_base64_record.go for the production builder
// that constructs the callback closure + record-only Pipeline.
func WithEncodedFormRecordCallback(cb func(*envelope.Envelope)) Option {
	return func(o *options) { o.encodedFormRecordCallback = cb }
}

// Role identifies whether the wrapped Channel is server-side (local endpoint
// behaves as the gRPC-Web server, sees inbound requests as Send) or
// client-side (local endpoint behaves as the gRPC-Web client, sees inbound
// responses as Receive).
//
// The constant is local to this package (not cross-imported from
// httpaggregator) because gRPC-Web must remain Channel-type-agnostic per
// Friction 4-C — the wrapper does not depend on the inner Channel's
// concrete Role enum.
type Role uint8

const (
	// RoleServer: local endpoint is the gRPC-Web server.
	// Inbound (Next) HTTPMessage envelopes have Direction=Send (request from
	// client) and Direction=Receive (response from upstream we are mediating
	// or that we will reply to via Send).
	// On Send-side (request) Next path, this Layer emits GRPCStartMessage +
	// 0..N GRPCDataMessage envelopes (no embedded trailer; gRPC-Web requests
	// have none). On Receive-side (response) Send path (i.e., Send called by
	// the caller to reply), this Layer assembles HTTPMessage from the
	// caller's GRPCStart + 0..N GRPCData + GRPCEnd events into an outbound
	// HTTPMessage with an embedded trailer LPM frame.
	RoleServer Role = iota

	// RoleClient: local endpoint is the gRPC-Web client.
	// On Send-side (request) Send path, the caller pushes
	// GRPCStartMessage + 0..N GRPCDataMessage + GRPCEndMessage(Send sentinel)
	// and this Layer assembles a single outbound HTTPMessage (no embedded
	// trailer) and forwards via inner.Send.
	// On Receive-side (response) Next path, this Layer emits GRPCStart + 0..N
	// GRPCData + GRPCEnd envelopes from the inbound HTTPMessage (response
	// body LPMs + embedded trailer LPM).
	RoleClient
)

// String returns a human-readable label.
func (r Role) String() string {
	switch r {
	case RoleServer:
		return "server"
	case RoleClient:
		return "client"
	default:
		return "unknown"
	}
}

// Wrap returns a [layer.Channel] that interprets the inner Channel's
// HTTPMessage envelopes as gRPC-Web traffic. The returned Channel emits
// GRPCStartMessage / GRPCDataMessage / GRPCEndMessage envelopes on Next and
// accepts the same envelope types on Send (the caller is responsible for
// terminating each direction with a GRPCEndMessage — see the package doc for
// the D6 Send-side flush convention).
//
// Wrap is Channel-type-agnostic (Friction 4-C): inner may be an HTTP/1.x
// Channel or an httpaggregator-wrapped HTTP/2 Channel. Wrap does not
// type-assert on the concrete Channel implementation.
//
// Close on the returned Channel cascades to inner.Close (per RFC-001 cascade
// discipline).
//
// Optional Options tune per-Channel behavior such as the wire-LPM cap
// (WithMaxMessageSize).
func Wrap(inner layer.Channel, role Role, opts ...Option) layer.Channel {
	o := options{
		maxMessageSize: config.MaxGRPCMessageSize,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return newChannel(inner, role, o)
}
