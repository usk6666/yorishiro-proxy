package http2

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// H2HeadersEvent represents a HEADERS frame block carrying initial request or
// response headers (NOT trailers). Emitted once per stream when the initial
// HEADERS + any CONTINUATION frames are fully decoded.
//
// Trailers are a separate event type — see H2TrailersEvent.
//
// Envelope.Raw contains the concatenated HPACK block fragment bytes (without
// the 9-byte HTTP/2 frame header or the frame-level padding byte), which is
// what a pure HPACK decoder would consume.
type H2HeadersEvent struct {
	// Pseudo-headers parsed out of the HPACK block for ergonomic access.
	// Wire copies also remain in Headers (wire fidelity).
	//
	// Request side (Direction=Send): Method / Scheme / Authority / Path.
	// Response side (Direction=Receive): Status / StatusReason.
	Method       string
	Scheme       string
	Authority    string
	Path         string
	RawQuery     string
	Status       int
	StatusReason string

	// Headers is the regular (non-pseudo) header list in wire order. HPACK
	// yields lowercase names per RFC 9113 §8.2.1; case is preserved as-is
	// (including anomalous uppercase, with an H2UppercaseHeaderName anomaly
	// attached).
	Headers []envelope.KeyValue

	// EndStream indicates the HEADERS frame carried END_STREAM (bodyless
	// request/response with no trailers).
	EndStream bool

	// Anomalies collected during header decode (pseudo-header-after-regular,
	// invalid-pseudo, uppercase-name, connection-specific-header, etc.).
	Anomalies []envelope.Anomaly
}

// Protocol returns envelope.ProtocolHTTP. The HTTP/2 Layer uses ProtocolHTTP
// for its event envelopes; the aggregator wrapper re-uses the same protocol
// identifier when yielding aggregated HTTPMessage envelopes. Pipeline Steps
// never see event envelopes directly — they are consumed by the aggregator
// Layer (or GRPCLayer for gRPC streams).
func (*H2HeadersEvent) Protocol() envelope.Protocol { return envelope.ProtocolHTTP }

// CloneMessage returns a deep copy suitable for variant snapshotting. Tests
// and the aggregator may call it during transitional snapshots; the Layer
// itself never mutates emitted events.
func (e *H2HeadersEvent) CloneMessage() envelope.Message {
	clone := &H2HeadersEvent{
		Method:       e.Method,
		Scheme:       e.Scheme,
		Authority:    e.Authority,
		Path:         e.Path,
		RawQuery:     e.RawQuery,
		Status:       e.Status,
		StatusReason: e.StatusReason,
		EndStream:    e.EndStream,
		Headers:      cloneKVs(e.Headers),
		Anomalies:    cloneEvAnomalies(e.Anomalies),
	}
	return clone
}

// H2DataEvent represents exactly one DATA frame's payload. The Layer emits
// one event per DATA frame (deterministic 1:1 mapping); the aggregator (or
// GRPCLayer) is responsible for accumulating these into a BodyBuffer.
//
// Envelope.Raw contains the DATA frame payload (post-padding, not including
// the 9-byte frame header).
type H2DataEvent struct {
	// Payload is a defensive copy of the DATA frame payload. Memory ownership
	// is the aggregator's.
	Payload []byte

	// EndStream indicates the DATA frame carried END_STREAM.
	EndStream bool
}

// Protocol returns envelope.ProtocolHTTP.
func (*H2DataEvent) Protocol() envelope.Protocol { return envelope.ProtocolHTTP }

// CloneMessage returns a deep copy.
func (e *H2DataEvent) CloneMessage() envelope.Message {
	return &H2DataEvent{
		Payload:   cloneEvBytes(e.Payload),
		EndStream: e.EndStream,
	}
}

// H2TrailersEvent represents a trailer HEADERS frame (HEADERS-after-DATA with
// END_STREAM). Always Direction=Receive per the HTTP/2 request/response
// framing model; trailer frames always carry END_STREAM per RFC 9113 §8.1.
//
// Envelope.Raw contains the concatenated HPACK block fragment bytes.
type H2TrailersEvent struct {
	// Trailers is the trailer header list in wire order. Pseudo-headers in
	// trailers are invalid (RFC 9113 §8.1); they are dropped here and an
	// H2InvalidPseudoHeader anomaly is attached.
	Trailers []envelope.KeyValue

	// Anomalies collected during trailer decode.
	Anomalies []envelope.Anomaly
}

// Protocol returns envelope.ProtocolHTTP.
func (*H2TrailersEvent) Protocol() envelope.Protocol { return envelope.ProtocolHTTP }

// CloneMessage returns a deep copy.
func (e *H2TrailersEvent) CloneMessage() envelope.Message {
	return &H2TrailersEvent{
		Trailers:  cloneKVs(e.Trailers),
		Anomalies: cloneEvAnomalies(e.Anomalies),
	}
}

// cloneKVs returns a deep copy of a KeyValue slice.
func cloneKVs(in []envelope.KeyValue) []envelope.KeyValue {
	if in == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(in))
	copy(out, in)
	return out
}

// cloneEvAnomalies returns a deep copy of an Anomaly slice.
func cloneEvAnomalies(in []envelope.Anomaly) []envelope.Anomaly {
	if in == nil {
		return nil
	}
	out := make([]envelope.Anomaly, len(in))
	copy(out, in)
	return out
}

// cloneEvBytes returns a copy of b, or nil if b is nil.
func cloneEvBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
