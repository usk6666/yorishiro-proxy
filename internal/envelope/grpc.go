package envelope

import "time"

// GRPCStartMessage carries the gRPC metadata (HEADERS frame) that opens
// one direction of a gRPC RPC. See RFC-001 section 3.2.3.
//
// One GRPCStartMessage envelope is emitted for the request side
// (Direction=Send, Sequence=0) and one for the response side
// (Direction=Receive, Sequence=0). Both share the RPC's Envelope.StreamID.
//
// USK-920: Authority / Scheme / Path are projected out of the HTTP/2
// pseudo-headers on the request side so downstream consumers (notably
// RecordStep → Flow.URL) can reconstruct the RPC's URL without re-parsing
// the wire HPACK block. The pseudo-header wire bytes remain in
// Envelope.Raw (untouched); these fields are a derived L7 overlay,
// matching the existing HTTPMessage.Authority / Scheme / Path pattern.
// Empty on the response side (response HEADERS only carry :status).
type GRPCStartMessage struct {
	// Service is the gRPC service name (derived from :path on the request
	// side and mirrored on the response side).
	Service string

	// Method is the gRPC method name.
	Method string

	// Authority is the :authority pseudo-header from the request-side
	// HEADERS frame. Empty on the response side. USK-920.
	Authority string

	// Scheme is the :scheme pseudo-header from the request-side HEADERS
	// frame ("http" for h2c, "https" for TLS+ALPN h2). Empty on the
	// response side. USK-920.
	Scheme string

	// Path is the :path pseudo-header from the request-side HEADERS
	// frame ("/Service/Method"), minus any query string (which lives on
	// RawQuery). Empty on the response side. USK-920. Service / Method
	// are also parsed out individually; Path is retained so a malformed
	// :path (which yields Service="" Method="") still leaves an
	// inspectable trace.
	//
	// USK-1053 made Path authoritative on Send under a narrow rule: the
	// derived Service/Method view wins whenever the observed :path was
	// parseable into it, and Path wins only when it was not (no inner
	// slash, leading "//" with a single remaining segment, trailing "/",
	// no leading "/"). That keeps the intercept / plugin service+method
	// override working on any parseable :path while stopping the gRPC
	// Layer from normalizing a malformed :path into "/Service/Method" or
	// "/" on the way to the upstream (MITM Principle #1). The narrower
	// scope is deliberate: on an unparseable observed :path a service /
	// method override no longer reaches the wire, because rebuilding
	// there would destroy the malformed path the wire actually carried —
	// the overlay is the only faithful representation, so it wins. An
	// empty Path falls through to the rebuild, so synthetic producers
	// (resend_grpc / fuzz_grpc) that never set it are unaffected. See
	// pathForStart in internal/layer/grpc/channel.go.
	//
	// Two residual losses remain, both inherited from the HTTP/2 Layer's
	// Path/RawQuery split and shared verbatim with HTTPMessage — they are
	// not specific to gRPC and are not fixable here:
	//   - ":path: \"\"" is re-emitted as "/" (appendRequestPseudoHeaders
	//     substitutes "/" for an empty path).
	//   - a bare trailing "?" is destroyed: splitPath yields
	//     RawQuery="", and the rejoin only re-adds "?" when RawQuery is
	//     non-empty.
	// The full wire bytes remain in Envelope.Raw in both cases.
	Path string

	// RawQuery is the query component of the request-side :path, without
	// the leading "?" — the same split the HTTP/2 Layer performs into
	// H2HeadersEvent.Path + .RawQuery, and the same representation
	// HTTPMessage uses. Empty on the response side, and empty when the
	// observed :path carried no query. USK-1053.
	RawQuery string

	// Metadata is the full gRPC metadata list. HTTP/2 pseudo-headers are
	// NOT included here — they belong to the transport layer and are
	// observable via Envelope.Context if needed. Order and casing are
	// preserved as observed on the wire.
	Metadata []KeyValue

	// Timeout is the parsed grpc-timeout value. Zero when unset.
	Timeout time.Duration

	// ContentType is the application/grpc[+proto|+json|...] content-type.
	ContentType string

	// Encoding is the parsed grpc-encoding value (identity, gzip, deflate,
	// ...).
	Encoding string

	// AcceptEncoding is the parsed grpc-accept-encoding list.
	AcceptEncoding []string

	// Anomalies records parser-detected deviations observed while
	// constructing this Start envelope from the underlying HTTP body.
	// Wire-format failures (malformed base64, malformed LPM framing,
	// malformed trailer text) populate this slice so an analyst sees the
	// bad bytes (preserved on Envelope.Raw) alongside a structured tag.
	// Stream-terminating problems (oversize LPM cap, gzip-bomb cap)
	// surface as *layer.StreamError instead and never reach this slice.
	Anomalies []Anomaly
}

// Protocol returns ProtocolGRPC.
func (m *GRPCStartMessage) Protocol() Protocol { return ProtocolGRPC }

// CloneMessage returns a deep copy of the GRPCStartMessage.
func (m *GRPCStartMessage) CloneMessage() Message {
	return &GRPCStartMessage{
		Service:        m.Service,
		Method:         m.Method,
		Authority:      m.Authority,
		Scheme:         m.Scheme,
		Path:           m.Path,
		RawQuery:       m.RawQuery,
		Metadata:       cloneKeyValues(m.Metadata),
		Timeout:        m.Timeout,
		ContentType:    m.ContentType,
		Encoding:       m.Encoding,
		AcceptEncoding: cloneStrings(m.AcceptEncoding),
		Anomalies:      cloneAnomalies(m.Anomalies),
	}
}

// GRPCDataMessage carries one length-prefixed gRPC message (LPM),
// reassembled from the underlying HTTP/2 DATA event stream. LPM boundaries
// are independent of DATA frame boundaries. See RFC-001 section 3.2.3.
//
// Envelope.Raw for a GRPCDataMessage envelope contains the exact wire
// bytes (5-byte LPM prefix + compressed payload, if compression is in
// use). Payload on this type is always the decompressed bytes for
// inspection convenience.
type GRPCDataMessage struct {
	// Service is denormalized from the associated GRPCStartMessage.
	// Read-only; changes must be made on GRPCStartMessage.
	Service string

	// Method is denormalized from the associated GRPCStartMessage.
	// Read-only; changes must be made on GRPCStartMessage.
	Method string

	// Compressed reflects the first byte of the 5-byte LPM prefix.
	Compressed bool

	// WireLength is the uint32 length field of the 5-byte LPM prefix
	// (the compressed-payload length in bytes).
	WireLength uint32

	// Payload is always the decompressed bytes, regardless of Compressed.
	// To inject malformed compressed bytes, write Envelope.Raw directly.
	Payload []byte

	// EndStream mirrors the wire-level END_STREAM flag carried by the H2
	// DATA frame that produced this LPM. Because gRPC clients do not emit
	// trailer headers, the request-side terminator is the END_STREAM bit on
	// the last DATA frame; without this field the proxy cannot round-trip
	// the request-side termination signal. See RFC-001 §3.2.3 / §9.2.
	EndStream bool
}

// Protocol returns ProtocolGRPC.
func (m *GRPCDataMessage) Protocol() Protocol { return ProtocolGRPC }

// CloneMessage returns a deep copy of the GRPCDataMessage.
func (m *GRPCDataMessage) CloneMessage() Message {
	return &GRPCDataMessage{
		Service:    m.Service,
		Method:     m.Method,
		Compressed: m.Compressed,
		WireLength: m.WireLength,
		Payload:    cloneBytes(m.Payload),
		EndStream:  m.EndStream,
	}
}

// GRPCEndMessage carries the trailer HEADERS frame (with END_STREAM) that
// terminates a gRPC RPC. Direction=Receive in the well-formed case;
// Direction=Send only when a request body unexpectedly carries an embedded
// trailer (recorded via AnomalyUnexpectedGRPCWebRequestTrailer). See
// RFC-001 §3.2.3.
type GRPCEndMessage struct {
	// Status is the parsed grpc-status code (codes.OK, codes.Canceled, ...
	// per the gRPC status code registry).
	Status uint32

	// Message is the parsed grpc-message value (percent-decoded).
	Message string

	// StatusDetails carries the raw protobuf bytes of the
	// grpc-status-details-bin trailer, if present. Decoding is schema-
	// dependent; left as bytes.
	StatusDetails []byte

	// Trailers holds the remaining trailer metadata after removing
	// grpc-status, grpc-message, and grpc-status-details-bin. Order and
	// casing are preserved as observed on the wire.
	Trailers []KeyValue

	// Anomalies records parser-detected deviations associated with this
	// End event. Two cases are produced today by the gRPC-Web Layer:
	// (1) a synthetic End synthesized to mark a Receive-direction body
	// that parsed but lacked a terminating trailer LPM, and (2) a real
	// End attached to a Send-direction request body whose presence of a
	// trailer LPM is itself anomalous. Variant-recording comparisons
	// must NOT inspect this field — parser-derived state is wire-derived,
	// not user-mutated.
	Anomalies []Anomaly
}

// Protocol returns ProtocolGRPC.
func (m *GRPCEndMessage) Protocol() Protocol { return ProtocolGRPC }

// CloneMessage returns a deep copy of the GRPCEndMessage.
func (m *GRPCEndMessage) CloneMessage() Message {
	return &GRPCEndMessage{
		Status:        m.Status,
		Message:       m.Message,
		StatusDetails: cloneBytes(m.StatusDetails),
		Trailers:      cloneKeyValues(m.Trailers),
		Anomalies:     cloneAnomalies(m.Anomalies),
	}
}

// cloneStrings returns a deep copy of a []string, preserving a nil input.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}
