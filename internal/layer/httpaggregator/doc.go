// Package httpaggregator wraps an event-granular HTTP/2 stream Channel into
// a Channel that yields one aggregated envelope.HTTPMessage per request /
// response. Used for plain HTTP/2 traffic that the user wants to treat as
// request-response pairs (intercept/transform on the full message) rather
// than as a raw event stream.
//
// The wrapper is a strict upper-layer boundary: it consumes
// *H2HeadersEvent / *H2DataEvent / *H2TrailersEvent envelopes from the
// underlying Channel and produces a single *envelope.HTTPMessage envelope
// per completed message. The Send direction works in reverse: a single
// HTTPMessage envelope is decomposed into HEADERS + DATA* + trailer HEADERS
// events and sent sequentially on the underlying Channel.
//
// Body buffering: small bodies materialize as HTTPMessage.Body (memory);
// larger bodies spill to a bodybuf.BodyBuffer (disk-backed) once cumulative
// size crosses BodySpillThreshold. MaxBodySize enforcement happens here
// (not in the HTTP/2 Layer) — exceeding the cap triggers a RST_STREAM on
// the underlying channel via MarkTerminatedWithRST.
//
// For gRPC streams the caller must use GRPCLayer.Wrap instead;
// httpaggregator cannot represent streaming. Decision between the two
// happens in the connector's dispatchH2Stream helper by peeking the first
// H2HeadersEvent for content-type.
//
// See RFC-001 §3.3.2, §4.4, §9.1 revised for the architectural motivation.
package httpaggregator
