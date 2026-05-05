package http2

// EncodeWireBytes has moved to internal/layer/httpaggregator as part of
// USK-637 (HTTP/2 Layer event-granular split). The aggregator is now the
// owner of post-mutation wire re-encoding for HTTP/2, because the Layer
// itself no longer sees full HTTPMessage envelopes — only event-granular
// H2HeadersEvent / H2DataEvent / H2TrailersEvent messages. The new
// encoder signature accepts an aggregated envelope.HTTPMessage envelope
// and emits HTTP/2 wire bytes identically to the old implementation.
//
// Callers that previously wired pipeline.WithWireEncoder(ProtocolHTTP,
// intHTTP2.EncodeWireBytes) should now use
// httpaggregator.EncodeWireBytes.
