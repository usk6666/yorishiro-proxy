package http2

// The original streamAssembler + HTTPMessage aggregation tests have been
// removed as part of USK-637 (HTTP/2 Layer event-granular split).
// Equivalent semantics are now tested in:
//   - internal/layer/http2/assembler_events_test.go — event extraction
//     (H2HeadersEvent / H2DataEvent / H2TrailersEvent) from HEADERS and
//     DATA frames, anomaly detection, CONTINUATION-flood guard.
//   - internal/layer/httpaggregator/aggregator_test.go — the phase machine
//     that rebuilds HTTPMessage from events (body buffer lifecycle,
//     MaxBodySize enforcement, trailer handling).
