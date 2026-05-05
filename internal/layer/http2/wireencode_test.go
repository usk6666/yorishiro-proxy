package http2

// The original EncodeWireBytes tests have been removed as part of USK-637
// (HTTP/2 Layer event-granular split). Equivalent tests now live in
// internal/layer/httpaggregator/wireencode_test.go, exercising the same
// encoding algorithm now owned by the aggregator package.
