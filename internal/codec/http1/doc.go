// Package http1 implements the HTTP/1.x Codec for the Codec + Pipeline + Session
// architecture.
//
// The Codec operates in two roles:
//
//   - Client role: Next() parses requests from the client, Send() serializes
//     responses back to the client.
//   - Upstream role: Send() serializes requests to the upstream server, Next()
//     parses responses from the upstream server.
//
// Wire fidelity is maintained through raw-first patching: when Pipeline Steps
// modify Exchange.Headers or Exchange.Body, Send() applies minimal diffs to
// the protocol-native RawHeaders, preserving original whitespace (OWS) for
// unmodified headers. When nothing is changed, the original RawBytes are
// written as-is (zero-copy optimization).
//
// Keep-alive is handled internally: each request-response pair gets a unique
// StreamID. Connection: close or HTTP/1.0 semantics cause Next() to return
// io.EOF after the current exchange.
package http1
