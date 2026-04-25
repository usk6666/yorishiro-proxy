// Package sse implements the SSE (Server-Sent Events, RFC 8895) Layer for
// RFC-001. It wraps the response side of an HTTP/1.x exchange whose body
// is a `text/event-stream` and re-shapes the byte stream into one
// envelope.SSEMessage per parsed event.
//
// Boundary:
//
//   - The package consumes a pre-read first response Envelope (Direction
//     Receive, Protocol ProtocolHTTP, status 200, Content-Type
//     text/event-stream) and an explicit `body io.Reader` that supplies
//     the post-headers byte stream from the upstream connection.
//   - Detection of the SSE Content-Type and the swap into this Layer is
//     owned by USK-643 (Session Upgrade swap mechanism); this package
//     contains no detection or swap logic and is purely a Channel adapter.
//
// Behavior:
//
//   - The first call to Next on the wrapped Channel returns a clone of
//     the supplied response Envelope with Protocol overridden to
//     ProtocolSSE (Direction Receive, Sequence preserved). Subsequent
//     Next calls drive an SSEParser over the body reader and emit one
//     Envelope per parsed event with Message=*envelope.SSEMessage and
//     Envelope.Raw containing the wire bytes of the event (including the
//     trailing blank line) — wire-fidelity per RFC-001 §3.3.
//   - Send is a programmer error; it returns the sentinel
//     ErrSendUnsupported (matchable with errors.Is). SSE is half-duplex
//     server→client per N7 D23.
//   - Close is idempotent and cascades: the body reader is closed if it
//     implements io.Closer, then inner.Close is called (per N6.7
//     cascade discipline).
//
// References:
//
//   - RFC 8895 — Server-Sent Events
//   - RFC-001 §3.2.5 (SSEMessage), §3.3.2 (Layer/Channel)
//   - N7 design decisions U3 (Receive-only wrap), D23 (Send forbidden)
package sse
