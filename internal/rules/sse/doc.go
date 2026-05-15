// Package sse provides Server-Sent Events (RFC 8895) rule engines for
// per-event intercept and transform. The engines operate on
// envelope.SSEMessage events that the SSE Layer projects from the
// upstream byte stream.
//
// # Engines
//
// InterceptEngine matches events against configurable rules and returns
// matched rule IDs for the HoldQueue. SSE is half-duplex Receive-only on
// the live wire so a single Match(env, msg) method covers every event;
// the rule's Direction field is accepted for cross-protocol schema
// consistency and "send" is rejected at compile time.
//
// TransformEngine applies SSE-specific actions
// (SetEvent / SetID / SetData / ReplaceData / Prepend/AppendData / SetRetry /
// Drop) in priority order. Rules are sorted ascending by Priority — lower
// values applied first; on scalar conflicts the highest-priority rule's
// (highest numeric value) write wins because it lands last.
//
// # MITM principles (USK-892 design review)
//
//   - Engines do NOT clear env.Raw. The session-side `sseMessageMutated`
//     field-diff (see internal/session/session.go relaySSEEvent) is the
//     authoritative re-encode signal. Clearing Raw here would false-
//     positive every unchanged event the Pipeline passes through.
//   - Anomalies are record-only metadata; engines never mutate the
//     Anomalies slice and never report Anomaly-only differences as a
//     mutation.
//   - PrependData / AppendData emit raw concatenation. The engine does
//     NOT auto-insert newline boundaries. Operators control the
//     "single data line vs. multi-line" decision by including (or not)
//     a `\n` in their action value. Compile-time CRLF guards still
//     reject `\r`.
//   - SetEvent / SetID / PrependData / AppendData / ReplaceData
//     replacement bodies are validated at compile time to reject CR/LF
//     characters (CWE-113). SetData accepts `\n` because multi-line
//     data is a legal RFC 8895 wire form (one `data:` line per chunk);
//     it still rejects `\r`.
//   - Direction is "receive"-only on the live wire. "send" rule entries
//     are rejected at compile time so a misconfigured rule cannot match
//     silently. "both" is accepted for cross-protocol template parity.
//
// # Drop semantics
//
// Drop mirrors the WS / gRPC mid-stream pattern: the Pipeline result
// carries Action=Drop and BlockedBy=BlockedByInterceptDrop. No synthetic
// HTTP 403 is emitted (SSE has no request-level handshake at the event
// granularity to short-circuit). Dropped events are recorded as a
// modified variant via RecordStep.
//
// # Match field sources
//
//   - EventPattern matches SSEMessage.Event (the `event:` field; may be
//     empty when only `data:` lines are present).
//   - IDPattern matches SSEMessage.ID.
//   - DataPattern matches SSEMessage.Data — the joined multi-line data
//     body. Operators wanting to match per-line need the `(?m)` flag in
//     their regex.
//   - RetryMinMs / RetryMaxMs match SSEMessage.Retry. Both are *int64
//     pointers (nil = unbounded). The rule is skipped on events with
//     Retry == 0 (unset on the wire).
//   - Anomalies is OR / any-of: the rule matches when any envelope
//     anomaly's Type equals any rule entry. Empty rule list matches all
//     events.
package sse
