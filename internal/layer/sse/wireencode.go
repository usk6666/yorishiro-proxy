package sse

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EncodeWireBytes re-renders env.Message into Server-Sent Events wire-form
// bytes for use by pipeline.RecordStep as the modified variant's RawBytes.
//
// Field order: event → id → retry → data lines → terminating blank line.
// Order is semantically irrelevant per RFC 8895 (each line is its own
// field); this order matches the parser's SSEEvent.String() helper for
// least-surprise round-trips.
//
// Field-emission rules:
//   - event: only when Event != ""
//   - id:    only when ID != ""
//   - retry: only when Retry > 0; serialized as integer milliseconds
//     (inverse of parseRetry).
//   - data:  one line per "\n"-split chunk of Data; entirely omitted when
//     Data == "" (avoids the bogus `data: \n` that SSEEvent.String emits).
//   - Anomalies are record-only metadata and never appear in wire output.
//
// Direction-agnostic: SSE is half-duplex (Receive) on the live wire, but
// the encoder produces valid bytes for any Direction so future Resend or
// fuzz paths can round-trip.
//
// EncodeWireBytes is pure: it does not mutate env or env.Message; it does
// no I/O.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("sse: EncodeWireBytes: nil envelope")
	}
	if env.Message == nil {
		return nil, fmt.Errorf("sse: EncodeWireBytes: nil Message")
	}
	msg, ok := env.Message.(*envelope.SSEMessage)
	if !ok {
		return nil, fmt.Errorf("sse: EncodeWireBytes: requires *SSEMessage, got %T", env.Message)
	}

	var buf bytes.Buffer
	if msg.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(msg.Event)
		buf.WriteByte('\n')
	}
	if msg.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(msg.ID)
		buf.WriteByte('\n')
	}
	if msg.Retry > 0 {
		buf.WriteString("retry: ")
		buf.WriteString(strconv.FormatInt(msg.Retry.Milliseconds(), 10))
		buf.WriteByte('\n')
	}
	if msg.Data != "" {
		for _, line := range strings.Split(msg.Data, "\n") {
			buf.WriteString("data: ")
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
