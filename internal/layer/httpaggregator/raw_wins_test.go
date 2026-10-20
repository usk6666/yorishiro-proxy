package httpaggregator

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestRawWinsSupported_RefusesHTTPMessage: an h2 HTTPMessage's Raw is
// unframed HPACK fragments + DATA payloads encoded against the source
// connection's dynamic table, so a plugin msg["raw"] can never be written
// verbatim (RFC-001 §9.3 D4 h2 policy).
func TestRawWinsSupported_RefusesHTTPMessage(t *testing.T) {
	cases := []struct {
		name string
		env  *envelope.Envelope
		want bool
	}{
		{"request", &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}}, false},
		{"response", &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP, Message: &envelope.HTTPMessage{Status: 200}}, false},
		{"nil envelope", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RawWinsSupported(tc.env); got != tc.want {
				t.Errorf("RawWinsSupported = %v, want %v", got, tc.want)
			}
		})
	}
}

// captureDefaultSlog swaps the process-default logger for one writing to
// a buffer at Debug level and restores it on cleanup. Callers must not
// run in parallel.
func captureDefaultSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestSend_RawWinsBackstop_WarnsAndUsesMessagePath: if a raw-authoritative
// envelope reaches the h2 aggregator (a registry missing the h2 policy),
// Send still renders the Message (the Raw cannot be framed) and warns that
// the recorded variant may diverge from the wire.
func TestSend_RawWinsBackstop_WarnsAndUsesMessagePath(t *testing.T) {
	logs := captureDefaultSlog(t)

	inner := newFakeChannel()
	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)
	env := &envelope.Envelope{
		StreamID:         "s1",
		Direction:        envelope.Send,
		Protocol:         envelope.ProtocolHTTP,
		Raw:              []byte("plugin-authored bytes"),
		RawAuthoritative: true,
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "http", Authority: "example.test", Path: "/msg",
			Headers: []envelope.KeyValue{{Name: "x-marker", Value: "m"}},
		},
	}
	if err := agg.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(inner.sent) != 1 {
		t.Fatalf("inner sends = %d, want 1 HEADERS event", len(inner.sent))
	}
	hdr, ok := inner.sent[0].Message.(*http2.H2HeadersEvent)
	if !ok {
		t.Fatalf("inner sent %T, want *http2.H2HeadersEvent", inner.sent[0].Message)
	}
	if hdr.Path != "/msg" {
		t.Errorf("HEADERS path = %q, want Message path /msg", hdr.Path)
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "raw") {
		t.Errorf("no raw-wins Warn logged; logs:\n%s", out)
	}
}
