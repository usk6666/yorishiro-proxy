package grpc

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestRawWinsSupported: gRPC Start/End Raw is an HPACK fragment that
// cannot be written verbatim (refused); Data Raw is the DATA payload the
// Layer already writes verbatim (honoured).
func TestRawWinsSupported(t *testing.T) {
	cases := []struct {
		name string
		msg  envelope.Message
		want bool
	}{
		{"start", &envelope.GRPCStartMessage{Service: "s", Method: "m"}, false},
		{"end", &envelope.GRPCEndMessage{Status: 0}, false},
		{"end without raw", nil, false},
		{"data", &envelope.GRPCDataMessage{Payload: []byte("p")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &envelope.Envelope{Protocol: envelope.ProtocolGRPC, Raw: []byte("x"), RawAuthoritative: true, Message: tc.msg}
			if tc.msg == nil {
				// The predicate must not depend on End's Raw being set.
				env.Message = &envelope.GRPCEndMessage{Status: 2}
				env.Raw = nil
			}
			if got := RawWinsSupported(env); got != tc.want {
				t.Errorf("RawWinsSupported(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
	if !RawWinsSupported(nil) {
		t.Error("RawWinsSupported(nil) = false, want true (nothing to refuse)")
	}
}

// TestWarnRawWinsIgnored: the Send backstop warns only for a
// raw-authoritative Start/End (a registry missing the gRPC policy), never
// for Data or a non-authoritative envelope.
func TestWarnRawWinsIgnored(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cases := []struct {
		name string
		env  *envelope.Envelope
		warn bool
	}{
		{"authoritative start", &envelope.Envelope{Raw: []byte("x"), RawAuthoritative: true, Message: &envelope.GRPCStartMessage{}}, true},
		{"authoritative data", &envelope.Envelope{Raw: []byte("x"), RawAuthoritative: true, Message: &envelope.GRPCDataMessage{}}, false},
		{"observed start", &envelope.Envelope{Raw: []byte("x"), Message: &envelope.GRPCStartMessage{}}, false},
	}
	for _, tc := range cases {
		buf.Reset()
		warnRawWinsIgnored(context.Background(), tc.env)
		if got := strings.Contains(buf.String(), "level=WARN"); got != tc.warn {
			t.Errorf("%s: warned = %v, want %v (log=%q)", tc.name, got, tc.warn, buf.String())
		}
	}
}
