package http1

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1274: the client-facing Layer exposes the authority of an
// absolute-form request-target on Envelope.Context.AbsoluteFormAuthority,
// verbatim from the wire (userinfo, casing and port included), so the
// scope check can judge it. HTTPMessage.Authority keeps carrying Host,
// and the wire snapshot (Envelope.Raw) is untouched.

// parseOneRequest feeds wire through a real client-facing Layer and
// returns the Send envelope of its first exchange.
func parseOneRequest(t *testing.T, wire string) *envelope.Envelope {
	t.Helper()
	cli, srv := net.Pipe()
	l := New(srv, "usk1274", envelope.Send, WithScheme("http"))
	t.Cleanup(func() {
		_ = l.Close()
		_ = cli.Close()
	})
	go func() { _, _ = cli.Write([]byte(wire)) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ch interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case c := <-l.Channels():
		ch = c
	case <-ctx.Done():
		t.Fatalf("Layer yielded no channel")
	}
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next(%q): %v", wire, err)
	}
	return env
}

func TestLayer_AbsoluteFormAuthority(t *testing.T) {
	tests := []struct {
		name          string
		requestLine   string
		host          string
		wantAbsolute  string
		wantAuthority string
	}{
		{
			name:          "absolute-form with userinfo, mixed case and port",
			requestLine:   "GET http://u@Denied.Example:8080/p?q HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "u@Denied.Example:8080",
			wantAuthority: "allowed.example",
		},
		{
			name:          "absolute-form without path",
			requestLine:   "GET http://denied.example HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "denied.example",
			wantAuthority: "allowed.example",
		},
		{
			name:          "absolute-form with query directly after authority",
			requestLine:   "GET http://denied.example?x=1 HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "denied.example",
			wantAuthority: "allowed.example",
		},
		{
			name:          "non-http scheme",
			requestLine:   "GET foo://denied.example/p HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "denied.example",
			wantAuthority: "allowed.example",
		},
		{
			name:          "empty authority",
			requestLine:   "GET http:///x HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "",
			wantAuthority: "allowed.example",
		},
		{
			name:          "unparsable authority kept verbatim",
			requestLine:   "GET http://[bad/x HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "[bad",
			wantAuthority: "allowed.example",
		},
		{
			name:          "origin-form",
			requestLine:   "GET /p?q HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "",
			wantAuthority: "allowed.example",
		},
		{
			name:          "asterisk-form",
			requestLine:   "OPTIONS * HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "",
			wantAuthority: "allowed.example",
		},
		{
			name:          "origin-form whose path contains ://",
			requestLine:   "GET /redirect?to=http://denied.example/ HTTP/1.1",
			host:          "allowed.example",
			wantAbsolute:  "",
			wantAuthority: "allowed.example",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.requestLine + "\r\nHost: " + tt.host + "\r\nContent-Length: 0\r\n\r\n"
			env := parseOneRequest(t, wire)
			if got := env.Context.AbsoluteFormAuthority; got != tt.wantAbsolute {
				t.Errorf("Context.AbsoluteFormAuthority = %q, want %q", got, tt.wantAbsolute)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.Authority != tt.wantAuthority {
				t.Errorf("HTTPMessage.Authority = %q, want %q", msg.Authority, tt.wantAuthority)
			}
			if string(env.Raw) != wire {
				t.Errorf("Envelope.Raw = %q, want the wire bytes %q", env.Raw, wire)
			}
		})
	}
}
