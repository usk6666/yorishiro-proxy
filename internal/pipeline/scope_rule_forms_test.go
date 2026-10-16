package pipeline

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// USK-1129: scope rule forms that silently never took effect, driven through
// the Pipeline scope steps with envelopes shaped exactly as the data path
// produces them.

// parseH1Request feeds raw request bytes through the real HTTP/1.x Layer
// (server-facing role) and returns the first Send envelope, so the
// HTTPMessage's Authority / Path are what the production parser derives —
// including the port-less "Host: [::1]" that net.SplitHostPort cannot split.
func parseH1Request(t *testing.T, raw string) *envelope.Envelope {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	l := http1.New(server, "usk1129", envelope.Send)
	t.Cleanup(func() { _ = l.Close() })

	go func() { _, _ = client.Write([]byte(raw)) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ch interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case c, ok := <-l.Channels():
		if !ok {
			t.Fatal("http1 layer closed without yielding a channel")
		}
		ch = c
	case <-ctx.Done():
		t.Fatal("timed out waiting for http1 channel")
	}
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("http1 Next: %v", err)
	}
	if _, ok := env.Message.(*envelope.HTTPMessage); !ok {
		t.Fatalf("envelope message = %T, want *HTTPMessage", env.Message)
	}
	return env
}

// TestHTTPScopeStep_IPv6RuleForms is T3: every zone-less IPv6 spelling of one
// address is the same target, whichever spelling the rule and the Host header use.
func TestHTTPScopeStep_IPv6RuleForms(t *testing.T) {
	tests := []struct {
		name      string
		denyHost  string
		raw       string
		wantBlock bool
	}{
		// Port-less Host: the gate's SplitHostPort fails and the bracketed
		// authority reaches CheckTarget verbatim.
		{"bare deny vs port-less bracketed Host", "::1",
			"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", true},
		// Host with port: SplitHostPort strips the brackets.
		{"bracketed deny vs bracketed Host with port", "[::1]",
			"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", true},
		{"bare deny vs non-canonical Host", "::1",
			"GET / HTTP/1.1\r\nHost: [0:0::1]:8080\r\n\r\n", true},
		{"bracketed deny vs absolute-form target", "[::1]",
			"GET http://[::1]:8080/x HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", true},
		// Control: other addresses stay unblocked.
		{"bracketed deny vs other address", "[::1]",
			"GET / HTTP/1.1\r\nHost: [::2]:8080\r\n\r\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: tc.denyHost}})
			step := NewHTTPScopeStep(scope)

			env := parseH1Request(t, tc.raw)
			msg := env.Message.(*envelope.HTTPMessage)
			r := step.Process(context.Background(), env)
			blocked := r.Action == Respond && r.BlockedBy == BlockedByTargetScope
			if blocked != tc.wantBlock {
				t.Errorf("deny %q, Authority %q: action=%v blockedBy=%q, want blocked=%v",
					tc.denyHost, msg.Authority, r.Action, r.BlockedBy, tc.wantBlock)
			}
		})
	}
}

// TestHostScopeStep_BracketedIPv6Deny is T2: a CONNECT-routed connection to
// "[::1]:443" carries TargetHost verbatim and a TLS snapshot (scheme https);
// a Policy deny "[::1]" must drop it.
func TestHostScopeStep_BracketedIPv6Deny(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "[::1]"}})
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("x")},
		Context: envelope.EnvelopeContext{
			TargetHost: "[::1]:443",
			TLS:        &envelope.TLSSnapshot{},
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Drop || r.BlockedBy != BlockedByTargetScope {
		t.Errorf("HostScopeStep(deny [::1], TargetHost [::1]:443) = action %v blockedBy %q, want Drop/%q",
			r.Action, r.BlockedBy, BlockedByTargetScope)
	}
}

// TestHTTPScopeStep_PathPrefixWithoutSlashIsNoOp is T7, a characterization
// test: it passes before and after USK-1129 on purpose. It documents why the
// validator now rejects a path_prefix that does not start with "/": the
// parser never yields such a path for normal traffic (absolute-form becomes
// "/admin"; "OPTIONS *" becomes "*"), so a deny "admin" silently never fires.
func TestHTTPScopeStep_PathPrefixWithoutSlashIsNoOp(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "h.test", PathPrefix: "admin"}})
	step := NewHTTPScopeStep(scope)

	for _, raw := range []string{
		"GET http://h.test/admin HTTP/1.1\r\nHost: h.test\r\n\r\n",
		"GET /admin HTTP/1.1\r\nHost: h.test\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: h.test\r\n\r\n",
	} {
		env := parseH1Request(t, raw)
		msg := env.Message.(*envelope.HTTPMessage)
		if r := step.Process(context.Background(), env); r.Action != Continue {
			t.Errorf("path %q unexpectedly matched deny path_prefix \"admin\" (action %v)", msg.Path, r.Action)
		}
	}
}
