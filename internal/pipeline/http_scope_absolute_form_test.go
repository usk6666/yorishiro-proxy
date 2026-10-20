package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1274: an HTTP/1.x absolute-form request-target names the host a
// server routes on (RFC 9112 §3.2.2: the URI authority wins over Host).
// HTTPScopeStep judges that authority as a name leg next to Host, so an
// allowed Host no longer carries a request to a denied absolute-form
// authority. Every envelope here comes from the real HTTP/1.x Layer.

func TestHTTPScopeStep_AbsoluteFormAuthority(t *testing.T) {
	const target = "127.0.0.1:8080"
	allowLoopback := []connector.TargetRule{{Hostname: "127.0.0.1"}}
	denies := []connector.TargetRule{{Hostname: "denied.example"}, {Hostname: "::1"}}
	tests := []struct {
		name        string
		requestLine string
		wantBlock   bool
	}{
		{"denied absolute-form authority", "GET http://denied.example/abs HTTP/1.1", true},
		{"denied authority, uppercase", "GET http://DENIED.EXAMPLE/abs HTTP/1.1", true},
		{"denied authority behind userinfo", "GET http://allowed@denied.example/abs HTTP/1.1", true},
		{"denied authority, non-http scheme", "GET foo://denied.example/abs HTTP/1.1", true},
		{"overflowing port fails closed", "GET http://ok.example:99999999999/abs HTTP/1.1", true},
		{"denied IPv6 literal", "GET http://[::1]/abs HTTP/1.1", true},
		{"unterminated IPv6 literal fails closed", "GET http://[bad/abs HTTP/1.1", true},
		{"percent-encoded ASCII host fails closed", "GET http://denied.ex%61mple/abs HTTP/1.1", true},
		{"empty authority is no leg", "GET http:///abs HTTP/1.1", false},
		{"origin-form", "GET /abs HTTP/1.1", false},
		{"IP-literal allow exempts an unlisted name", "GET http://vhost.example/abs HTTP/1.1", false},
		{"absolute-form naming the dial target", "GET http://" + target + "/abs HTTP/1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.requestLine + "\r\nHost: " + target + "\r\n\r\n"
			env := realH1RequestEnvelopeWithContext(t, "http",
				envelope.EnvelopeContext{TargetHost: target}, wire)
			step := NewHTTPScopeStep(hostLegScope(allowLoopback, denies))
			r := step.Process(context.Background(), env)
			if tt.wantBlock {
				if r.Action != Respond || r.BlockedBy != BlockedByTargetScope {
					t.Fatalf("%q: Action=%v BlockedBy=%q, want Respond / %q", tt.requestLine, r.Action, r.BlockedBy, BlockedByTargetScope)
				}
				return
			}
			if r.Action != Continue {
				t.Fatalf("%q: Action=%v, want Continue", tt.requestLine, r.Action)
			}
		})
	}
}

// Under a domain allow the absolute-form authority must be allow-listed
// too (Option B): the operator allowed names, not an address.
func TestHTTPScopeStep_AbsoluteFormAuthority_DomainAllow(t *testing.T) {
	const target = "localhost:8080"
	step := NewHTTPScopeStep(hostLegScope([]connector.TargetRule{{Hostname: "localhost"}}, nil))
	for _, tt := range []struct {
		requestLine string
		wantBlock   bool
	}{
		{"GET http://unlisted.example/abs HTTP/1.1", true},
		{"GET http://localhost:8080/abs HTTP/1.1", false},
	} {
		env := realH1RequestEnvelopeWithContext(t, "http", envelope.EnvelopeContext{TargetHost: target},
			tt.requestLine+"\r\nHost: "+target+"\r\n\r\n")
		r := step.Process(context.Background(), env)
		if blocked := r.Action == Respond; blocked != tt.wantBlock {
			t.Errorf("%q: Action=%v, want blocked=%v", tt.requestLine, r.Action, tt.wantBlock)
		}
	}
}
