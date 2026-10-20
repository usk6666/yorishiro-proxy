package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1235: HTTPScopeStep infers the port of a port-less authority from the
// transport scheme (443 / 80). Behind a CONNECT to a non-default port —
// `CONNECT x.test:8443` followed by `:authority: x.test` — that inference
// names a port the connection never dialed. These tests pin that the verdict
// is nevertheless bound to the real dial port, because HTTPScopeStep also
// checks Envelope.Context.TargetHost (the dial host:port) with the request
// path and both checks must pass. The authority's inferred default port can
// therefore only over-block, never admit or exempt the request.

// portInferenceEnv is a TLS-MITM'd Send request whose authority carries no
// port while the connection dialed targetHost.
func portInferenceEnv(targetHost, authority, path string) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{
			TargetHost: targetHost,
			TLS:        &envelope.TLSSnapshot{SNI: "x.test"},
		},
		Message: &envelope.HTTPMessage{Method: "GET", Authority: authority, Path: path},
	}
}

func assertScopeBlocked(t *testing.T, r Result) {
	t.Helper()
	if r.Action != Respond || r.BlockedBy != BlockedByTargetScope {
		t.Fatalf("action = %v blockedBy %q, want Respond/%q", r.Action, r.BlockedBy, BlockedByTargetScope)
	}
	if r.Response == nil {
		t.Fatalf("Respond without a synthetic response")
	}
	if m, ok := r.Response.Message.(*envelope.HTTPMessage); !ok || m.Status != 403 {
		t.Errorf("response = %#v, want a 403 HTTPMessage", r.Response.Message)
	}
}

// T2 (Issue case a): a path-scoped deny with ports:[8443] fires on an HTTP/2
// request whose `:authority` has no port, when the connection dialed
// x.test:8443. The envelope comes from the real ServerRole HTTP/2 Layer +
// httpaggregator; it runs through the production HostScope → HTTPScope
// order. Before the TargetHost check the authority leg judged x.test:443,
// the deny's port did not match, and HostScopeStep (path "") could not
// match a path-scoped deny either — the request reached /admin.
func TestScopeChain_PortlessH2AuthorityDenyOnDialPort(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{
		{Hostname: "x.test", Ports: []int{8443}, PathPrefix: "/admin"},
	})

	tests := []struct {
		path      string
		wantBlock bool
	}{
		{"/admin", true},
		{"/admin/users", true},
		{"/public", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			env := rawH2RequestEnvelope(t, []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "x.test"},
				{Name: ":path", Value: tc.path},
			})
			// The h2 Layer helper is wired for a default-port dial; this
			// connection was opened by `CONNECT x.test:8443`.
			env.Context.TargetHost = "x.test:8443"
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.Authority != "x.test" {
				t.Fatalf("precondition: aggregated Authority = %q, want port-less %q", msg.Authority, "x.test")
			}

			_, action, resp := scopeChain(scope).Run(context.Background(), env)
			if !tc.wantBlock {
				if action != Continue {
					t.Fatalf("action = %v, want Continue (path outside the deny prefix)", action)
				}
				return
			}
			if action != Respond || resp == nil {
				t.Fatalf("action = %v, want Respond (403) — the deny on the dial port was bypassed by a port-less :authority", action)
			}
			if m, ok := resp.Message.(*envelope.HTTPMessage); !ok || m.Status != 403 {
				t.Errorf("response = %#v, want a 403 HTTPMessage", resp.Message)
			}
		})
	}
}

// T3 (Issue case b): an allow for x.test on port 443 does not admit a
// request on a connection that dialed x.test:8443, even though the port-less
// authority alone infers 443 and matches the allow. A domain name is used on
// purpose so no IP-literal admission path is involved.
func TestHTTPScopeStep_PortlessAuthorityAllowDoesNotAdmitOtherDialPort(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "x.test", Ports: []int{443}}}, nil)
	step := NewHTTPScopeStep(scope)

	// Control: the same request on a default-port dial is admitted, so the
	// block below is caused by the dial port and nothing else.
	if r := step.Process(context.Background(), portInferenceEnv("x.test:443", "x.test", "/")); r.Action != Continue {
		t.Fatalf("control: dial x.test:443 action = %v blockedBy %q, want Continue", r.Action, r.BlockedBy)
	}

	assertScopeBlocked(t, step.Process(context.Background(), portInferenceEnv("x.test:8443", "x.test", "/")))
}

// T4 (characterization — decision pinned for USK-1235): a port-less
// authority means the scheme's default port (RFC 9110 §4.2.2 for https: "If
// the port subcomponent is empty or not given, TCP port 443 is the
// default"; §4.2.1 says the same of port 80 for http). The authority leg keeps that meaning even when the connection
// dialed a different port; it is not rewritten from TargetHost. So a deny
// on x.test:443 also blocks a port-less `x.test` request riding a
// connection to x.test:8443. This is an over-block by design: the
// authority leg can only make the verdict stricter, and the dial-port leg
// is what keeps it from being looser.
func TestHTTPScopeStep_PortlessAuthorityTakesDefaultPortOverBlock(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "x.test", Ports: []int{443}}})
	step := NewHTTPScopeStep(scope)

	assertScopeBlocked(t, step.Process(context.Background(), portInferenceEnv("x.test:8443", "x.test", "/")))

	// Control: an authority carrying the dial port explicitly is admitted.
	if r := step.Process(context.Background(), portInferenceEnv("x.test:8443", "x.test:8443", "/")); r.Action != Continue {
		t.Errorf("control: authority x.test:8443 action = %v blockedBy %q, want Continue", r.Action, r.BlockedBy)
	}
}
