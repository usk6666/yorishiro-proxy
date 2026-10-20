package pipeline

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-1304: every comma-separated part of a Host value or authority is
// deny-checked. USK-1306: a name leg's deny also matches on the dial
// target's port. Both on HTTP/1 Host, HTTP/2 :authority and HTTP/2 host.

// hostLegH2Request is a Send HTTP/2 request: TLS client connection,
// TargetHost the dial target, Authority the :authority pseudo-header and
// headers the regular header fields (layer/http2 → httpaggregator).
func hostLegH2Request(target, authority string, headers ...envelope.KeyValue) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Context:   envelope.EnvelopeContext{TargetHost: target, TLS: &envelope.TLSSnapshot{}},
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "https", Authority: authority, Path: "/",
			Headers: headers,
		},
	}
}

func TestHTTPScopeStep_NameLegParsing(t *testing.T) {
	deny := []connector.TargetRule{{Hostname: "denied.example"}}
	allowLoopback := []connector.TargetRule{{Hostname: "127.0.0.1"}}
	portDeny8080 := []connector.TargetRule{{Hostname: "portd.example", Ports: []int{8080}}}
	portDeny443 := []connector.TargetRule{{Hostname: "portd.example", Ports: []int{443}}}
	tests := []struct {
		name      string
		allows    []connector.TargetRule
		denies    []connector.TargetRule
		env       *envelope.Envelope
		wantBlock bool
	}{
		{
			name:      "h1 Host comma, denied part (deny-only)",
			denies:    deny,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: "ok.example, denied.example"}),
			wantBlock: true,
		},
		{
			name:      "h1 Host comma, denied part (IP-literal allow)",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: "ok.example, denied.example"}),
			wantBlock: true,
		},
		{
			name:      "h1 authority comma, denied part",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH1Request("ok.example, denied.example"),
			wantBlock: true,
		},
		{
			name:      "h1 Host comma, non-denied parts pass (guard)",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH1Request("a.example, b.example", envelope.KeyValue{Name: "Host", Value: "a.example, b.example"}),
			wantBlock: false,
		},
		{
			name:      "h2 host comma, denied part",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH2Request("127.0.0.1:443", "127.0.0.1", envelope.KeyValue{Name: "host", Value: "ok.example, denied.example"}),
			wantBlock: true,
		},
		{
			name:      "h2 :authority comma, denied part",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH2Request("127.0.0.1:443", "ok.example, denied.example"),
			wantBlock: true,
		},
		{
			name:      "h1 Host dial-port deny",
			allows:    allowLoopback,
			denies:    portDeny8080,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: "portd.example:1"}),
			wantBlock: true,
		},
		{
			name:      "h1 authority dial-port deny",
			allows:    allowLoopback,
			denies:    portDeny8080,
			env:       hostLegH1Request("portd.example:1"),
			wantBlock: true,
		},
		{
			name:      "h2 :authority dial-port deny",
			allows:    allowLoopback,
			denies:    portDeny443,
			env:       hostLegH2Request("127.0.0.1:443", "portd.example:1"),
			wantBlock: true,
		},
		{
			name:      "h2 host dial-port deny",
			allows:    allowLoopback,
			denies:    portDeny443,
			env:       hostLegH2Request("127.0.0.1:443", "127.0.0.1", envelope.KeyValue{Name: "host", Value: "portd.example:1"}),
			wantBlock: true,
		},
		{
			// Review F-1: the multi-colon reading closed on the Host leg
			// must not stay open on :authority when no host header is sent.
			name:      "h2 :authority multi-colon non-IPv6 fails closed",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH2Request("127.0.0.1:443", "denied.example:5432:x"),
			wantBlock: true,
		},
		{
			// Review S-2: a bracket holding a non-IPv6 value.
			name:      "h2 :authority non-IPv6 bracket fails closed",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH2Request("127.0.0.1:443", "[denied.example:1]:443"),
			wantBlock: true,
		},
		{
			name:      "h2 :authority bracketed IPv6 passes (guard)",
			allows:    allowLoopback,
			denies:    deny,
			env:       hostLegH2Request("127.0.0.1:443", "[::2]:443"),
			wantBlock: false,
		},
		{
			name:      "dial-port deny: neither port matches (guard)",
			allows:    allowLoopback,
			denies:    []connector.TargetRule{{Hostname: "portd.example", Ports: []int{9999}}},
			env:       hostLegH1Request("portd.example:8080", envelope.KeyValue{Name: "Host", Value: "portd.example:8080"}),
			wantBlock: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := NewHTTPScopeStep(hostLegScope(tt.allows, tt.denies))
			msg := tt.env.Message.(*envelope.HTTPMessage)
			before := append([]envelope.KeyValue(nil), msg.Headers...)
			beforeAuthority := msg.Authority

			r := step.Process(context.Background(), tt.env)

			if blocked := r.Action != Continue; blocked != tt.wantBlock {
				t.Fatalf("Process action = %v, want blocked=%v", r.Action, tt.wantBlock)
			}
			if tt.wantBlock && (r.Action != Respond || r.BlockedBy != BlockedByTargetScope) {
				t.Errorf("Result = %v / %q, want Respond / %q", r.Action, r.BlockedBy, BlockedByTargetScope)
			}
			if !reflect.DeepEqual(before, msg.Headers) || msg.Authority != beforeAuthority {
				t.Errorf("message mutated by the scope check")
			}
		})
	}
}

func TestInterceptStep_ScopeRecheck_ModifyAndForwardCommaHost(t *testing.T) {
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	held := recheckHTTPRequest("/public")
	held.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: recheckTarget}}
	modified := held.Clone()
	modified.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: "ok.example, denied.example"}}

	whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

	assertTargetScope403(t, step.Process(context.Background(), held))
}

func TestTransformStep_ScopeRecheck_CommaHost(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.SetRules([]httprules.TransformRule{{
		ID:          "set-host",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(".*"),
		ActionType:  httprules.TransformSetHeader,
		HeaderName:  "Host",
		HeaderValue: "ok.example, denied.example",
	}})
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	step := NewTransformStep(engine, nil, nil, nil).
		WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
	env := recheckHTTPRequest("/")
	env.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: recheckTarget}}
	assertTargetScope403(t, step.Process(context.Background(), env))
}
