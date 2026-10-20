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

// USK-1167: the HTTP/1 serializer writes the Host line from Headers and
// never writes msg.Authority, so HTTPScopeStep must judge every Host header
// value (not only the authority parsed from the first one). HTTP/2 forwards
// a regular `host` header next to :authority, so it is judged there too.
// Name legs follow "Option B": deny rules always apply; an allow layer
// that admitted the dial target through an IP-literal rule does not
// require the name to be allow-listed.

const hostLegTarget = "127.0.0.1:8080"

func hostLegScope(allows, denies []connector.TargetRule) *connector.TargetScope {
	s := connector.NewTargetScope()
	s.SetPolicyRules(allows, denies)
	return s
}

// hostLegH1Request is a Send HTTP/1.x request in the plain-forward shape:
// TargetHost is the dial target and Authority is the first Host value as
// parsed off the wire (layer/http1 parseRequestURI).
func hostLegH1Request(authority string, headers ...envelope.KeyValue) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Context:   envelope.EnvelopeContext{TargetHost: hostLegTarget},
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "http",
			Authority: authority,
			Path:      "/",
			Headers:   headers,
		},
	}
}

func TestHTTPScopeStep_HostHeaderLegs(t *testing.T) {
	denyVhost := []connector.TargetRule{{Hostname: "denied.example"}}
	allowLoopback := []connector.TargetRule{{Hostname: "127.0.0.1"}}
	tests := []struct {
		name      string
		allows    []connector.TargetRule
		denies    []connector.TargetRule
		env       *envelope.Envelope
		wantBlock bool
	}{
		{
			name:      "Host rewritten to a denied vhost, authority unchanged",
			allows:    allowLoopback,
			denies:    denyVhost,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: "denied.example"}),
			wantBlock: true,
		},
		{
			name:      "Host with surrounding OWS",
			denies:    denyVhost,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: " denied.example\t"}),
			wantBlock: true,
		},
		{
			name:   "duplicate Host, second one denied",
			denies: denyVhost,
			env: hostLegH1Request(hostLegTarget,
				envelope.KeyValue{Name: "Host", Value: hostLegTarget},
				envelope.KeyValue{Name: "HOST", Value: "denied.example"}),
			wantBlock: true,
		},
		{
			name:      "Host name with trailing whitespace before the colon",
			denies:    denyVhost,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host ", Value: "denied.example"}),
			wantBlock: true,
		},
		{
			name:      "Host with a port",
			denies:    denyVhost,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "host", Value: "denied.example:8080"}),
			wantBlock: true,
		},
		{
			name:      "Host with a non-decimal port fails closed",
			denies:    []connector.TargetRule{{Hostname: "denied.example", Ports: []int{80}}},
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: "denied.example:abc"}),
			wantBlock: true,
		},
		{
			name:      "allowed Host passes (guard)",
			allows:    allowLoopback,
			denies:    denyVhost,
			env:       hostLegH1Request(hostLegTarget, envelope.KeyValue{Name: "Host", Value: hostLegTarget}),
			wantBlock: false,
		},
		{
			name:      "Option B: IP-literal allow on the dial target, unlisted vhost passes",
			allows:    allowLoopback,
			env:       hostLegH1Request("vhost.example", envelope.KeyValue{Name: "Host", Value: "vhost.example"}),
			wantBlock: false,
		},
		{
			name:      "Option B: authority leg alone (no Host header) is relaxed as well",
			allows:    allowLoopback,
			env:       hostLegH1Request("vhost.example"),
			wantBlock: false,
		},
		{
			name:      "Option B: denied authority still refused",
			allows:    allowLoopback,
			denies:    denyVhost,
			env:       hostLegH1Request("denied.example"),
			wantBlock: true,
		},
		{
			name:   "h2: denied regular host header next to an allowed :authority",
			denies: denyVhost,
			env: &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Context:   envelope.EnvelopeContext{TargetHost: "127.0.0.1:443", TLS: &envelope.TLSSnapshot{}},
				Message: &envelope.HTTPMessage{
					Method: "GET", Scheme: "https", Authority: "127.0.0.1", Path: "/",
					Headers: []envelope.KeyValue{{Name: "host", Value: "denied.example"}},
				},
			},
			wantBlock: true,
		},
		{
			name:   "h2: non-denied :authority/host mismatch passes",
			allows: allowLoopback,
			denies: denyVhost,
			env: &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Context:   envelope.EnvelopeContext{TargetHost: "127.0.0.1:443", TLS: &envelope.TLSSnapshot{}},
				Message: &envelope.HTTPMessage{
					Method: "GET", Scheme: "https", Authority: "127.0.0.1", Path: "/",
					Headers: []envelope.KeyValue{{Name: "host", Value: "other.example"}},
				},
			},
			wantBlock: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := NewHTTPScopeStep(hostLegScope(tt.allows, tt.denies))
			msg := tt.env.Message.(*envelope.HTTPMessage)
			before := append([]envelope.KeyValue(nil), msg.Headers...)

			r := step.Process(context.Background(), tt.env)

			if blocked := r.Action != Continue; blocked != tt.wantBlock {
				t.Fatalf("Process action = %v, want blocked=%v", r.Action, tt.wantBlock)
			}
			if tt.wantBlock {
				if r.Action != Respond || r.BlockedBy != BlockedByTargetScope {
					t.Errorf("Result = %v / %q, want Respond / %q", r.Action, r.BlockedBy, BlockedByTargetScope)
				}
			}
			if !reflect.DeepEqual(before, msg.Headers) {
				t.Errorf("Headers mutated by the scope check: %v -> %v", before, msg.Headers)
			}
		})
	}
}

// Option B, domain branch: a dial target admitted by a domain-name allow
// keeps the full check on name legs.
func TestHTTPScopeStep_HostHeaderLegs_DomainAllowKeepsFullCheck(t *testing.T) {
	step := NewHTTPScopeStep(hostLegScope([]connector.TargetRule{{Hostname: "app.example"}}, nil))
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Context:   envelope.EnvelopeContext{TargetHost: "app.example:80"},
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "http", Authority: "app.example", Path: "/",
			Headers: []envelope.KeyValue{{Name: "Host", Value: "other.example"}},
		},
	}
	if r := step.Process(context.Background(), env); r.Action != Respond {
		t.Fatalf("Process action = %v, want Respond (other.example is outside the domain allow)", r.Action)
	}
}

// Intercept route: the release re-check runs the real HTTPScopeStep, so a
// modify_and_forward that only rewrites the Host header is refused.
func TestInterceptStep_ScopeRecheck_ModifyAndForwardHostHeaderOnly(t *testing.T) {
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	held := recheckHTTPRequest("/public")
	held.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: recheckTarget}}
	modified := held.Clone()
	modified.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: "denied.example"}}

	whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

	assertTargetScope403(t, step.Process(context.Background(), held))
}

// Transform route: TransformStep runs after the head-of-pipeline scope
// check, so a set_header Host rule must be re-checked.
func TestTransformStep_ScopeRecheck_HostHeader(t *testing.T) {
	newStep := func(value string, scope *connector.TargetScope) *TransformStep {
		engine := httprules.NewTransformEngine()
		engine.SetRules([]httprules.TransformRule{{
			ID:          "set-host",
			Enabled:     true,
			Direction:   httprules.DirectionRequest,
			PathPattern: regexp.MustCompile(".*"),
			ActionType:  httprules.TransformSetHeader,
			HeaderName:  "Host",
			HeaderValue: value,
		}})
		return NewTransformStep(engine, nil, nil, nil).
			WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
	}
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})

	t.Run("denied Host refused", func(t *testing.T) {
		env := recheckHTTPRequest("/")
		env.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: recheckTarget}}
		assertTargetScope403(t, newStep("denied.example", scope).Process(context.Background(), env))
	})
	t.Run("allowed Host passes", func(t *testing.T) {
		env := recheckHTTPRequest("/")
		env.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: recheckTarget}}
		if r := newStep("vhost.example", scope).Process(context.Background(), env); r.Action != Continue {
			t.Fatalf("Process action = %v (%q), want Continue", r.Action, r.BlockedBy)
		}
	})
	t.Run("no mutation: no re-check", func(t *testing.T) {
		// The rule targets responses only, so the request is not mutated and
		// an already-denied request is not re-judged here (the head of the
		// pipeline owns that verdict).
		engine := httprules.NewTransformEngine()
		step := NewTransformStep(engine, nil, nil, nil).
			WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
		env := recheckHTTPRequest("/")
		env.Message.(*envelope.HTTPMessage).Headers = []envelope.KeyValue{{Name: "Host", Value: "denied.example"}}
		if r := step.Process(context.Background(), env); r.Action != Continue {
			t.Fatalf("Process action = %v, want Continue (no transform fired)", r.Action)
		}
	})
}
