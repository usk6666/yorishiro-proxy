package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestHostScopeStep_NilScope(t *testing.T) {
	step := NewHostScopeStep(nil)
	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "example.com:443",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("nil scope: got action %v, want Continue", r.Action)
	}
}

func TestHostScopeStep_EmptyTargetHost(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("empty TargetHost: got action %v, want Continue", r.Action)
	}
}

func TestHostScopeStep_AllowedHost(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "allowed.com:443",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("allowed host: got action %v, want Continue", r.Action)
	}
}

func TestHostScopeStep_BlockedHost(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "blocked.com:443",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Drop {
		t.Errorf("blocked host: got action %v, want Drop", r.Action)
	}
	if r.BlockedBy != BlockedByTargetScope {
		t.Errorf("blocked host: BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
	}
}

func TestHostScopeStep_DeniedHost(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{
		{Hostname: "evil.com"},
	})
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "evil.com:80",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Drop {
		t.Errorf("denied host: got action %v, want Drop", r.Action)
	}
	if r.BlockedBy != BlockedByTargetScope {
		t.Errorf("denied host: BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
	}
}

func TestHostScopeStep_WildcardAllow(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "*.example.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	tests := []struct {
		name   string
		target string
		want   Action
	}{
		{"subdomain allowed", "sub.example.com:443", Continue},
		{"other domain blocked", "other.com:443", Drop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &envelope.Envelope{
				Context: envelope.EnvelopeContext{
					TargetHost: tt.target,
				},
			}
			r := step.Process(context.Background(), env)
			if r.Action != tt.want {
				t.Errorf("%s: got action %v, want %v", tt.name, r.Action, tt.want)
			}
		})
	}
}

func TestHostScopeStep_PortFiltering(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "example.com", Ports: []int{443}},
	}, nil)
	step := NewHostScopeStep(scope)

	tests := []struct {
		name   string
		target string
		want   Action
	}{
		{"allowed port", "example.com:443", Continue},
		{"blocked port", "example.com:80", Drop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &envelope.Envelope{
				Context: envelope.EnvelopeContext{
					TargetHost: tt.target,
				},
			}
			r := step.Process(context.Background(), env)
			if r.Action != tt.want {
				t.Errorf("%s: got action %v, want %v", tt.name, r.Action, tt.want)
			}
		})
	}
}

func TestHostScopeStep_BareHostname(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "allowed.com",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("bare hostname: got action %v, want Continue", r.Action)
	}
}

func TestHostScopeStep_NoRules_AllAllowed(t *testing.T) {
	scope := connector.NewTargetScope()
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "anything.com:443",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("no rules: got action %v, want Continue", r.Action)
	}
}

// TestHostScopeStep_BlockedHost_HTTPMessage_Respond verifies the USK-829
// branch: when the held envelope carries an *envelope.HTTPMessage payload,
// HostScopeStep block emits Respond + synthetic 403 instead of a silent
// Drop, so the client sees a clean wire terminator. Non-HTTPMessage blocks
// (covered by the legacy TestHostScopeStep_BlockedHost / _DeniedHost above)
// keep the Drop shape — protocol-correct terminators for raw/ws/gRPC are
// deferred (D2-D5).
func TestHostScopeStep_BlockedHost_HTTPMessage_Respond(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "blocked.com:443",
		},
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Respond {
		t.Fatalf("blocked HTTP host: got action %v, want Respond (USK-829)", r.Action)
	}
	if r.BlockedBy != BlockedByTargetScope {
		t.Errorf("blocked HTTP host: BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
	}
	if r.Response == nil {
		t.Fatal("blocked HTTP host: Response is nil; expected synthetic 403 envelope")
	}
	respMsg, ok := r.Response.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("blocked HTTP host: Response.Message type = %T, want *HTTPMessage", r.Response.Message)
	}
	if respMsg.Status != 403 {
		t.Errorf("blocked HTTP host: Response status = %d, want 403", respMsg.Status)
	}
	if r.Response.Direction != envelope.Receive {
		t.Errorf("blocked HTTP host: Response.Direction = %v, want Receive", r.Response.Direction)
	}
}

// TestHostScopeStep_DeniedHost_HTTPMessage_Respond mirrors the above but
// exercises the deny-list path (SetPolicyRules denies arg) — both allow-
// list miss and deny-list hit must route through the same Respond branch.
func TestHostScopeStep_DeniedHost_HTTPMessage_Respond(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{
		{Hostname: "evil.com"},
	})
	step := NewHostScopeStep(scope)

	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			TargetHost: "evil.com:80",
		},
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api",
		},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Respond {
		t.Fatalf("denied HTTP host: got action %v, want Respond (USK-829)", r.Action)
	}
	if r.BlockedBy != BlockedByTargetScope {
		t.Errorf("denied HTTP host: BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
	}
	if r.Response == nil {
		t.Fatal("denied HTTP host: Response is nil; expected synthetic 403 envelope")
	}
	respMsg, ok := r.Response.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("denied HTTP host: Response.Message type = %T, want *HTTPMessage", r.Response.Message)
	}
	if respMsg.Status != 403 {
		t.Errorf("denied HTTP host: Response status = %d, want 403", respMsg.Status)
	}
}

// TestHostScopeStep_SchemeDerivedFromTLS is the USK-1081 regression suite.
//
// Before USK-1081, Process passed a literal "" as the scheme argument to
// TargetScope.CheckTarget. matchTargetRule is AND logic, so every rule
// carrying a Schemes condition silently stopped matching at this Step:
//
//   - allow side: a Schemes-bearing allow rule never matched, so
//     CheckTarget step 3 ("policy allow rules exist and none match")
//     blocked every connection — including the example rule published
//     verbatim in internal/mcp/resources/help_security.md.
//   - deny side: a Schemes-bearing deny rule never matched, so the
//     connection sailed through the host-level gate.
//
// The scheme is now derived from Envelope.Context.TLS, which carries the
// same transport-confidentiality meaning the CONNECT / plain-HTTP forward
// handler gates already express with their "https" / "http" literals.
func TestHostScopeStep_SchemeDerivedFromTLS(t *testing.T) {
	// tlsOn is a minimal non-nil snapshot: HostScopeStep only tests the
	// pointer for nil-ness and never reads a field, so the zero value is a
	// faithful stand-in for "a TLS layer is in the stack".
	tlsOn := &envelope.TLSSnapshot{}

	tests := []struct {
		name         string
		policyAllows []connector.TargetRule
		policyDenies []connector.TargetRule
		agentAllows  []connector.TargetRule
		agentDenies  []connector.TargetRule
		targetHost   string
		tls          *envelope.TLSSnapshot
		msg          envelope.Message
		wantAction   Action
	}{
		{
			// The verbatim allow rule from help_security.md. Pre-fix this
			// returned Respond + a synthetic 403 on every request, so an
			// operator who copied our own documentation proxied nothing.
			name: "documented https allow rule matches a TLS connection",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Ports: []int{443}, Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        tlsOn,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			// Deny side, raw TCP: there is no HTTPScopeStep backstop for a
			// RawMessage, so a deny missed here is a deny missed entirely.
			name: "http deny rule matches a plaintext connection",
			policyDenies: []connector.TargetRule{
				{Hostname: "169.254.169.254", Schemes: []string{"http"}},
			},
			targetHost: "169.254.169.254:80",
			tls:        nil,
			msg:        &envelope.RawMessage{Bytes: []byte("GET / HTTP/1.1\r\n")},
			wantAction: Drop,
		},
		{
			// Negative control: the derivation must not degenerate into
			// "always allow". A plaintext connection still fails an
			// https-only allow rule. This case holds both before and after
			// the fix — it pins the direction of the derivation.
			name: "https allow rule still blocks a plaintext connection",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Ports: []int{443}, Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        nil,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Respond,
		},
		{
			// Mirror of the negative control on the deny axis: an
			// https-only deny rule must not fire on a plaintext leg.
			name: "https deny rule does not fire on a plaintext connection",
			policyDenies: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        nil,
			msg:        &envelope.RawMessage{Bytes: []byte("hello")},
			wantAction: Continue,
		},
		{
			name: "http allow rule matches a plaintext connection",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Ports: []int{80}, Schemes: []string{"http"}},
			},
			targetHost: "api.target.com:80",
			tls:        nil,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			name: "https deny rule matches a TLS connection",
			policyDenies: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        tlsOn,
			msg:        &envelope.RawMessage{Bytes: []byte("hello")},
			wantAction: Drop,
		},
		{
			// Schemes matching is case-insensitive (containsStringFold);
			// the derived token is lowercase, so an operator who wrote
			// "HTTPS" must still match.
			name: "uppercase scheme token in the rule still matches",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"HTTPS"}},
			},
			targetHost: "api.target.com:443",
			tls:        tlsOn,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			// A rule with no Schemes condition must be completely
			// unaffected by the derivation (len(rule.Schemes) == 0 short-
			// circuits matchTargetRule's scheme test).
			name: "rule without Schemes is unaffected on a TLS connection",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com"},
			},
			targetHost: "api.target.com:443",
			tls:        tlsOn,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			name: "rule without Schemes is unaffected on a plaintext connection",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com"},
			},
			targetHost: "api.target.com:80",
			tls:        nil,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			// TargetHost without a port: SplitHostPort fails, port stays 0,
			// and the scheme derivation must still apply.
			name: "bare hostname still derives the scheme",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"https"}},
			},
			targetHost: "api.target.com",
			tls:        tlsOn,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			// The Agent Layer shares matchTargetRule, so it inherits the
			// same fix.
			name: "agent allow rule with Schemes matches a TLS connection",
			agentAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        tlsOn,
			msg:        &envelope.HTTPMessage{Method: "GET", Path: "/"},
			wantAction: Continue,
		},
		{
			name: "agent deny rule with Schemes matches a plaintext connection",
			agentDenies: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"http"}},
			},
			targetHost: "api.target.com:80",
			tls:        nil,
			msg:        &envelope.RawMessage{Bytes: []byte("hello")},
			wantAction: Drop,
		},
		{
			// Terminator shape split: a blocked non-HTTP envelope keeps the
			// legacy silent Drop even though the scope decision itself is
			// Message-agnostic (USK-829 D2-D5).
			name: "blocked raw envelope drops instead of responding",
			policyAllows: []connector.TargetRule{
				{Hostname: "api.target.com", Schemes: []string{"https"}},
			},
			targetHost: "api.target.com:443",
			tls:        nil,
			msg:        &envelope.RawMessage{Bytes: []byte("hello")},
			wantAction: Drop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(tt.policyAllows, tt.policyDenies)
			if tt.agentAllows != nil || tt.agentDenies != nil {
				if err := scope.SetAgentRules(tt.agentAllows, tt.agentDenies); err != nil {
					t.Fatalf("SetAgentRules: %v", err)
				}
			}
			step := NewHostScopeStep(scope)

			env := &envelope.Envelope{
				Context: envelope.EnvelopeContext{
					TargetHost: tt.targetHost,
					TLS:        tt.tls,
				},
				Message: tt.msg,
			}
			r := step.Process(context.Background(), env)

			if r.Action != tt.wantAction {
				t.Fatalf("got action %v, want %v", r.Action, tt.wantAction)
			}
			switch tt.wantAction {
			case Continue:
				// Result is comparable, so pin the whole value: a
				// continuing scope check must not leave an Envelope
				// replacement, a Response, or a BlockedBy behind.
				if r != (Result{}) {
					t.Errorf("Continue: got %+v, want the zero Result", r)
				}
			case Drop, Respond:
				if r.BlockedBy != BlockedByTargetScope {
					t.Errorf("blocked: BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
				}
			}
			switch tt.wantAction {
			case Respond:
				if r.Response == nil {
					t.Fatal("Respond: Response is nil; expected synthetic 403 envelope")
				}
				respMsg, ok := r.Response.Message.(*envelope.HTTPMessage)
				if !ok {
					t.Fatalf("Respond: Response.Message type = %T, want *HTTPMessage", r.Response.Message)
				}
				if respMsg.Status != 403 {
					t.Errorf("Respond: status = %d, want 403", respMsg.Status)
				}
			case Drop:
				if r.Response != nil {
					t.Error("Drop: Response is non-nil; non-HTTP envelopes keep the silent Drop")
				}
			}
		})
	}
}

// TestHostScopeStep_SchemeDerivation_ShortCircuits pins the two early
// returns that precede the scheme derivation: a nil scope and an empty
// TargetHost both continue regardless of TLS state, so USK-1081 cannot
// have introduced a scope check where there was none.
func TestHostScopeStep_SchemeDerivation_ShortCircuits(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "api.target.com", Schemes: []string{"http"}},
	}, nil)

	tests := []struct {
		name       string
		step       *HostScopeStep
		targetHost string
		tls        *envelope.TLSSnapshot
	}{
		{"nil scope with TLS", NewHostScopeStep(nil), "api.target.com:443", &envelope.TLSSnapshot{}},
		{"nil scope without TLS", NewHostScopeStep(nil), "api.target.com:80", nil},
		{"empty TargetHost with TLS", NewHostScopeStep(scope), "", &envelope.TLSSnapshot{}},
		{"empty TargetHost without TLS", NewHostScopeStep(scope), "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &envelope.Envelope{
				Context: envelope.EnvelopeContext{
					TargetHost: tt.targetHost,
					TLS:        tt.tls,
				},
				Message: &envelope.HTTPMessage{Method: "GET", Path: "/"},
			}
			r := tt.step.Process(context.Background(), env)
			if r.Action != Continue {
				t.Errorf("got action %v, want Continue", r.Action)
			}
		})
	}
}
