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
