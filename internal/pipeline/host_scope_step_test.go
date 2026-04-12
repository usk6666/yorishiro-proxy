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
