package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestHTTPScopeStep_WithinScope(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	step := NewHTTPScopeStep(scope)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/api/users",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WithinScope: got action %v, want Continue", result.Action)
	}
}

func TestHTTPScopeStep_OutsideScope(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHTTPScopeStep(scope)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "blocked.com",
		Path:      "/",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("OutsideScope: got action %v, want Drop", result.Action)
	}
}

func TestHTTPScopeStep_ReceiveDirection_Skip(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHTTPScopeStep(scope)

	msg := &envelope.HTTPMessage{
		Status:       200,
		StatusReason: "OK",
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("ReceiveDirection: got action %v, want Continue", result.Action)
	}
}

func TestHTTPScopeStep_RawMessage_PassThrough(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	step := NewHTTPScopeStep(scope)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("hello")},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("RawMessage: got action %v, want Continue", result.Action)
	}
}

func TestHTTPScopeStep_NilScope(t *testing.T) {
	step := NewHTTPScopeStep(nil)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "anything.com",
		Path:      "/",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilScope: got action %v, want Continue", result.Action)
	}
}

func TestHTTPScopeStep_NoRules(t *testing.T) {
	scope := connector.NewTargetScope()
	step := NewHTTPScopeStep(scope)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "anything.com",
		Path:      "/",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NoRules: got action %v, want Continue", result.Action)
	}
}

func TestHTTPScopeStep_AuthorityWithPort(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "example.com", Ports: []int{8080}},
	}, nil)
	step := NewHTTPScopeStep(scope)

	tests := []struct {
		name      string
		authority string
		want      Action
	}{
		{"allowed port", "example.com:8080", Continue},
		{"blocked port", "example.com:9090", Drop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    "https",
				Authority: tt.authority,
				Path:      "/",
			}
			env := &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Message:   msg,
			}

			result := step.Process(context.Background(), env)
			if result.Action != tt.want {
				t.Errorf("%s: got action %v, want %v", tt.name, result.Action, tt.want)
			}
		})
	}
}

func TestHTTPScopeStep_AuthorityWithoutPort_DefaultPort(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "example.com", Ports: []int{443}},
	}, nil)
	step := NewHTTPScopeStep(scope)

	tests := []struct {
		name      string
		scheme    string
		authority string
		want      Action
	}{
		{"https default 443 allowed", "https", "example.com", Continue},
		{"http default 80 blocked", "http", "example.com", Drop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    tt.scheme,
				Authority: tt.authority,
				Path:      "/",
			}
			env := &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Message:   msg,
			}

			result := step.Process(context.Background(), env)
			if result.Action != tt.want {
				t.Errorf("%s: got action %v, want %v", tt.name, result.Action, tt.want)
			}
		})
	}
}

func TestHTTPScopeStep_PathBasedScope(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "example.com", PathPrefix: "/api/"},
	}, nil)
	step := NewHTTPScopeStep(scope)

	tests := []struct {
		name string
		path string
		want Action
	}{
		{"allowed path", "/api/users", Continue},
		{"blocked path", "/admin/settings", Drop},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    "https",
				Authority: "example.com",
				Path:      tt.path,
			}
			env := &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Message:   msg,
			}

			result := step.Process(context.Background(), env)
			if result.Action != tt.want {
				t.Errorf("%s: got action %v, want %v", tt.name, result.Action, tt.want)
			}
		})
	}
}

func TestDefaultPortForScheme(t *testing.T) {
	tests := []struct {
		scheme string
		want   int
	}{
		{"https", 443},
		{"http", 80},
		{"ws", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := defaultPortForScheme(tt.scheme)
		if got != tt.want {
			t.Errorf("defaultPortForScheme(%q) = %d, want %d", tt.scheme, got, tt.want)
		}
	}
}
