package grpc

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// wireFormGRPCWebStart builds a Start exactly as layer/grpcweb now produces
// it for a gRPC-Web request over HTTP/1.x (USK-1139): Path is the wire-form
// request path, and Service / Method are split from that wire form without
// percent-decoding.
func wireFormGRPCWebStart(wirePath, service, method string) (*envelope.Envelope, *envelope.GRPCStartMessage) {
	msg := &envelope.GRPCStartMessage{
		Service:   service,
		Method:    method,
		Scheme:    "https",
		Authority: "api.example",
		Path:      wirePath,
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   msg,
	}
	return env, msg
}

// TestSafetyEngine_WirePath_EitherForm pins the USK-1139 either-form
// contract on the gRPC Input Safety engine: a deny rule matches when either
// the wire form or its single-pass percent-decoded form matches, so a
// percent-encoded :path cannot slip past a rule that the decoded form
// (what the upstream server acts on) would trip.
func TestSafetyEngine_WirePath_EitherForm(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		target  common.Target
		path    string
		service string
		method  string
	}{
		{
			name:    "url target, encoded mkfs in method segment",
			pattern: `mkfs\.`,
			target:  common.TargetURL,
			path:    "/pkg.Svc/%6dkfs.ext4",
			service: "pkg.Svc",
			method:  "%6dkfs.ext4",
		},
		{
			name:    "method target, encoded first letter",
			pattern: `^Delete$`,
			target:  TargetMethod,
			path:    "/pkg.Svc/%44elete",
			service: "pkg.Svc",
			method:  "%44elete",
		},
		{
			name:    "service target, encoded service",
			pattern: `^admin\.Danger$`,
			target:  TargetService,
			path:    "/%61dmin.Danger/Run",
			service: "%61dmin.Danger",
			method:  "Run",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewSafetyEngine()
			re, err := common.CompilePattern(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			e.AddRule(common.CompiledRule{
				ID:      "custom:either-form",
				Name:    "either form",
				Pattern: re,
				Targets: []common.Target{tt.target},
			})
			env, msg := wireFormGRPCWebStart(tt.path, tt.service, tt.method)
			if v := e.CheckInput(context.Background(), env, msg); v == nil {
				t.Fatalf("CheckInput(path=%q) = nil, want a violation (decoded form matches %q)", tt.path, tt.pattern)
			}
			if got := e.CheckInputAll(context.Background(), env, msg); len(got) != 1 {
				t.Errorf("CheckInputAll = %d violations, want 1", len(got))
			}
			// Wire fidelity: matching must not rewrite the message.
			if msg.Path != tt.path || msg.Service != tt.service || msg.Method != tt.method {
				t.Errorf("message mutated: path=%q service=%q method=%q", msg.Path, msg.Service, msg.Method)
			}
		})
	}
}

// TestSafetyEngine_WirePath_PresetOnEncodedPath covers the preset reuse
// contract (destructive-os-command declares the url target) against an
// encoded :path.
func TestSafetyEngine_WirePath_PresetOnEncodedPath(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveOSCommand); err != nil {
		t.Fatal(err)
	}
	env, msg := wireFormGRPCWebStart("/pkg.Svc/%6dkfs.ext4", "pkg.Svc", "%6dkfs.ext4")
	if v := e.CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("destructive-os-command preset did not block an encoded mkfs :path")
	}
}

// TestSafetyEngine_WirePath_MethodOnDataMessage covers the Data arm: the
// Data envelope carries the same wire-form Service / Method.
func TestSafetyEngine_WirePath_MethodOnDataMessage(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Delete$`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:delete",
		Pattern: re,
		Targets: []common.Target{TargetMethod},
	})
	env, msg := makeDataEnv(envelope.Send, "pkg.Svc", "%44elete", []byte("x"))
	if v := e.CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("method rule did not match an encoded method on a Data envelope")
	}
}

// TestSafetyEngine_WirePath_NoFalsePositive keeps the decoded comparison
// from matching something neither form contains.
func TestSafetyEngine_WirePath_NoFalsePositive(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Delete$`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:delete",
		Pattern: re,
		Targets: []common.Target{TargetMethod, common.TargetURL},
	})
	env, msg := wireFormGRPCWebStart("/pkg.Svc/%47et", "pkg.Svc", "%47et")
	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Fatalf("unexpected violation %+v", v)
	}
}
