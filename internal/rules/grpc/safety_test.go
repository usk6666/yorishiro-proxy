package grpc

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

func TestSafetyEngine_PresetReuse_DestructiveSQL_OnPayload(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// destructive-sql preset uses common.TargetBody. The gRPC engine
	// must remap that to TargetPayload data extraction.
	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("DROP TABLE users"))
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation from preset on payload")
	}
	if v.Target != "payload" {
		t.Errorf("Target = %q, want payload", v.Target)
	}
	if v.RuleID != "destructive-sql:drop" {
		t.Errorf("RuleID = %q, want destructive-sql:drop", v.RuleID)
	}
}

func TestSafetyEngine_TargetPayload_BlocksMatch(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`(?i)password=`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:password-leak",
		Name:    "Password leak",
		Pattern: re,
		Targets: []common.Target{TargetPayload},
	})

	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("payload password=hunter2"))
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation")
	}
	if v.Target != "payload" {
		t.Errorf("Target = %q, want payload", v.Target)
	}
}

func TestSafetyEngine_TargetMetadata_OnStart(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`Bearer\s+[a-z0-9]+`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:auth-leak",
		Name:    "Auth header leak",
		Pattern: re,
		Targets: []common.Target{TargetMetadata},
	})

	metadata := []envelope.KeyValue{{Name: "authorization", Value: "Bearer abcdef123"}}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on metadata")
	}
	if v.Target != "metadata" {
		t.Errorf("Target = %q, want metadata", v.Target)
	}
}

func TestSafetyEngine_TargetMetadata_OnEndTrailers(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`internal-trace=`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:trace-leak",
		Pattern: re,
		Targets: []common.Target{TargetMetadata},
	})

	msg := &envelope.GRPCEndMessage{
		Status:   0,
		Trailers: []envelope.KeyValue{{Name: "x-debug", Value: "internal-trace=abc"}},
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on End trailers")
	}
	if v.Target != "metadata" {
		t.Errorf("Target = %q, want metadata (trailers)", v.Target)
	}
}

func TestSafetyEngine_TargetService(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`forbidden\.`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:forbidden-svc",
		Pattern: re,
		Targets: []common.Target{TargetService},
	})

	env, msg := makeStartEnv(envelope.Send, "forbidden.AdminService", "Reset", nil)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on service name")
	}
	if v.Target != "service" {
		t.Errorf("Target = %q, want service", v.Target)
	}
}

func TestSafetyEngine_TargetMethod(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Delete`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:dangerous-verb",
		Pattern: re,
		Targets: []common.Target{TargetMethod},
	})

	env, msg := makeStartEnv(envelope.Send, "svc", "DeleteAllUsers", nil)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on method name")
	}
	if v.Target != "method" {
		t.Errorf("Target = %q, want method", v.Target)
	}
}

func TestSafetyEngine_NoMatch_ReturnsNil(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("benign payload"))
	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Errorf("unexpected violation: %+v", v)
	}
}

func TestSafetyEngine_CheckInputAll(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	env, msg := makeDataEnv(envelope.Send, "svc", "M",
		[]byte("DROP TABLE users; TRUNCATE TABLE sessions"))
	violations := e.CheckInputAll(context.Background(), env, msg)
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d", len(violations))
	}
}

func TestSafetyEngine_RuleCount(t *testing.T) {
	e := NewSafetyEngine()
	if e.RuleCount() != 0 {
		t.Errorf("expected 0, got %d", e.RuleCount())
	}
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() == 0 {
		t.Error("expected non-zero after preset load")
	}
}

func TestSafetyEngine_SetRules(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`x`)
	e.SetRules([]common.CompiledRule{
		{ID: "a", Pattern: re, Targets: []common.Target{TargetPayload}},
		{ID: "b", Pattern: re, Targets: []common.Target{TargetPayload}},
	})
	if e.RuleCount() != 2 {
		t.Errorf("RuleCount = %d, want 2", e.RuleCount())
	}
	e.SetRules(nil)
	if e.RuleCount() != 0 {
		t.Errorf("RuleCount after nil = %d, want 0", e.RuleCount())
	}
}

func TestSafetyEngine_NilEnvOrMsg(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`anything`)
	e.AddRule(common.CompiledRule{
		ID: "r1", Pattern: re, Targets: []common.Target{TargetPayload},
	})

	if v := e.CheckInput(context.Background(), nil, nil); v != nil {
		t.Error("nil env/msg must not panic and must return nil")
	}
}

func TestSafetyEngine_CheckMetadataTarget(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Bearer\s`)
	rule := &common.CompiledRule{
		ID:      "custom:bearer",
		Name:    "Bearer token",
		Pattern: re,
	}

	metadata := []envelope.KeyValue{{Name: "Authorization", Value: "Bearer xyz"}}
	v := e.CheckMetadataTarget(metadata, "authorization", rule)
	if v == nil {
		t.Fatal("expected violation on Authorization metadata")
	}
	if v.Target != "metadata:authorization" {
		t.Errorf("Target = %q", v.Target)
	}

	// Missing metadata returns nil.
	if v := e.CheckMetadataTarget(metadata, "x-missing", rule); v != nil {
		t.Errorf("expected nil for missing metadata, got %+v", v)
	}
}

func TestAllMetadataString_NoNormalization(t *testing.T) {
	metadata := []envelope.KeyValue{
		{Name: "Authorization", Value: "Bearer x"},
		{Name: "x-trace-id", Value: "abc"},
		{Name: "X-UPPER", Value: "CAPS"},
	}
	got := allMetadataString(metadata)
	want := "Authorization: Bearer x\nx-trace-id: abc\nX-UPPER: CAPS\n"
	if got != want {
		t.Errorf("allMetadataString = %q, want %q", got, want)
	}
}
