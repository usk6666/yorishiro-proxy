package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

func newTestSafetyEngine(t *testing.T) *httprules.SafetyEngine {
	t.Helper()
	e := httprules.NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSafetyStep_DangerousSQL_Drop(t *testing.T) {
	engine := newTestSafetyEngine(t)
	step := NewSafetyStep(engine, nil, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "POST",
		Scheme: "https",
		Path:   "/api/query",
		Body:   []byte("DROP TABLE users"),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("DangerousSQL: got action %v, want Drop", result.Action)
	}
}

func TestSafetyStep_SafeRequest_Continue(t *testing.T) {
	engine := newTestSafetyEngine(t)
	step := NewSafetyStep(engine, nil, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "GET",
		Scheme: "https",
		Path:   "/api/users",
		Body:   []byte(`{"name": "alice"}`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("SafeRequest: got action %v, want Continue", result.Action)
	}
}

func TestSafetyStep_ReceiveDirection_Skip(t *testing.T) {
	engine := newTestSafetyEngine(t)
	step := NewSafetyStep(engine, nil, nil, nil)

	// Even a dangerous body in Receive direction should pass through.
	msg := &envelope.HTTPMessage{
		Status:       200,
		StatusReason: "OK",
		Body:         []byte("DROP TABLE users"),
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

func TestSafetyStep_RawMessage_PassThrough(t *testing.T) {
	engine := newTestSafetyEngine(t)
	step := NewSafetyStep(engine, nil, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("DROP TABLE users")},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("RawMessage: got action %v, want Continue", result.Action)
	}
}

func TestSafetyStep_NilEngine(t *testing.T) {
	step := NewSafetyStep(nil, nil, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "POST",
		Path:   "/",
		Body:   []byte("DROP TABLE users"),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilEngine: got action %v, want Continue", result.Action)
	}
}

// ---------------------------------------------------------------------------
// WS / gRPC dispatch tests (USK-648).
// ---------------------------------------------------------------------------

func newTestWSSafetyEngine(t *testing.T) *wsrules.SafetyEngine {
	t.Helper()
	e := wsrules.NewSafetyEngine()
	pat, err := common.CompilePattern(`(?i)password=`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:      "ws:password-leak",
		Name:    "password in payload",
		Pattern: pat,
		Targets: []common.Target{wsrules.TargetPayload},
	})
	return e
}

func newTestGRPCSafetyEngine(t *testing.T) *grpcrules.SafetyEngine {
	t.Helper()
	e := grpcrules.NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSafetyStep_WS_DangerousPayload_Drop(t *testing.T) {
	wsEngine := newTestWSSafetyEngine(t)
	step := NewSafetyStep(nil, wsEngine, nil, nil)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`{"login":"admin","password=hunter2"}`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("WS_Dangerous: got action %v, want Drop", result.Action)
	}
}

func TestSafetyStep_WS_SafePayload_Continue(t *testing.T) {
	wsEngine := newTestWSSafetyEngine(t)
	step := NewSafetyStep(nil, wsEngine, nil, nil)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`{"hello":"world"}`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_Safe: got action %v, want Continue", result.Action)
	}
}

func TestSafetyStep_WS_ReceiveDirection_Skip(t *testing.T) {
	wsEngine := newTestWSSafetyEngine(t)
	step := NewSafetyStep(nil, wsEngine, nil, nil)

	// Receive direction must skip the SafetyEngine entirely (top-level
	// Send-only gate).
	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`password=hunter2`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_Receive: got action %v, want Continue", result.Action)
	}
}

func TestSafetyStep_WS_NilEngine(t *testing.T) {
	step := NewSafetyStep(nil, nil, nil, nil)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`password=hunter2`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_NilEngine: got action %v, want Continue", result.Action)
	}
}

func TestSafetyStep_GRPCData_DangerousPayload_Drop(t *testing.T) {
	grpcEngine := newTestGRPCSafetyEngine(t)
	step := NewSafetyStep(nil, nil, grpcEngine, nil)

	msg := &envelope.GRPCDataMessage{
		Service: "Admin",
		Method:  "Query",
		Payload: []byte("DROP TABLE users"),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("GRPCData_Dangerous: got action %v, want Drop", result.Action)
	}
}

func TestSafetyStep_GRPCStart_Continue(t *testing.T) {
	grpcEngine := newTestGRPCSafetyEngine(t)
	step := NewSafetyStep(nil, nil, grpcEngine, nil)

	msg := &envelope.GRPCStartMessage{
		Service: "Greeter",
		Method:  "SayHello",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCStart: got action %v, want Continue", result.Action)
	}
}

// TestSafetyStep_GRPCEnd_Send_Skip verifies GRPCEndMessage on Send is skipped
// entirely (no SafetyEngine call) — End carries no Send-side user content.
// The test wires a SafetyEngine that would otherwise drop on metadata
// matching DROP TABLE; if Skip wasn't honoured the test would fail.
func TestSafetyStep_GRPCEnd_Send_Skip(t *testing.T) {
	grpcEngine := grpcrules.NewSafetyEngine()
	pat, err := common.CompilePattern(`(?i)attack`)
	if err != nil {
		t.Fatal(err)
	}
	grpcEngine.AddRule(common.CompiledRule{
		ID:      "grpc:trailer-leak",
		Name:    "leak in trailers",
		Pattern: pat,
		Targets: []common.Target{grpcrules.TargetMetadata},
	})
	step := NewSafetyStep(nil, nil, grpcEngine, nil)

	msg := &envelope.GRPCEndMessage{
		Trailers: []envelope.KeyValue{{Name: "x-leak", Value: "attack"}},
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCEnd_Send_Skip: got action %v, want Continue (End must skip SafetyEngine)", result.Action)
	}
}

func TestSafetyStep_GRPC_NilEngine(t *testing.T) {
	step := NewSafetyStep(nil, nil, nil, nil)

	msg := &envelope.GRPCDataMessage{
		Service: "Admin",
		Method:  "Query",
		Payload: []byte("DROP TABLE users"),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPC_NilEngine: got action %v, want Continue", result.Action)
	}
}

// TestSafetyStep_SSE_PassThrough verifies SSEMessage envelopes pass through
// silently even on Send direction (N7 scope-out: SSE is half-duplex
// Receive-only, so a Send envelope shouldn't normally exist, but if one
// does the dispatch must not panic).
func TestSafetyStep_SSE_PassThrough(t *testing.T) {
	httpEngine := newTestSafetyEngine(t)
	step := NewSafetyStep(httpEngine, nil, nil, nil)

	msg := &envelope.SSEMessage{Event: "msg", Data: "hello"}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolSSE,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("SSE_PassThrough: got action %v, want Continue", result.Action)
	}
}
