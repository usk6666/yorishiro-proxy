package pipeline

import (
	"bytes"
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
	// USK-829: SafetyStep block on HTTPMessage now emits Respond +
	// synthetic 403 so the client receives a clean terminator instead
	// of hanging on a read timeout.
	if result.Action != Respond {
		t.Errorf("DangerousSQL: got action %v, want Respond (USK-829)", result.Action)
	}
	if result.BlockedBy != BlockedBySafetyFilter {
		t.Errorf("DangerousSQL: BlockedBy = %q, want %q", result.BlockedBy, BlockedBySafetyFilter)
	}
	if result.Response == nil {
		t.Fatal("DangerousSQL: Response is nil; expected synthetic 403 envelope")
	}
	if respMsg, ok := result.Response.Message.(*envelope.HTTPMessage); !ok {
		t.Fatalf("DangerousSQL: Response.Message type = %T, want *HTTPMessage", result.Response.Message)
	} else if respMsg.Status != 403 {
		t.Errorf("DangerousSQL: Response status = %d, want 403", respMsg.Status)
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
	if result.BlockedBy != BlockedBySafetyFilter {
		t.Errorf("WS_Dangerous: BlockedBy = %q, want %q", result.BlockedBy, BlockedBySafetyFilter)
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
	if result.BlockedBy != BlockedBySafetyFilter {
		t.Errorf("GRPCData_Dangerous: BlockedBy = %q, want %q", result.BlockedBy, BlockedBySafetyFilter)
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

// TestSafetyStep_HTTP_WireFidelity_OnDrop is the wire-fidelity guard
// (RFC-001 Principle 1) for the HTTP arm of SafetyStep. Even when the
// step returns Drop, env.Raw, msg.Body, msg.Headers, and the underlying
// byte slices must be byte-for-byte unchanged so the recorder captures
// the original wire bytes.
func TestSafetyStep_HTTP_WireFidelity_OnDrop(t *testing.T) {
	engine := newTestSafetyEngine(t)
	step := NewSafetyStep(engine, nil, nil, nil)

	bodyOriginal := []byte("DROP TABLE users -- payload")
	rawOriginal := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 27\r\n\r\nDROP TABLE users -- payload")
	headers := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "Content-Type", Value: "application/sql"},
	}
	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/api",
		Headers:   headers,
		Body:      bodyOriginal,
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Raw:       rawOriginal,
	}

	bodySnap := append([]byte(nil), bodyOriginal...)
	rawSnap := append([]byte(nil), rawOriginal...)
	headerSnap := append([]envelope.KeyValue(nil), headers...)

	// USK-829: HTTPMessage block now emits Respond + synthetic 403. The
	// wire-fidelity contract (RFC-001 Principle 1) still holds: the
	// original held envelope's Raw / Body / Headers must not be mutated.
	// The Response is a NEW envelope and is unrelated to the held env's
	// underlying bytes.
	if result := step.Process(context.Background(), env); result.Action != Respond {
		t.Fatalf("expected Respond action; got %v (rule precondition failed)", result.Action)
	}

	if !bytes.Equal(msg.Body, bodySnap) {
		t.Errorf("HTTPMessage.Body mutated after Respond: got %q, want %q", string(msg.Body), string(bodySnap))
	}
	if !bytes.Equal(bodyOriginal, bodySnap) {
		t.Errorf("underlying body slice mutated after Respond: got %q, want %q", string(bodyOriginal), string(bodySnap))
	}
	if !bytes.Equal(env.Raw, rawSnap) {
		t.Errorf("env.Raw mutated after Respond: got %q, want %q", string(env.Raw), string(rawSnap))
	}
	if !bytes.Equal(rawOriginal, rawSnap) {
		t.Errorf("underlying env.Raw slice mutated after Respond: got %q, want %q", string(rawOriginal), string(rawSnap))
	}
	for i := range msg.Headers {
		if msg.Headers[i] != headerSnap[i] {
			t.Errorf("Headers[%d] mutated after Respond: got %+v, want %+v", i, msg.Headers[i], headerSnap[i])
		}
	}
}

// TestSafetyStep_WS_WireFidelity_OnDrop is the wire-fidelity guard for
// the WebSocket arm. The WS engine has no mask method; this test locks
// in that even on Drop the WSMessage.Payload and env.Raw remain the
// original wire bytes.
func TestSafetyStep_WS_WireFidelity_OnDrop(t *testing.T) {
	wsEngine := newTestWSSafetyEngine(t)
	step := NewSafetyStep(nil, wsEngine, nil, nil)

	payloadOriginal := []byte(`{"login":"admin","password=hunter2"}`)
	rawOriginal := []byte("\x81\x24" + string(payloadOriginal)) // text frame, no mask
	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: payloadOriginal,
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
		Raw:       rawOriginal,
	}

	payloadSnap := append([]byte(nil), payloadOriginal...)
	rawSnap := append([]byte(nil), rawOriginal...)

	if result := step.Process(context.Background(), env); result.Action != Drop {
		t.Fatalf("expected Drop action; got %v (rule precondition failed)", result.Action)
	}

	if !bytes.Equal(msg.Payload, payloadSnap) {
		t.Errorf("WSMessage.Payload mutated after Drop: got %q, want %q", string(msg.Payload), string(payloadSnap))
	}
	if !bytes.Equal(payloadOriginal, payloadSnap) {
		t.Errorf("underlying payload slice mutated after Drop: got %q, want %q", string(payloadOriginal), string(payloadSnap))
	}
	if !bytes.Equal(env.Raw, rawSnap) {
		t.Errorf("env.Raw mutated after Drop: got %q, want %q", string(env.Raw), string(rawSnap))
	}
}

// TestSafetyStep_GRPC_WireFidelity_OnDrop is the wire-fidelity guard for
// the gRPC arm. On Drop the GRPCDataMessage.Payload and env.Raw must
// remain the original wire bytes.
func TestSafetyStep_GRPC_WireFidelity_OnDrop(t *testing.T) {
	grpcEngine := newTestGRPCSafetyEngine(t)
	step := NewSafetyStep(nil, nil, grpcEngine, nil)

	payloadOriginal := []byte("DROP TABLE users")
	rawOriginal := []byte("\x00\x00\x00\x00\x10DROP TABLE users") // LPM-framed
	msg := &envelope.GRPCDataMessage{
		Service:    "Admin",
		Method:     "Query",
		Payload:    payloadOriginal,
		WireLength: uint32(len(payloadOriginal)),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
		Raw:       rawOriginal,
	}

	payloadSnap := append([]byte(nil), payloadOriginal...)
	rawSnap := append([]byte(nil), rawOriginal...)

	if result := step.Process(context.Background(), env); result.Action != Drop {
		t.Fatalf("expected Drop action; got %v (rule precondition failed)", result.Action)
	}

	if !bytes.Equal(msg.Payload, payloadSnap) {
		t.Errorf("GRPCDataMessage.Payload mutated after Drop: got %q, want %q", string(msg.Payload), string(payloadSnap))
	}
	if !bytes.Equal(payloadOriginal, payloadSnap) {
		t.Errorf("underlying payload slice mutated after Drop: got %q, want %q", string(payloadOriginal), string(payloadSnap))
	}
	if !bytes.Equal(env.Raw, rawSnap) {
		t.Errorf("env.Raw mutated after Drop: got %q, want %q", string(env.Raw), string(rawSnap))
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
