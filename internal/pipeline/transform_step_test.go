package pipeline

import (
	"context"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

func TestTransformStep_Request_AddHeader(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.SetRules([]httprules.TransformRule{{
		ID:          "add-header",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		ActionType:  httprules.TransformAddHeader,
		HeaderName:  "X-Proxy",
		HeaderValue: "yorishiro",
	}})
	step := NewTransformStep(engine, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "GET",
		Path:   "/",
		Headers: []envelope.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("got action %v, want Continue", result.Action)
	}
	if result.Envelope != nil {
		t.Error("expected nil Envelope (in-place mutation)")
	}

	// Check that the header was added in-place.
	found := false
	for _, h := range msg.Headers {
		if h.Name == "X-Proxy" && h.Value == "yorishiro" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected X-Proxy header to be added")
	}
}

func TestTransformStep_Response_AddHeader(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.SetRules([]httprules.TransformRule{{
		ID:          "add-resp-header",
		Enabled:     true,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformAddHeader,
		HeaderName:  "X-Inspected",
		HeaderValue: "true",
	}})
	step := NewTransformStep(engine, nil, nil)

	msg := &envelope.HTTPMessage{
		Status:       200,
		StatusReason: "OK",
		Headers: []envelope.KeyValue{
			{Name: "Content-Type", Value: "text/html"},
		},
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("got action %v, want Continue", result.Action)
	}

	found := false
	for _, h := range msg.Headers {
		if h.Name == "X-Inspected" && h.Value == "true" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected X-Inspected header to be added")
	}
}

func TestTransformStep_NoMatchingRule(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.SetRules([]httprules.TransformRule{{
		ID:          "resp-only",
		Enabled:     true,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformAddHeader,
		HeaderName:  "X-Resp",
		HeaderValue: "yes",
	}})
	step := NewTransformStep(engine, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "GET",
		Path:   "/",
		Headers: []envelope.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("got action %v, want Continue", result.Action)
	}

	// Headers should not be modified.
	if len(msg.Headers) != 1 {
		t.Errorf("expected 1 header, got %d", len(msg.Headers))
	}
}

func TestTransformStep_RawMessage_PassThrough(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.SetRules([]httprules.TransformRule{{
		ID:          "add-header",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		ActionType:  httprules.TransformAddHeader,
		HeaderName:  "X-Test",
		HeaderValue: "yes",
	}})
	step := NewTransformStep(engine, nil, nil)

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

func TestTransformStep_NilEngine(t *testing.T) {
	step := NewTransformStep(nil, nil, nil)

	msg := &envelope.HTTPMessage{
		Method: "GET",
		Path:   "/",
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

func TestTransformStep_WS_ReplacePayload(t *testing.T) {
	wsEngine := wsrules.NewTransformEngine()
	wsEngine.SetRules([]wsrules.TransformRule{{
		ID:             "ws-replace",
		Enabled:        true,
		Direction:      wsrules.DirectionBoth,
		ActionType:     wsrules.TransformReplacePayload,
		PayloadPattern: regexp.MustCompile(`alice`),
		PayloadReplace: []byte("bob"),
	}})
	step := NewTransformStep(nil, wsEngine, nil)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`{"name":"alice"}`),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_Replace: got action %v, want Continue", result.Action)
	}
	if string(msg.Payload) != `{"name":"bob"}` {
		t.Errorf("WS_Replace: payload = %q, want %q", msg.Payload, `{"name":"bob"}`)
	}
}

func TestTransformStep_WS_NilEngine(t *testing.T) {
	step := NewTransformStep(nil, nil, nil)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte("payload"),
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
	if string(msg.Payload) != "payload" {
		t.Errorf("WS_NilEngine: payload should be unchanged")
	}
}

func TestTransformStep_GRPCStart_AddMetadata(t *testing.T) {
	grpcEngine := grpcrules.NewTransformEngine()
	grpcEngine.SetRules([]grpcrules.TransformRule{{
		ID:            "grpc-add",
		Enabled:       true,
		Direction:     grpcrules.DirectionBoth,
		ActionType:    grpcrules.TransformAddMetadata,
		MetadataName:  "x-injected",
		MetadataValue: "yes",
	}})
	step := NewTransformStep(nil, nil, grpcEngine)

	msg := &envelope.GRPCStartMessage{
		Service: "Greeter",
		Method:  "SayHello",
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
		Raw:       []byte("snapshot"),
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCStart: got action %v, want Continue", result.Action)
	}

	found := false
	for _, kv := range msg.Metadata {
		if kv.Name == "x-injected" && kv.Value == "yes" {
			found = true
		}
	}
	if !found {
		t.Error("GRPCStart: expected x-injected metadata to be added")
	}
	// Engine clears env.Raw on commit so downstream Layer re-encodes.
	if env.Raw != nil {
		t.Error("GRPCStart: expected env.Raw cleared after Transform commit")
	}
}

func TestTransformStep_GRPCData_ReplacePayload(t *testing.T) {
	grpcEngine := grpcrules.NewTransformEngine()
	grpcEngine.SetRules([]grpcrules.TransformRule{{
		ID:             "grpc-replace",
		Enabled:        true,
		Direction:      grpcrules.DirectionBoth,
		ActionType:     grpcrules.TransformReplacePayload,
		PayloadPattern: regexp.MustCompile(`secret`),
		PayloadReplace: "redacted",
	}})
	step := NewTransformStep(nil, nil, grpcEngine)

	msg := &envelope.GRPCDataMessage{
		Service: "Greeter",
		Method:  "SayHello",
		Payload: []byte("the secret is foo"),
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCData: got action %v, want Continue", result.Action)
	}
	if string(msg.Payload) != "the redacted is foo" {
		t.Errorf("GRPCData: payload = %q", msg.Payload)
	}
}

func TestTransformStep_GRPCEnd_Receive_SetStatus(t *testing.T) {
	grpcEngine := grpcrules.NewTransformEngine()
	grpcEngine.SetRules([]grpcrules.TransformRule{{
		ID:          "grpc-status",
		Enabled:     true,
		Direction:   grpcrules.DirectionBoth,
		ActionType:  grpcrules.TransformSetStatus,
		StatusValue: 13, // INTERNAL
	}})
	step := NewTransformStep(nil, nil, grpcEngine)

	msg := &envelope.GRPCEndMessage{Status: 0}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCEnd_Receive: got action %v, want Continue", result.Action)
	}
	if msg.Status != 13 {
		t.Errorf("GRPCEnd_Receive: status = %d, want 13", msg.Status)
	}
}

// TestTransformStep_GRPCEnd_Send_PassThrough verifies the grpc-web Send-side
// End sentinel is filtered before TransformEnd runs (mirrors InterceptStep).
func TestTransformStep_GRPCEnd_Send_PassThrough(t *testing.T) {
	grpcEngine := grpcrules.NewTransformEngine()
	grpcEngine.SetRules([]grpcrules.TransformRule{{
		ID:          "grpc-status",
		Enabled:     true,
		Direction:   grpcrules.DirectionBoth,
		ActionType:  grpcrules.TransformSetStatus,
		StatusValue: 13,
	}})
	step := NewTransformStep(nil, nil, grpcEngine)

	msg := &envelope.GRPCEndMessage{Status: 0}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCEnd_Send: got action %v, want Continue", result.Action)
	}
	if msg.Status != 0 {
		t.Errorf("GRPCEnd_Send: status mutated to %d (expected 0 — Send sentinel must pass through)", msg.Status)
	}
}

func TestTransformStep_GRPC_NilEngine(t *testing.T) {
	step := NewTransformStep(nil, nil, nil)

	msg := &envelope.GRPCDataMessage{
		Service: "Greeter",
		Method:  "SayHello",
		Payload: []byte("body"),
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
	if string(msg.Payload) != "body" {
		t.Errorf("GRPC_NilEngine: payload should be unchanged")
	}
}

// TestTransformStep_SSE_PassThrough verifies SSEMessage envelopes pass through
// silently even when other engines are wired (N7 scope-out).
func TestTransformStep_SSE_PassThrough(t *testing.T) {
	httpEngine := httprules.NewTransformEngine()
	httpEngine.SetRules([]httprules.TransformRule{{
		ID:          "http-add",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		ActionType:  httprules.TransformAddHeader,
		HeaderName:  "X-Test",
		HeaderValue: "yes",
	}})
	wsEngine := wsrules.NewTransformEngine()
	grpcEngine := grpcrules.NewTransformEngine()
	step := NewTransformStep(httpEngine, wsEngine, grpcEngine)

	msg := &envelope.SSEMessage{Event: "msg", Data: "hello"}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Message:   msg,
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("SSE_PassThrough: got action %v, want Continue", result.Action)
	}
	if msg.Data != "hello" {
		t.Errorf("SSE_PassThrough: data should be unchanged")
	}
}
