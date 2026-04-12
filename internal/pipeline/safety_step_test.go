package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
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
	step := NewSafetyStep(engine, nil)

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
	step := NewSafetyStep(engine, nil)

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
	step := NewSafetyStep(engine, nil)

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
	step := NewSafetyStep(engine, nil)

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
	step := NewSafetyStep(nil, nil)

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
