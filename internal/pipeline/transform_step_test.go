package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
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
	step := NewTransformStep(engine)

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
	step := NewTransformStep(engine)

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
	step := NewTransformStep(engine)

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
	step := NewTransformStep(engine)

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
	step := NewTransformStep(nil)

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
