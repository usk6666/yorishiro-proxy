package http1

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestBuildSendEnvelope_BasicFields(t *testing.T) {
	headers := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "Content-Type", Value: "application/json"},
	}
	body := []byte(`{"key":"value"}`)

	env := BuildSendEnvelope("POST", "https", "example.com", "/api/data", "q=1", headers, body)

	if env.Direction != envelope.Send {
		t.Errorf("Direction: got %v, want Send", env.Direction)
	}
	if env.Protocol != envelope.ProtocolHTTP {
		t.Errorf("Protocol: got %v, want %v", env.Protocol, envelope.ProtocolHTTP)
	}
	if env.FlowID == "" {
		t.Error("FlowID should be generated")
	}
	if env.Opaque != nil {
		t.Error("Opaque should be nil (triggers synthetic send path)")
	}
	if env.Raw != nil {
		t.Error("Raw should be nil (no wire-observed bytes for synthetic envelopes)")
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type: got %T, want *HTTPMessage", env.Message)
	}
	if msg.Method != "POST" {
		t.Errorf("Method: got %q, want %q", msg.Method, "POST")
	}
	if msg.Scheme != "https" {
		t.Errorf("Scheme: got %q, want %q", msg.Scheme, "https")
	}
	if msg.Authority != "example.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "example.com")
	}
	if msg.Path != "/api/data" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/api/data")
	}
	if msg.RawQuery != "q=1" {
		t.Errorf("RawQuery: got %q, want %q", msg.RawQuery, "q=1")
	}
	if len(msg.Headers) != 2 {
		t.Fatalf("Headers count: got %d, want 2", len(msg.Headers))
	}
	if msg.Headers[0].Name != "Host" || msg.Headers[0].Value != "example.com" {
		t.Errorf("Headers[0]: got %v", msg.Headers[0])
	}
	if string(msg.Body) != `{"key":"value"}` {
		t.Errorf("Body: got %q", msg.Body)
	}
}

func TestBuildSendEnvelope_MinimalFields(t *testing.T) {
	env := BuildSendEnvelope("GET", "http", "localhost", "/", "", nil, nil)

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Method != "GET" {
		t.Errorf("Method: got %q, want %q", msg.Method, "GET")
	}
	if msg.Headers != nil {
		t.Errorf("Headers: got %v, want nil", msg.Headers)
	}
	if msg.Body != nil {
		t.Errorf("Body: got %v, want nil", msg.Body)
	}
}

func TestBuildSendEnvelope_UniqueFlowIDs(t *testing.T) {
	env1 := BuildSendEnvelope("GET", "http", "a.com", "/", "", nil, nil)
	env2 := BuildSendEnvelope("GET", "http", "b.com", "/", "", nil, nil)

	if env1.FlowID == env2.FlowID {
		t.Error("each call should generate a unique FlowID")
	}
}
