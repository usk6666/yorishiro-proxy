package job

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestExpandEnvelopeTemplates_HTTPMessage(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{
			Method:    "§method§",
			Authority: "§host§",
			Path:      "/api/§version§",
			RawQuery:  "token=§token§",
			Headers: []envelope.KeyValue{
				{Name: "Authorization", Value: "Bearer §auth§"},
				{Name: "X-Custom", Value: "no-template"},
			},
			Body: []byte(`{"user":"§user§"}`),
		},
	}

	kvStore := map[string]string{
		"method":  "POST",
		"host":    "example.com",
		"version": "v2",
		"token":   "abc123",
		"auth":    "my-token",
		"user":    "admin",
	}

	err := ExpandEnvelopeTemplates(env, kvStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Method != "POST" {
		t.Errorf("Method: got %q, want %q", msg.Method, "POST")
	}
	if msg.Authority != "example.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "example.com")
	}
	if msg.Path != "/api/v2" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/api/v2")
	}
	if msg.RawQuery != "token=abc123" {
		t.Errorf("RawQuery: got %q, want %q", msg.RawQuery, "token=abc123")
	}
	if msg.Headers[0].Value != "Bearer my-token" {
		t.Errorf("Auth header: got %q, want %q", msg.Headers[0].Value, "Bearer my-token")
	}
	if msg.Headers[1].Value != "no-template" {
		t.Errorf("Custom header: got %q, want %q", msg.Headers[1].Value, "no-template")
	}
	if string(msg.Body) != `{"user":"admin"}` {
		t.Errorf("Body: got %q, want %q", msg.Body, `{"user":"admin"}`)
	}
}

func TestExpandEnvelopeTemplates_RawMessage(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.RawMessage{
			Bytes: []byte("GET /§path§ HTTP/1.1\r\nHost: §host§\r\n\r\n"),
		},
	}

	kvStore := map[string]string{
		"path": "admin",
		"host": "target.com",
	}

	err := ExpandEnvelopeTemplates(env, kvStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	expected := "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
	if string(msg.Bytes) != expected {
		t.Errorf("Bytes: got %q, want %q", msg.Bytes, expected)
	}
}

func TestExpandEnvelopeTemplates_UnknownVarsLeftAsIs(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{
			Path: "/§unknown§",
		},
	}

	err := ExpandEnvelopeTemplates(env, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Path != "/§unknown§" {
		t.Errorf("unknown var should be left as-is: got %q", msg.Path)
	}
}

func TestExpandEnvelopeTemplates_NilMessage(t *testing.T) {
	err := ExpandEnvelopeTemplates(&envelope.Envelope{}, map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("nil message should not error: %v", err)
	}
}

func TestExpandEnvelopeTemplates_NilEnvelope(t *testing.T) {
	err := ExpandEnvelopeTemplates(nil, map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("nil envelope should not error: %v", err)
	}
}

func TestExpandEnvelopeTemplates_EmptyKVStore(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{
			Path: "/§var§",
		},
	}
	err := ExpandEnvelopeTemplates(env, nil)
	if err != nil {
		t.Fatalf("empty kvStore should not error: %v", err)
	}
}

func TestExpandEnvelopeTemplates_NilBody(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{
			Method: "§method§",
			Body:   nil,
		},
	}
	err := ExpandEnvelopeTemplates(env, map[string]string{"method": "GET"})
	if err != nil {
		t.Fatalf("nil body should not error: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Method != "GET" {
		t.Errorf("Method: got %q", msg.Method)
	}
}
