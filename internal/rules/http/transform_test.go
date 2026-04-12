package http

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

func testTransformEnv(method, path, host string, headers []envelope.KeyValue, body []byte) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Method:    method,
		Path:      path,
		Authority: host,
		Headers:   headers,
		Body:      body,
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   envelope.EnvelopeContext{TargetHost: host + ":443"},
	}
	return env, msg
}

func TestTransformEngine_AddHeader(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformAddHeader, "X-Added", "value", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformEnv("GET", "/", "example.com", nil, nil)
	modified := e.TransformRequest(env, msg)

	if !modified {
		t.Error("expected modification")
	}
	if headerGet(msg.Headers, "X-Added") != "value" {
		t.Errorf("X-Added = %q, want value", headerGet(msg.Headers, "X-Added"))
	}
}

func TestTransformEngine_SetHeader(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformSetHeader, "Content-Type", "application/json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	headers := []envelope.KeyValue{
		{Name: "Content-Type", Value: "text/html"},
		{Name: "Content-Type", Value: "text/plain"},
	}
	env, msg := testTransformEnv("POST", "/", "example.com", headers, nil)
	e.TransformRequest(env, msg)

	// Should have exactly one Content-Type header.
	count := 0
	for _, h := range msg.Headers {
		if h.Name == "Content-Type" {
			count++
			if h.Value != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", h.Value)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected 1 Content-Type, got %d", count)
	}
}

func TestTransformEngine_RemoveHeader(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformRemoveHeader, "X-Remove", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	headers := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "X-Remove", Value: "bye"},
	}
	env, msg := testTransformEnv("GET", "/", "example.com", headers, nil)
	modified := e.TransformRequest(env, msg)

	if !modified {
		t.Error("expected modification")
	}
	if headerGet(msg.Headers, "X-Remove") != "" {
		t.Error("X-Remove should be deleted")
	}
	if len(msg.Headers) != 1 {
		t.Errorf("expected 1 header remaining, got %d", len(msg.Headers))
	}
}

func TestTransformEngine_ReplaceBody(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := []byte(`{"password": "secret123"}`)
	env, msg := testTransformEnv("POST", "/login", "example.com", nil, body)
	modified := e.TransformRequest(env, msg)

	if !modified {
		t.Error("expected modification")
	}
	if string(msg.Body) != `{"password": "[REDACTED]"}` {
		t.Errorf("body = %q", string(msg.Body))
	}
}

func TestTransformEngine_ReplaceBody_NilBody(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `test`, "replaced")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformEnv("GET", "/", "example.com", nil, nil)
	modified := e.TransformRequest(env, msg)

	if modified {
		t.Error("should not modify nil body")
	}
}

func TestTransformEngine_Priority_Order(t *testing.T) {
	e := NewTransformEngine()

	rule1, _ := CompileTransformRule("r1", 10, DirectionRequest, "", "", nil,
		TransformAddHeader, "X-Order", "second", "", "")
	rule2, _ := CompileTransformRule("r2", 1, DirectionRequest, "", "", nil,
		TransformAddHeader, "X-Order", "first", "", "")

	e.SetRules([]TransformRule{*rule1, *rule2})

	env, msg := testTransformEnv("GET", "/", "example.com", nil, nil)
	e.TransformRequest(env, msg)

	// Both should be added, priority 1 first (lower = earlier).
	if len(msg.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(msg.Headers))
	}
	if msg.Headers[0].Value != "first" {
		t.Errorf("first header = %q, want first", msg.Headers[0].Value)
	}
	if msg.Headers[1].Value != "second" {
		t.Errorf("second header = %q, want second", msg.Headers[1].Value)
	}
}

func TestTransformEngine_CRLF_Rejection(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformAddHeader, "X-Injected\r\nEvil", "value", "", "")
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformEnv("GET", "/", "example.com", nil, nil)
	modified := e.TransformRequest(env, msg)

	if modified {
		t.Error("CRLF in header name should be rejected")
	}
}

func TestTransformEngine_DirectionFilter(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformAddHeader, "X-Response", "yes", "", "")
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformEnv("GET", "/", "example.com", nil, nil)
	modified := e.TransformRequest(env, msg)

	if modified {
		t.Error("response rule should not apply to requests")
	}
}

func TestTransformEngine_HostCondition(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionRequest, `^target\.com$`, "", nil,
		TransformAddHeader, "X-Match", "yes", "", "")
	e.SetRules([]TransformRule{*rule})

	// Non-matching host.
	env, msg := testTransformEnv("GET", "/", "other.com", nil, nil)
	if e.TransformRequest(env, msg) {
		t.Error("should not match different host")
	}

	// Matching host.
	env2, msg2 := testTransformEnv("GET", "/", "target.com", nil, nil)
	if !e.TransformRequest(env2, msg2) {
		t.Error("should match target host")
	}
}

var _ = common.MaxPatternLength // use import
