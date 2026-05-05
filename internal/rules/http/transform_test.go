package http

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	e.TransformRequest(context.Background(), env, msg)

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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	e.TransformRequest(context.Background(), env, msg)

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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	modified := e.TransformRequest(context.Background(), env, msg)

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
	if e.TransformRequest(context.Background(), env, msg) {
		t.Error("should not match different host")
	}

	// Matching host.
	env2, msg2 := testTransformEnv("GET", "/", "target.com", nil, nil)
	if !e.TransformRequest(context.Background(), env2, msg2) {
		t.Error("should match target host")
	}
}

// TestTransformEngine_ReplaceBody_BodyBufferMaterializes verifies that a
// 12 MiB disk-backed BodyBuffer matching the Transform pattern is
// materialized via Bytes(ctx), replaced, and committed into msg.Body with
// the BodyBuffer released to nil (Transform commit contract, USK-631 /
// USK-633).
func TestTransformEngine_ReplaceBody_BodyBufferMaterializes(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Build a 12 MiB body with a needle near the middle.
	const payloadSize = 12 << 20
	needle := []byte("secret123")
	filler := bytes.Repeat([]byte("A"), payloadSize/2)
	payload := append(append([]byte(nil), filler...), needle...)
	payload = append(payload, filler...)

	bb, err := bodybuf.NewFile(t.TempDir(), "test-body", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Release backstop: if Transform commits it will be nil; if it fails
	// to commit we release here to avoid leaking the temp file.
	t.Cleanup(func() {
		// Transform Released+niled on commit; calling Release on the
		// returned (possibly nil) pointer is a no-op.
	})
	if _, err := bb.Write(payload); err != nil {
		t.Fatal(err)
	}

	env, msg := testTransformEnv("POST", "/api", "example.com", nil, nil)
	msg.BodyBuffer = bb

	modified := e.TransformRequest(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected Transform to report modified")
	}
	if msg.BodyBuffer != nil {
		t.Errorf("expected msg.BodyBuffer == nil after commit, got %p", msg.BodyBuffer)
	}
	if msg.Body == nil {
		t.Fatal("expected msg.Body non-nil after commit")
	}
	if bytes.Contains(msg.Body, []byte("secret123")) {
		t.Error("msg.Body still contains original needle; replacement failed")
	}
	if !bytes.Contains(msg.Body, []byte("[REDACTED]")) {
		t.Error("msg.Body missing replacement token")
	}
	// payload = 2*filler + needle; replacement: needle → "[REDACTED]".
	if want := len(payload) + len("[REDACTED]") - len("secret123"); len(msg.Body) != want {
		t.Errorf("body length = %d, want %d", len(msg.Body), want)
	}
}

// TestTransformEngine_ReplaceBody_NoMatchKeepsBodyBuffer verifies that when
// the regex does not match, Transform returns false and leaves BodyBuffer
// intact (no spurious Release, no msg.Body populated).
func TestTransformEngine_ReplaceBody_NoMatchKeepsBodyBuffer(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `nothing-matches-this`, "replaced")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	bb, err := bodybuf.NewFile(t.TempDir(), "test-body", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bb.Release() })
	if _, err := bb.Write([]byte("some body content")); err != nil {
		t.Fatal(err)
	}

	env, msg := testTransformEnv("POST", "/api", "example.com", nil, nil)
	msg.BodyBuffer = bb

	modified := e.TransformRequest(context.Background(), env, msg)
	if modified {
		t.Error("expected no modification when regex does not match")
	}
	if msg.BodyBuffer != bb {
		t.Errorf("BodyBuffer pointer changed on no-match path; got %p want %p", msg.BodyBuffer, bb)
	}
	if msg.Body != nil {
		t.Errorf("msg.Body = %q, want nil (buffer untouched)", msg.Body)
	}
}

// TestTransformEngine_ReplaceBody_CtxCancel_NoMutation verifies that a
// cancelled ctx during body materialization prevents any mutation and
// leaves the BodyBuffer intact.
func TestTransformEngine_ReplaceBody_CtxCancel_NoMutation(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	bb, err := bodybuf.NewFile(t.TempDir(), "test-body", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bb.Release() })
	if _, err := bb.Write([]byte("secret123")); err != nil {
		t.Fatal(err)
	}

	env, msg := testTransformEnv("POST", "/api", "example.com", nil, nil)
	msg.BodyBuffer = bb

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled: Bytes(ctx) must fail fast.

	modified := e.TransformRequest(ctx, env, msg)
	if modified {
		t.Error("expected no modification when ctx is cancelled")
	}
	if msg.BodyBuffer != bb {
		t.Error("BodyBuffer pointer changed on ctx-cancel path")
	}
	if msg.Body != nil {
		t.Errorf("msg.Body = %q, want nil on ctx-cancel", msg.Body)
	}
}

var _ = common.MaxPatternLength // use import
