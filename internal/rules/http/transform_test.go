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

// testTransformResponseEnv builds a response envelope as the HTTP/1.x channel
// / httpaggregator would: Method/Path/Authority all empty per the
// HTTPMessage field-validity contract (see internal/envelope/http.go). Used
// by USK-824 regression tests to verify that direction:"response" and
// direction:"both" transform rules with request-only conditions
// (path_pattern, methods) do not silently fail to match.
func testTransformResponseEnv(status int, host string, headers []envelope.KeyValue, body []byte) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Status:  status,
		Headers: headers,
		Body:    body,
		// Method, Path, Authority intentionally empty: response envelopes
		// have these fields blank by spec.
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   envelope.EnvelopeContext{TargetHost: host + ":443"},
	}
	return env, msg
}

// TestTransformMatchResponse_PathPatternIgnored verifies the USK-824 fix:
// a transform rule with direction:"response" + path_pattern + a host_pattern
// that DOES match the response envelope's TargetHost must trigger. Without
// the fix, matchesConditions short-circuited on the empty Path field and the
// rule never fired on the response side.
func TestTransformMatchResponse_PathPatternIgnored(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse,
		`^example\.com$`, `^/headers$`, nil,
		TransformAddHeader, "X-Response-Tag", "yes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformResponseEnv(200, "example.com", nil, nil)
	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("USK-824: response with empty Path should not short-circuit on PathPattern")
	}
	if headerGet(msg.Headers, "X-Response-Tag") != "yes" {
		t.Errorf("X-Response-Tag = %q, want yes", headerGet(msg.Headers, "X-Response-Tag"))
	}
}

// TestTransformMatchResponse_MethodsIgnored is the parallel regression guard
// for the Methods request-only field. Response envelopes have Method=="", so
// an unconditional methods check would over-reject them.
func TestTransformMatchResponse_MethodsIgnored(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse,
		`^example\.com$`, "", []string{"GET", "POST"},
		TransformAddHeader, "X-Response-Tag", "yes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformResponseEnv(200, "example.com", nil, nil)
	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("USK-824: response with empty Method should not short-circuit on Methods")
	}
	if headerGet(msg.Headers, "X-Response-Tag") != "yes" {
		t.Errorf("X-Response-Tag = %q, want yes", headerGet(msg.Headers, "X-Response-Tag"))
	}
}

// TestTransformMatchResponse_HostPatternStillEnforced is the negative case: a
// host mismatch on the response side must still reject the rule even though
// path/method are skipped. Parallel to TestMatchResponse_HostPatternStillEnforced
// in intercept_test.go.
func TestTransformMatchResponse_HostPatternStillEnforced(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse,
		`^example\.com$`, `^/headers$`, nil,
		TransformAddHeader, "X-Response-Tag", "yes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := testTransformResponseEnv(200, "httpbin.org", nil, nil)
	if e.TransformResponse(context.Background(), env, msg) {
		t.Error("host mismatch should reject even when path is skipped")
	}
	if headerGet(msg.Headers, "X-Response-Tag") != "" {
		t.Errorf("X-Response-Tag should not be added on host mismatch")
	}
}

// TestTransformMatchRequest_PathPatternStillEnforced is the regression guard
// against the fix being too aggressive. Request-side matching of PathPattern
// must remain correct.
func TestTransformMatchRequest_PathPatternStillEnforced(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest,
		"", `^/api/`, nil,
		TransformAddHeader, "X-Match", "yes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Matching path.
	env, msg := testTransformEnv("GET", "/api/users", "example.com", nil, nil)
	if !e.TransformRequest(context.Background(), env, msg) {
		t.Error("regression: request-side PathPattern still applies, /api/users should match")
	}

	// Non-matching path.
	env2, msg2 := testTransformEnv("GET", "/web/index.html", "example.com", nil, nil)
	if e.TransformRequest(context.Background(), env2, msg2) {
		t.Error("regression: request-side PathPattern should still reject /web/index.html")
	}
}

// TestTransformMatchRequest_MethodsStillEnforced is the parallel regression
// guard for Methods on the request side.
func TestTransformMatchRequest_MethodsStillEnforced(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest,
		"", "", []string{"POST"},
		TransformAddHeader, "X-Match", "yes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Matching method.
	env, msg := testTransformEnv("POST", "/", "example.com", nil, nil)
	if !e.TransformRequest(context.Background(), env, msg) {
		t.Error("regression: request-side Methods still applies, POST should match")
	}

	// Non-matching method.
	env2, msg2 := testTransformEnv("GET", "/", "example.com", nil, nil)
	if e.TransformRequest(context.Background(), env2, msg2) {
		t.Error("regression: request-side Methods should still reject GET")
	}
}

// TestTransformMatchBoth_RequestPath_ResponseHost covers the canonical
// direction:"both" use case from USK-821 / USK-824: a rule that scopes
// requests by path while still firing on the response side via host alone.
// With the USK-824 fix, the request side matches by path+host and the
// response side matches by host alone (path skipped).
func TestTransformMatchBoth_RequestPath_ResponseHost(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionBoth,
		`^httpbin\.org$`, `^/headers$`, nil,
		TransformAddHeader, "X-Tag", "tagged", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Request side: path + host both check out.
	reqEnv, reqMsg := testTransformEnv("GET", "/headers", "httpbin.org", nil, nil)
	if !e.TransformRequest(context.Background(), reqEnv, reqMsg) {
		t.Error("request side: path+host should match")
	}
	if headerGet(reqMsg.Headers, "X-Tag") != "tagged" {
		t.Errorf("X-Tag = %q on request, want tagged", headerGet(reqMsg.Headers, "X-Tag"))
	}

	// Response side: only host left to evaluate (path skipped). Should match.
	respEnv, respMsg := testTransformResponseEnv(200, "httpbin.org", nil, nil)
	if !e.TransformResponse(context.Background(), respEnv, respMsg) {
		t.Error("USK-824: response side with direction:both should match by host alone")
	}
	if headerGet(respMsg.Headers, "X-Tag") != "tagged" {
		t.Errorf("X-Tag = %q on response, want tagged", headerGet(respMsg.Headers, "X-Tag"))
	}

	// Response side, host mismatch: still rejects.
	respEnv2, respMsg2 := testTransformResponseEnv(200, "example.com", nil, nil)
	if e.TransformResponse(context.Background(), respEnv2, respMsg2) {
		t.Error("response side: host mismatch should still reject")
	}

	// Request side, path mismatch: rejects (path still applies on Send).
	reqEnv2, reqMsg2 := testTransformEnv("GET", "/other", "httpbin.org", nil, nil)
	if e.TransformRequest(context.Background(), reqEnv2, reqMsg2) {
		t.Error("request side: path mismatch should reject")
	}
}

// TestTransformMatchResponse_BodyReplaceFires is the end-to-end behavioral
// proof of the USK-824 fix: a direction:"response" transform with
// path_pattern + a ReplaceBody action must rewrite the response body. Without
// the fix the rule never matches and the response body is unchanged.
func TestTransformMatchResponse_BodyReplaceFires(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse,
		`^example\.com$`, `^/secret$`, nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := []byte(`{"data": "secret123"}`)
	env, msg := testTransformResponseEnv(200, "example.com", nil, body)
	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("USK-824: response body should be rewritten despite empty Path")
	}
	if string(msg.Body) != `{"data": "[REDACTED]"}` {
		t.Errorf("msg.Body = %q, want redacted", string(msg.Body))
	}
}
