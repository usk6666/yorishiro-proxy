package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"strconv"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
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
// Context.RequestPath / RequestMethod are also empty, simulating the
// "no paired request data" case that preserves the USK-824 fix
// (knowable=false → request-only checks skipped).
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

// testTransformResponseEnvPaired builds a response envelope as the HTTP/1.x
// channel / httpaggregator does post-USK-833: the producing Layer has
// threaded the paired request's path/method/query forward onto
// EnvelopeContext.RequestPath/Method/RawQuery so response-phase rule
// matching can gate on the paired request's identity.
func testTransformResponseEnvPaired(status int, host string, headers []envelope.KeyValue, body []byte, method, path, rawQuery string) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Status:  status,
		Headers: headers,
		Body:    body,
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			TargetHost:      host + ":443",
			RequestMethod:   method,
			RequestPath:     path,
			RequestRawQuery: rawQuery,
		},
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

// TestTransformMatchBoth_PathMatch_ResponseFires is the canonical happy
// path for direction:"both" with a path_pattern: the producing HTTP Layer
// threads the request's path forward via EnvelopeContext.RequestPath, so
// the response side fires when the paired request's path matched.
//
// USK-833: replaces the prior TestTransformMatchBoth_RequestPath_ResponseHost
// which codified the regression — response side fired on host alone
// regardless of the paired request's path.
func TestTransformMatchBoth_PathMatch_ResponseFires(t *testing.T) {
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

	// Response side paired with /headers: USK-833 reads paired path from
	// Context.RequestPath and matches.
	respEnv, respMsg := testTransformResponseEnvPaired(200, "httpbin.org", nil, nil, "GET", "/headers", "")
	if !e.TransformResponse(context.Background(), respEnv, respMsg) {
		t.Error("USK-833: response paired with /headers under path_pattern ^/headers$ should fire")
	}
	if headerGet(respMsg.Headers, "X-Tag") != "tagged" {
		t.Errorf("X-Tag = %q on response, want tagged", headerGet(respMsg.Headers, "X-Tag"))
	}
}

// TestTransformMatchBoth_PathMismatch_ResponseNotFires is the verbatim
// Pattern ① repro from USK-833 against the transform engine: a
// direction:"both" transform with path_pattern:"^/headers$" applied to a
// request to "/" must NOT modify the paired response.
func TestTransformMatchBoth_PathMismatch_ResponseNotFires(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionBoth,
		`^httpbin\.org$`, `^/headers$`, nil,
		TransformAddHeader, "X-Tag", "tagged", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Request side, path mismatch.
	reqEnv, reqMsg := testTransformEnv("GET", "/", "httpbin.org", nil, nil)
	if e.TransformRequest(context.Background(), reqEnv, reqMsg) {
		t.Error("request /: path mismatch should reject")
	}

	// Response side paired with /: USK-833 reads paired path and rejects.
	respEnv, respMsg := testTransformResponseEnvPaired(200, "httpbin.org", nil, nil, "GET", "/", "")
	if e.TransformResponse(context.Background(), respEnv, respMsg) {
		t.Error("USK-833 Pattern ①: response paired with / under path_pattern ^/headers$ must NOT fire")
	}
	if headerGet(respMsg.Headers, "X-Tag") != "" {
		t.Errorf("X-Tag = %q, want empty (transform must not fire on path-mismatched response)", headerGet(respMsg.Headers, "X-Tag"))
	}
}

// TestTransformMatchBoth_DifferentPath_ResponseNotFires is Pattern ② for
// the transform engine.
func TestTransformMatchBoth_DifferentPath_ResponseNotFires(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionBoth,
		`^httpbin\.org$`, `^/headers$`, nil,
		TransformAddHeader, "X-Tag", "tagged", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	respEnv, respMsg := testTransformResponseEnvPaired(200, "httpbin.org", nil, nil, "GET", "/uuid", "")
	if e.TransformResponse(context.Background(), respEnv, respMsg) {
		t.Error("USK-833 Pattern ②: response paired with /uuid under path_pattern ^/headers$ must NOT fire")
	}
}

// TestTransformMatchBoth_MethodMismatch_ResponseNotFires confirms the
// methods condition gates the response side too with USK-833.
func TestTransformMatchBoth_MethodMismatch_ResponseNotFires(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionBoth,
		`^httpbin\.org$`, "", []string{"POST"},
		TransformAddHeader, "X-Tag", "tagged", "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	respEnv, respMsg := testTransformResponseEnvPaired(200, "httpbin.org", nil, nil, "GET", "/", "")
	if e.TransformResponse(context.Background(), respEnv, respMsg) {
		t.Error("USK-833: response paired with GET under methods:[POST] must NOT fire")
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

// ---------------------------------------------------------------------------
// USK-834: Content-Encoding auto-decode for replace_body.
// ---------------------------------------------------------------------------

// gzipEncode returns gzip-compressed bytes for body.
func gzipEncode(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// brotliEncode returns brotli-compressed bytes for body.
func brotliEncode(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := brotli.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zstdEncode returns zstd-compressed bytes for body.
func zstdEncode(t *testing.T, body []byte) []byte {
	t.Helper()
	zw, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	out := zw.EncodeAll(body, nil)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

// findHeader returns the value of the first matching header, or "" if missing.
func findHeader(headers []envelope.KeyValue, name string) string {
	return headerGet(headers, name)
}

// TestTransformEngine_ReplaceBody_DecodesCE_Gzip is the USK-834 happy-path:
// a response with Content-Encoding: gzip is decoded, the regex matches the
// plaintext, and the wire-side msg.Body is the modified plaintext with
// Content-Encoding stripped and Content-Length re-stamped.
func TestTransformEngine_ReplaceBody_DecodesCE_Gzip(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `"args":`, `"REPLACED":`)
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	plaintext := []byte(`{"args": {"k":"v"}, "url": "https://example.com"}`)
	compressed := gzipEncode(t, plaintext)
	headers := []envelope.KeyValue{
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Content-Encoding", Value: "gzip"},
		{Name: "Content-Length", Value: strconv.Itoa(len(compressed))},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, compressed)

	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected gzip-decoded body to be modified")
	}

	wantBody := []byte(`{"REPLACED": {"k":"v"}, "url": "https://example.com"}`)
	if !bytes.Equal(msg.Body, wantBody) {
		t.Errorf("body = %q, want %q", msg.Body, wantBody)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding should be stripped after decode, got %q", got)
	}
	if got := findHeader(msg.Headers, "Content-Length"); got != strconv.Itoa(len(wantBody)) {
		t.Errorf("Content-Length = %q, want %d", got, len(wantBody))
	}
}

// TestTransformEngine_ReplaceBody_DecodesCE_Brotli verifies br codec coverage.
func TestTransformEngine_ReplaceBody_DecodesCE_Brotli(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	plaintext := []byte(`{"pw": "secret123"}`)
	compressed := brotliEncode(t, plaintext)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "br"},
		{Name: "Content-Length", Value: strconv.Itoa(len(compressed))},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, compressed)

	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected brotli-decoded body to be modified")
	}
	if string(msg.Body) != `{"pw": "[REDACTED]"}` {
		t.Errorf("body = %q", msg.Body)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding should be stripped, got %q", got)
	}
	if got := findHeader(msg.Headers, "Content-Length"); got != strconv.Itoa(len(msg.Body)) {
		t.Errorf("Content-Length = %q, want %d", got, len(msg.Body))
	}
}

// TestTransformEngine_ReplaceBody_DecodesCE_Zstd verifies zstd codec
// coverage — the Fly.io edge codec from the USK-834 repro.
func TestTransformEngine_ReplaceBody_DecodesCE_Zstd(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `"args":`, `"REPLACED":`)
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	plaintext := []byte(`{"args": {"k":"v"}}`)
	compressed := zstdEncode(t, plaintext)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "zstd"},
		{Name: "Content-Length", Value: strconv.Itoa(len(compressed))},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, compressed)

	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected zstd-decoded body to be modified")
	}
	if string(msg.Body) != `{"REPLACED": {"k":"v"}}` {
		t.Errorf("body = %q", msg.Body)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding should be stripped, got %q", got)
	}
	if got := findHeader(msg.Headers, "Content-Length"); got != strconv.Itoa(len(msg.Body)) {
		t.Errorf("Content-Length = %q, want %d", got, len(msg.Body))
	}
}

// TestTransformEngine_ReplaceBody_DecodesCE_GzipRequest exercises request-side
// gzip decode (the rare but legitimate gzipped-POST upload case).
func TestTransformEngine_ReplaceBody_DecodesCE_GzipRequest(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionRequest, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	plaintext := []byte(`{"pw":"secret123"}`)
	compressed := gzipEncode(t, plaintext)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "gzip"},
		{Name: "Content-Length", Value: strconv.Itoa(len(compressed))},
	}
	env, msg := testTransformEnv("POST", "/upload", "example.com", headers, compressed)

	modified := e.TransformRequest(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected request gzip body to be decoded + modified")
	}
	if string(msg.Body) != `{"pw":"[REDACTED]"}` {
		t.Errorf("body = %q", msg.Body)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding should be stripped on request side too, got %q", got)
	}
	if got := findHeader(msg.Headers, "Content-Length"); got != strconv.Itoa(len(msg.Body)) {
		t.Errorf("Content-Length = %q, want %d", got, len(msg.Body))
	}
}

// TestTransformEngine_ReplaceBody_Identity_NoHeaderRewrite confirms that the
// identity / no-CE fast path leaves Content-Encoding/Content-Length untouched
// even after a successful regex replace. Pre-USK-834 behavior must be
// preserved for the common uncompressed path.
func TestTransformEngine_ReplaceBody_Identity_NoHeaderRewrite(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `secret\d+`, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := []byte(`{"pw":"secret123"}`)
	headers := []envelope.KeyValue{
		{Name: "Content-Type", Value: "application/json"},
		// No Content-Encoding header — common uncompressed case.
		{Name: "Content-Length", Value: strconv.Itoa(len(body))},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, body)

	modified := e.TransformResponse(context.Background(), env, msg)
	if !modified {
		t.Fatal("expected regex to modify uncompressed body")
	}
	if string(msg.Body) != `{"pw":"[REDACTED]"}` {
		t.Errorf("body = %q", msg.Body)
	}
	// On the identity path, Transform must not rewrite CL — the downstream
	// HTTP/1.x channel handles CL via applyTEToCLRewrite, and rewriting
	// here on the uncompressed path would change observable header order.
	clCount := 0
	for _, h := range msg.Headers {
		if h.Name == "Content-Length" {
			clCount++
		}
	}
	if clCount != 1 {
		t.Errorf("Content-Length count = %d, want 1 (no rewrite on identity path)", clCount)
	}
	if got := findHeader(msg.Headers, "Content-Length"); got != strconv.Itoa(len(body)) {
		// Original CL preserved; Transform did not touch it.
		t.Errorf("Content-Length = %q, want %d (original, untouched)", got, len(body))
	}
}

// TestTransformEngine_ReplaceBody_DecodeFailSoft_UnknownCodec verifies fail-
// soft semantics on an unrecognized Content-Encoding (e.g., "snappy"). The
// transform must NOT mutate msg, the original compressed bytes must continue
// along the wire untouched, and the rule reports false.
func TestTransformEngine_ReplaceBody_DecodeFailSoft_UnknownCodec(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `secret`, "REDACTED")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := []byte(`whatever-bytes-secret`)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "snappy"},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, body)

	modified := e.TransformResponse(context.Background(), env, msg)
	if modified {
		t.Error("unknown codec must trigger fail-soft (no mutation)")
	}
	if !bytes.Equal(msg.Body, body) {
		t.Errorf("body changed under fail-soft: %q vs original %q", msg.Body, body)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "snappy" {
		t.Errorf("Content-Encoding should be preserved under fail-soft, got %q", got)
	}
}

// TestTransformEngine_ReplaceBody_DecodeFailSoft_ChainedCE verifies fail-soft
// on a multi-codec Content-Encoding chain like "gzip, br". bodydecode rejects
// chains; transform must surface that as a no-op.
func TestTransformEngine_ReplaceBody_DecodeFailSoft_ChainedCE(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `secret`, "REDACTED")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Note: body bytes are arbitrary — chain rejection happens before any
	// decode attempt.
	body := []byte(`opaque-chained-payload-secret`)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "gzip, br"},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, body)

	modified := e.TransformResponse(context.Background(), env, msg)
	if modified {
		t.Error("chained CE must trigger fail-soft (no mutation)")
	}
	if !bytes.Equal(msg.Body, body) {
		t.Errorf("body changed under fail-soft: %q vs original %q", msg.Body, body)
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "gzip, br" {
		t.Errorf("Content-Encoding should be preserved under fail-soft, got %q", got)
	}
}

// TestTransformEngine_ReplaceBody_DecodeFailSoft_MalformedGzip verifies that
// a Content-Encoding: gzip header on non-gzip bytes triggers fail-soft via
// the malformed anomaly type, leaving the wire bytes intact.
func TestTransformEngine_ReplaceBody_DecodeFailSoft_MalformedGzip(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `secret`, "REDACTED")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := []byte(`not-actually-gzip-secret`)
	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "gzip"},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, body)

	modified := e.TransformResponse(context.Background(), env, msg)
	if modified {
		t.Error("malformed gzip must trigger fail-soft (no mutation)")
	}
	if !bytes.Equal(msg.Body, body) {
		t.Errorf("body changed under fail-soft: %q", msg.Body)
	}
}

// TestTransformEngine_ReplaceBody_DecodeEmptyBody_NoOp verifies that a
// response with Content-Encoding: gzip but zero-byte body is a no-op and
// does not strip the (legitimately compressed-but-empty) headers.
func TestTransformEngine_ReplaceBody_DecodeEmptyBody_NoOp(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionResponse, "", "", nil,
		TransformReplaceBody, "", "", `anything`, "X")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	headers := []envelope.KeyValue{
		{Name: "Content-Encoding", Value: "gzip"},
	}
	env, msg := testTransformResponseEnv(200, "example.com", headers, nil)

	modified := e.TransformResponse(context.Background(), env, msg)
	if modified {
		t.Error("empty body should not produce modification")
	}
	if got := findHeader(msg.Headers, "Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding should be preserved when body is empty, got %q", got)
	}
}
