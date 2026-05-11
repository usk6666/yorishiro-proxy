package http

import (
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func testHTTPRequest(method, path, host string, headers []envelope.KeyValue) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Method:    method,
		Path:      path,
		Authority: host,
		Headers:   headers,
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   envelope.EnvelopeContext{TargetHost: host + ":443"},
	}
	return env, msg
}

func TestInterceptEngine_MatchRequest_Host(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionRequest,
		HostPattern: regexp.MustCompile(`example\.com`),
	}})

	env, msg := testHTTPRequest("GET", "/", "example.com", nil)
	matched := e.MatchRequest(env, msg)
	if len(matched) != 1 || matched[0] != "r1" {
		t.Errorf("matched = %v, want [r1]", matched)
	}

	env2, msg2 := testHTTPRequest("GET", "/", "other.com", nil)
	matched2 := e.MatchRequest(env2, msg2)
	if len(matched2) != 0 {
		t.Errorf("matched = %v, want empty", matched2)
	}
}

func TestInterceptEngine_MatchRequest_Path(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionRequest,
		PathPattern: regexp.MustCompile(`^/api/`),
	}})

	env, msg := testHTTPRequest("GET", "/api/users", "example.com", nil)
	if len(e.MatchRequest(env, msg)) != 1 {
		t.Error("expected match on /api/users")
	}

	env2, msg2 := testHTTPRequest("GET", "/web/index.html", "example.com", nil)
	if len(e.MatchRequest(env2, msg2)) != 0 {
		t.Error("expected no match on /web/index.html")
	}
}

func TestInterceptEngine_MatchRequest_Methods(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Methods:   []string{"POST", "PUT"},
	}})

	env, msg := testHTTPRequest("POST", "/", "example.com", nil)
	if len(e.MatchRequest(env, msg)) != 1 {
		t.Error("expected match on POST")
	}

	env2, msg2 := testHTTPRequest("GET", "/", "example.com", nil)
	if len(e.MatchRequest(env2, msg2)) != 0 {
		t.Error("expected no match on GET")
	}
}

func TestInterceptEngine_MatchRequest_HeaderMatch(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		HeaderMatch: map[string]*regexp.Regexp{
			"content-type": regexp.MustCompile(`application/json`),
		},
	}})

	headers := []envelope.KeyValue{{Name: "Content-Type", Value: "application/json"}}
	env, msg := testHTTPRequest("POST", "/", "example.com", headers)
	if len(e.MatchRequest(env, msg)) != 1 {
		t.Error("expected match on Content-Type header")
	}

	headers2 := []envelope.KeyValue{{Name: "Content-Type", Value: "text/html"}}
	env2, msg2 := testHTTPRequest("POST", "/", "example.com", headers2)
	if len(e.MatchRequest(env2, msg2)) != 0 {
		t.Error("expected no match on text/html")
	}
}

func TestInterceptEngine_ANDCombination(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`example\.com`),
		PathPattern: regexp.MustCompile(`^/api/`),
		Methods:     []string{"POST"},
	}})

	// All conditions match.
	env, msg := testHTTPRequest("POST", "/api/test", "example.com", nil)
	if len(e.MatchRequest(env, msg)) != 1 {
		t.Error("expected match when all conditions met")
	}

	// Host doesn't match.
	env2, msg2 := testHTTPRequest("POST", "/api/test", "other.com", nil)
	if len(e.MatchRequest(env2, msg2)) != 0 {
		t.Error("expected no match when host differs")
	}

	// Method doesn't match.
	env3, msg3 := testHTTPRequest("GET", "/api/test", "example.com", nil)
	if len(e.MatchRequest(env3, msg3)) != 0 {
		t.Error("expected no match when method differs")
	}
}

func TestInterceptEngine_DirectionFilter(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionResponse,
	}})

	env, msg := testHTTPRequest("GET", "/", "example.com", nil)
	// Request should not match a response-only rule.
	if len(e.MatchRequest(env, msg)) != 0 {
		t.Error("response rule should not match requests")
	}

	// Response should match.
	if len(e.MatchResponse(env, msg)) != 1 {
		t.Error("response rule should match responses")
	}
}

func TestInterceptEngine_DisabledRule(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   false,
		Direction: DirectionRequest,
	}})

	env, msg := testHTTPRequest("GET", "/", "example.com", nil)
	if len(e.MatchRequest(env, msg)) != 0 {
		t.Error("disabled rule should not match")
	}
}

func TestInterceptEngine_AddRemoveRule(t *testing.T) {
	e := NewInterceptEngine()
	e.AddRule(InterceptRule{ID: "r1", Enabled: true, Direction: DirectionRequest})
	e.AddRule(InterceptRule{ID: "r2", Enabled: true, Direction: DirectionRequest})

	env, msg := testHTTPRequest("GET", "/", "example.com", nil)
	if len(e.MatchRequest(env, msg)) != 2 {
		t.Error("expected 2 matches")
	}

	e.RemoveRule("r1")
	if len(e.MatchRequest(env, msg)) != 1 {
		t.Error("expected 1 match after removal")
	}
}

func TestCompileInterceptRule(t *testing.T) {
	rule, err := CompileInterceptRule("r1", DirectionBoth,
		`example\.com`, `^/api/`, []string{"GET", "POST"},
		map[string]string{"Content-Type": "json"})
	if err != nil {
		t.Fatal(err)
	}
	if rule.HostPattern == nil || rule.PathPattern == nil {
		t.Error("patterns should be compiled")
	}
	if len(rule.HeaderMatch) != 1 {
		t.Errorf("expected 1 header match, got %d", len(rule.HeaderMatch))
	}
	// Header key should be lowercased.
	if _, ok := rule.HeaderMatch["content-type"]; !ok {
		t.Error("header key should be lowercased")
	}
}

// testHTTPResponse builds a response envelope as the HTTP/1.x channel /
// httpaggregator would: Method/Path/Authority all empty per the
// HTTPMessage field-validity contract (see internal/envelope/http.go).
// Used by USK-821 regression tests to verify that direction:"response" and
// direction:"both" rules with request-only conditions (path_pattern,
// methods) do not silently fail to match. Context.RequestPath / RequestMethod
// are also empty here, simulating the "no paired request data" case that
// preserves the USK-821 fix (knowable=false → request-only checks skipped).
func testHTTPResponse(status int, host string, headers []envelope.KeyValue) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Status:  status,
		Headers: headers,
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

// testHTTPResponseWithPairedRequest builds a response envelope as the
// HTTP/1.x channel / httpaggregator does post-USK-833: the producing Layer
// has threaded the paired request's path/method/query forward onto
// EnvelopeContext.RequestPath / RequestMethod / RequestRawQuery so
// response-phase rule matching can gate on the paired request's identity.
// Used by USK-833 regression tests for direction:"both" + path_pattern /
// methods.
func testHTTPResponseWithPairedRequest(status int, host string, headers []envelope.KeyValue, method, path, rawQuery string) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Status:  status,
		Headers: headers,
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

// TestMatchResponse_PathPatternIgnored verifies USK-821 fix: a rule with
// direction:"response" + path_pattern + a host_pattern that DOES match the
// response envelope's TargetHost must match. Previously matchesRule
// short-circuited on the empty Path field, so the rule never fired on
// the response side.
func TestMatchResponse_PathPatternIgnored(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionResponse,
		HostPattern: regexp.MustCompile(`^example\.com$`),
		PathPattern: regexp.MustCompile(`^/headers$`), // request-only field
	}})

	env, msg := testHTTPResponse(200, "example.com", nil)
	matched := e.MatchResponse(env, msg)
	if len(matched) != 1 || matched[0] != "r1" {
		t.Errorf("matched = %v, want [r1] (USK-821: response with empty Path should not short-circuit on PathPattern)", matched)
	}
}

// TestMatchResponse_MethodsIgnored is the parallel regression guard for
// the Methods request-only field. response envelopes have Method=="",
// so an unconditional methods check would over-reject them.
func TestMatchResponse_MethodsIgnored(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionResponse,
		HostPattern: regexp.MustCompile(`^example\.com$`),
		Methods:     []string{"GET", "POST"}, // request-only field
	}})

	env, msg := testHTTPResponse(200, "example.com", nil)
	matched := e.MatchResponse(env, msg)
	if len(matched) != 1 || matched[0] != "r1" {
		t.Errorf("matched = %v, want [r1] (USK-821: response with empty Method should not short-circuit on Methods)", matched)
	}
}

// TestMatchResponse_HeaderMatchStillEnforced verifies that the
// direction-aware skip applies ONLY to request-only fields. HeaderMatch
// is valid on both directions and must still gate the match.
func TestMatchResponse_HeaderMatchStillEnforced(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionResponse,
		HeaderMatch: map[string]*regexp.Regexp{
			"content-type": regexp.MustCompile(`application/json`),
		},
	}})

	// Matching response: header present with matching value.
	headers := []envelope.KeyValue{{Name: "Content-Type", Value: "application/json"}}
	env, msg := testHTTPResponse(200, "example.com", headers)
	if matched := e.MatchResponse(env, msg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (header match should still gate response)", matched)
	}

	// Non-matching response: header value differs.
	headers2 := []envelope.KeyValue{{Name: "Content-Type", Value: "text/html"}}
	env2, msg2 := testHTTPResponse(200, "example.com", headers2)
	if matched := e.MatchResponse(env2, msg2); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (header match should reject text/html)", matched)
	}
}

// TestMatchResponse_HostPatternStillEnforced is the negative case: a
// host mismatch on the response side must still reject the rule even
// though path/method are skipped.
func TestMatchResponse_HostPatternStillEnforced(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionResponse,
		HostPattern: regexp.MustCompile(`^example\.com$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
	}})

	env, msg := testHTTPResponse(200, "httpbin.org", nil)
	if matched := e.MatchResponse(env, msg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (host mismatch should reject even when path is skipped)", matched)
	}
}

// TestMatchRequest_PathPatternStillEnforced is the regression guard
// against the fix being too aggressive. Request-side matching of
// PathPattern must remain correct.
func TestMatchRequest_PathPatternStillEnforced(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionRequest,
		PathPattern: regexp.MustCompile(`^/api/`),
	}})

	// Matching path.
	env, msg := testHTTPRequest("GET", "/api/users", "example.com", nil)
	if matched := e.MatchRequest(env, msg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (regression: request-side PathPattern still applies)", matched)
	}

	// Non-matching path.
	env2, msg2 := testHTTPRequest("GET", "/web/index.html", "example.com", nil)
	if matched := e.MatchRequest(env2, msg2); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (regression: request-side PathPattern should still reject mismatches)", matched)
	}
}

// TestMatchRequest_MethodsStillEnforced is the parallel regression
// guard for Methods.
func TestMatchRequest_MethodsStillEnforced(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Methods:   []string{"POST"},
	}})

	env, msg := testHTTPRequest("POST", "/", "example.com", nil)
	if matched := e.MatchRequest(env, msg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (regression: request-side Methods still applies)", matched)
	}

	env2, msg2 := testHTTPRequest("GET", "/", "example.com", nil)
	if matched := e.MatchRequest(env2, msg2); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (regression: request-side Methods should still reject)", matched)
	}
}

// TestMatchBoth_PathMatch_ResponseHeld is the canonical happy path for
// direction:"both" with a path_pattern: the producing HTTP Layer threads
// the request's path forward via EnvelopeContext.RequestPath, so the
// response side matches when the paired request's path matched. Both
// request and response phases should fire.
//
// USK-833: this replaces the prior TestMatchBoth_RequestPath_ResponseHost,
// which codified the regression — host-only-passes on the response side
// regardless of path. The new semantics gate the response phase on the
// paired request's identity.
func TestMatchBoth_PathMatch_ResponseHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
	}})

	// Request side: path + host both check out.
	reqEnv, reqMsg := testHTTPRequest("GET", "/headers", "httpbin.org", nil)
	if matched := e.MatchRequest(reqEnv, reqMsg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (request side: path+host should match)", matched)
	}

	// Response side: HTTP Layer has threaded the paired request's path
	// onto Context.RequestPath. Path matches, so the rule fires.
	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "httpbin.org", nil, "GET", "/headers", "")
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (USK-833: response with paired path match should be held)", matched)
	}
}

// TestMatchBoth_PathMismatch_ResponseNotHeld is the verbatim Pattern ① repro
// from USK-833: a direction:"both" rule with path_pattern:"^/headers$"
// applied to a request to "/" must NOT hold the paired response. The bug
// codified by the prior test was that the response side held regardless of
// the request's path.
func TestMatchBoth_PathMismatch_ResponseNotHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
	}})

	// Request side, path mismatch: rejects.
	reqEnv, reqMsg := testHTTPRequest("GET", "/", "httpbin.org", nil)
	if matched := e.MatchRequest(reqEnv, reqMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (request side: path mismatch should reject)", matched)
	}

	// Response side with paired request path "/" - rule's path_pattern
	// requires "/headers". With USK-833 the response side now reads the
	// paired path from Context and must reject.
	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "httpbin.org", nil, "GET", "/", "")
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (USK-833 Pattern ①: response of / under path_pattern ^/headers$ must NOT be held)", matched)
	}
}

// TestMatchBoth_PathPattern_DifferentPath_ResponseNotHeld is the verbatim
// Pattern ② repro from USK-833: a direction:"both" rule with
// path_pattern:"^/headers$" applied to /uuid must NOT hold the paired
// response either.
func TestMatchBoth_PathPattern_DifferentPath_ResponseNotHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
	}})

	reqEnv, reqMsg := testHTTPRequest("GET", "/uuid", "httpbin.org", nil)
	if matched := e.MatchRequest(reqEnv, reqMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (request /uuid must not match ^/headers$)", matched)
	}

	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "httpbin.org", nil, "GET", "/uuid", "")
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (USK-833 Pattern ②: response of /uuid under path_pattern ^/headers$ must NOT be held)", matched)
	}
}

// TestMatchBoth_HostMismatch_ResponseNotHeld confirms host gating still
// works on the response side after the USK-833 change.
func TestMatchBoth_HostMismatch_ResponseNotHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
	}})

	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "example.com", nil, "GET", "/headers", "")
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (response side: host mismatch must reject)", matched)
	}
}

// TestMatchBoth_MethodMismatch_ResponseNotHeld confirms the methods
// condition gates the response side too with USK-833.
func TestMatchBoth_MethodMismatch_ResponseNotHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		Methods:     []string{"POST"},
	}})

	// Request: GET — does not match POST whitelist.
	reqEnv, reqMsg := testHTTPRequest("GET", "/", "httpbin.org", nil)
	if matched := e.MatchRequest(reqEnv, reqMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (GET against POST whitelist)", matched)
	}

	// Response paired with GET — USK-833 reads paired method from Context.
	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "httpbin.org", nil, "GET", "/", "")
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (USK-833: response paired with GET under methods:[POST] must NOT be held)", matched)
	}
}

// TestMatchBoth_BothConditions_ResponseHeld covers the positive case: a
// direction:"both" rule with both path_pattern AND methods, where the
// paired request matches both, so the response side fires.
func TestMatchBoth_BothConditions_ResponseHeld(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r2",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
		Methods:     []string{"GET"},
	}})

	respEnv, respMsg := testHTTPResponseWithPairedRequest(200, "httpbin.org", nil, "GET", "/headers", "")
	matched := e.MatchResponse(respEnv, respMsg)
	if len(matched) != 1 || matched[0] != "r2" {
		t.Errorf("matched = %v, want [r2] (USK-833: response paired with GET /headers under matching path+methods should be held)", matched)
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
	}
	for _, tt := range tests {
		got := extractHostname(tt.input)
		if got != tt.want {
			t.Errorf("extractHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
