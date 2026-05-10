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
// methods) do not silently fail to match.
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

// TestMatchBoth_RequestPath_ResponseHost covers the canonical
// direction:"both" use case from the design review: a rule that scopes
// requests by path while still firing on the response side via host
// alone. With the USK-821 fix, the request side matches by path+host
// and the response side matches by host alone (path skipped).
func TestMatchBoth_RequestPath_ResponseHost(t *testing.T) {
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

	// Response side: only host left to evaluate (path skipped). Should match.
	respEnv, respMsg := testHTTPResponse(200, "httpbin.org", nil)
	if matched := e.MatchResponse(respEnv, respMsg); len(matched) != 1 {
		t.Errorf("matched = %v, want 1 (USK-821: response side with direction:both should match by host alone)", matched)
	}

	// Response side, host mismatch: still rejects.
	respEnv2, respMsg2 := testHTTPResponse(200, "example.com", nil)
	if matched := e.MatchResponse(respEnv2, respMsg2); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (response side: host mismatch should still reject)", matched)
	}

	// Request side, path mismatch: rejects (path still applies on Send).
	reqEnv2, reqMsg2 := testHTTPRequest("GET", "/other", "httpbin.org", nil)
	if matched := e.MatchRequest(reqEnv2, reqMsg2); len(matched) != 0 {
		t.Errorf("matched = %v, want empty (request side: path mismatch should reject)", matched)
	}
}

// TestMatchResponse_BothDirection_AllRequestOnlyConditions is the
// reproducer for the issue's ケース B: a direction:"both" rule with
// path_pattern AND methods. The response side should still match (both
// request-only fields skipped on Receive, only host/header drive the
// response match).
func TestMatchResponse_BothDirection_AllRequestOnlyConditions(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r2",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`^httpbin\.org$`),
		PathPattern: regexp.MustCompile(`^/headers$`),
		Methods:     []string{"GET"},
	}})

	respEnv, respMsg := testHTTPResponse(200, "httpbin.org", nil)
	matched := e.MatchResponse(respEnv, respMsg)
	if len(matched) != 1 || matched[0] != "r2" {
		t.Errorf("matched = %v, want [r2] (USK-821 ケース B: direction:both + path + methods should match response by host alone)", matched)
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
