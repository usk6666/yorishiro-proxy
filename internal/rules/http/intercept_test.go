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
