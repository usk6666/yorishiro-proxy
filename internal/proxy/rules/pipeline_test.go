package rules

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestPipeline_AddRule(t *testing.T) {
	p := NewPipeline()

	err := p.AddRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action:    Action{Type: ActionRemoveHeader, Header: "X-Test"},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1", p.Len())
	}
}

func TestPipeline_AddRule_Duplicate(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})

	err := p.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "Y"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate rule ID")
	}
}

func TestPipeline_AddRule_Invalid(t *testing.T) {
	p := NewPipeline()

	err := p.AddRule(Rule{
		ID:        "r1",
		Direction: "invalid",
		Action:    Action{Type: ActionRemoveHeader, Header: "X"},
	})
	if err == nil {
		t.Fatal("expected error for invalid rule")
	}
}

func TestPipeline_RemoveRule(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})
	p.AddRule(Rule{
		ID: "r2", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "Y"},
	})

	if err := p.RemoveRule("r1"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1", p.Len())
	}

	// Verify r2 still exists.
	_, err := p.GetRule("r2")
	if err != nil {
		t.Errorf("r2 should still exist: %v", err)
	}
}

func TestPipeline_RemoveRule_NotFound(t *testing.T) {
	p := NewPipeline()

	err := p.RemoveRule("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

func TestPipeline_EnableRule(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "r1", Enabled: false, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})

	if err := p.EnableRule("r1", true); err != nil {
		t.Fatalf("EnableRule: %v", err)
	}

	r, _ := p.GetRule("r1")
	if !r.Enabled {
		t.Error("r1 should be enabled")
	}

	if err := p.EnableRule("r1", false); err != nil {
		t.Fatalf("EnableRule(false): %v", err)
	}

	r, _ = p.GetRule("r1")
	if r.Enabled {
		t.Error("r1 should be disabled")
	}
}

func TestPipeline_EnableRule_NotFound(t *testing.T) {
	p := NewPipeline()

	err := p.EnableRule("nonexistent", true)
	if err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

func TestPipeline_GetRule_NotFound(t *testing.T) {
	p := NewPipeline()

	_, err := p.GetRule("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent rule")
	}
}

func TestPipeline_Rules_Empty(t *testing.T) {
	p := NewPipeline()

	rules := p.Rules()
	if rules != nil {
		t.Errorf("Rules() = %v, want nil", rules)
	}
}

func TestPipeline_Rules_SortedByPriority(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "r3", Enabled: true, Priority: 30, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})
	p.AddRule(Rule{
		ID: "r1", Enabled: true, Priority: 10, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "Y"},
	})
	p.AddRule(Rule{
		ID: "r2", Enabled: true, Priority: 20, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "Z"},
	})

	rules := p.Rules()
	if len(rules) != 3 {
		t.Fatalf("len(Rules()) = %d, want 3", len(rules))
	}
	if rules[0].ID != "r1" || rules[1].ID != "r2" || rules[2].ID != "r3" {
		t.Errorf("rules order = [%s, %s, %s], want [r1, r2, r3]",
			rules[0].ID, rules[1].ID, rules[2].ID)
	}
}

func TestPipeline_SetRules(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "old", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})

	err := p.SetRules([]Rule{
		{
			ID: "new-1", Enabled: true, Priority: 10, Direction: DirectionRequest,
			Action: Action{Type: ActionRemoveHeader, Header: "Y"},
		},
		{
			ID: "new-2", Enabled: true, Priority: 5, Direction: DirectionResponse,
			Action: Action{Type: ActionSetHeader, Header: "Z", Value: "v"},
		},
	})
	if err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	if p.Len() != 2 {
		t.Errorf("Len() = %d, want 2", p.Len())
	}

	// Verify order (new-2 has lower priority, should be first).
	rules := p.Rules()
	if rules[0].ID != "new-2" {
		t.Errorf("first rule ID = %q, want %q (lower priority first)", rules[0].ID, "new-2")
	}

	// Old rule should be gone.
	_, err = p.GetRule("old")
	if err == nil {
		t.Error("old rule should have been replaced")
	}
}

func TestPipeline_SetRules_DuplicateID(t *testing.T) {
	p := NewPipeline()

	err := p.SetRules([]Rule{
		{
			ID: "dup", Enabled: true, Direction: DirectionRequest,
			Action: Action{Type: ActionRemoveHeader, Header: "X"},
		},
		{
			ID: "dup", Enabled: true, Direction: DirectionResponse,
			Action: Action{Type: ActionRemoveHeader, Header: "Y"},
		},
	})
	if err == nil {
		t.Fatal("expected error for duplicate rule IDs in SetRules")
	}
}

func TestPipeline_SetRules_InvalidRule(t *testing.T) {
	p := NewPipeline()

	// Add a valid rule first.
	p.AddRule(Rule{
		ID: "existing", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})

	err := p.SetRules([]Rule{
		{
			ID: "valid", Enabled: true, Direction: DirectionRequest,
			Action: Action{Type: ActionRemoveHeader, Header: "X"},
		},
		{
			ID: "invalid", Direction: "bad",
			Action: Action{Type: ActionRemoveHeader, Header: "Y"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid rule in SetRules")
	}

	// Existing rules should be preserved.
	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (should preserve existing)", p.Len())
	}
}

func TestPipeline_Clear(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "X"},
	})

	p.Clear()

	if p.Len() != 0 {
		t.Errorf("Len() = %d, want 0 after Clear()", p.Len())
	}
}

func TestPipeline_TransformRequest_AddHeader(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "add-auth",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:   ActionAddHeader,
			Header: "Authorization",
			Value:  "Bearer test-token",
		},
	})

	u, _ := url.Parse("http://api.target.com/test")
	headers := http.Header{"Content-Type": {"application/json"}}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
	}
	// Original header should still be present.
	if got := headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
}

func TestPipeline_TransformRequest_SetHeader(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "set-auth",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:   ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer new-token",
		},
	})

	u, _ := url.Parse("http://api.target.com/test")
	headers := http.Header{
		"Authorization": {"Bearer old-token"},
		"Content-Type":  {"application/json"},
	}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("Authorization"); got != "Bearer new-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer new-token")
	}
}

func TestPipeline_TransformRequest_RemoveHeader(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "remove-csp",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:   ActionRemoveHeader,
			Header: "X-Unwanted",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{
		"X-Unwanted":   {"val"},
		"Content-Type": {"text/html"},
	}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("X-Unwanted"); got != "" {
		t.Errorf("X-Unwanted should be removed, got %q", got)
	}
	if got := headers.Get("Content-Type"); got != "text/html" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html")
	}
}

func TestPipeline_TransformRequest_ReplaceBody(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "replace-host",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:    ActionReplaceBody,
			Pattern: "production-host",
			Value:   "staging-host",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}
	body := []byte(`{"server": "production-host", "port": 443}`)

	_, newBody := p.TransformRequest("POST", u, headers, body)

	expected := `{"server": "staging-host", "port": 443}`
	if string(newBody) != expected {
		t.Errorf("body = %q, want %q", string(newBody), expected)
	}
}

func TestPipeline_TransformRequest_ReplaceBodyRegex(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "replace-version",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:    ActionReplaceBody,
			Pattern: `v\d+\.\d+`,
			Value:   "v2.0",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}
	body := []byte(`{"api_version": "v1.5", "name": "test"}`)

	_, newBody := p.TransformRequest("POST", u, headers, body)

	expected := `{"api_version": "v2.0", "name": "test"}`
	if string(newBody) != expected {
		t.Errorf("body = %q, want %q", string(newBody), expected)
	}
}

func TestPipeline_TransformRequest_DisabledRuleSkipped(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "disabled-rule",
		Enabled:   false,
		Priority:  0,
		Direction: DirectionRequest,
		Action: Action{
			Type:   ActionSetHeader,
			Header: "X-Should-Not-Exist",
			Value:  "oops",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("X-Should-Not-Exist"); got != "" {
		t.Errorf("disabled rule should not add header, got %q", got)
	}
}

func TestPipeline_TransformRequest_DirectionFilter(t *testing.T) {
	p := NewPipeline()

	// Response-only rule should not apply to requests.
	p.AddRule(Rule{
		ID:        "response-only",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionResponse,
		Action: Action{
			Type:   ActionSetHeader,
			Header: "X-Response-Only",
			Value:  "val",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("X-Response-Only"); got != "" {
		t.Errorf("response-only rule should not apply to requests, got %q", got)
	}
}

func TestPipeline_TransformRequest_BothDirection(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "both-dir",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionBoth,
		Action: Action{
			Type:   ActionAddHeader,
			Header: "X-Proxy",
			Value:  "yorishiro",
		},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	if got := headers.Get("X-Proxy"); got != "yorishiro" {
		t.Errorf("both-direction rule should apply to requests, got %q", got)
	}
}

func TestPipeline_TransformRequest_ConditionFilter(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "api-only",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Conditions: Conditions{
			URLPattern: "/api/.*",
		},
		Action: Action{
			Type:   ActionSetHeader,
			Header: "X-API",
			Value:  "true",
		},
	})

	// Matching request.
	u1, _ := url.Parse("http://example.com/api/test")
	h1 := http.Header{}
	h1, _ = p.TransformRequest("GET", u1, h1, nil)
	if got := h1.Get("X-API"); got != "true" {
		t.Errorf("matching request: X-API = %q, want %q", got, "true")
	}

	// Non-matching request.
	u2, _ := url.Parse("http://example.com/public/test")
	h2 := http.Header{}
	h2, _ = p.TransformRequest("GET", u2, h2, nil)
	if got := h2.Get("X-API"); got != "" {
		t.Errorf("non-matching request: X-API should be empty, got %q", got)
	}
}

func TestPipeline_TransformRequest_PriorityOrder(t *testing.T) {
	p := NewPipeline()

	// Add in reverse priority order to verify sorting.
	p.AddRule(Rule{
		ID: "second", Enabled: true, Priority: 20, Direction: DirectionRequest,
		Action: Action{Type: ActionSetHeader, Header: "X-Test", Value: "second"},
	})
	p.AddRule(Rule{
		ID: "first", Enabled: true, Priority: 10, Direction: DirectionRequest,
		Action: Action{Type: ActionSetHeader, Header: "X-Test", Value: "first"},
	})
	p.AddRule(Rule{
		ID: "third", Enabled: true, Priority: 30, Direction: DirectionRequest,
		Action: Action{Type: ActionSetHeader, Header: "X-Test", Value: "third"},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}

	headers, _ = p.TransformRequest("GET", u, headers, nil)

	// Last writer wins for SetHeader, so "third" (highest priority value, applied last).
	if got := headers.Get("X-Test"); got != "third" {
		t.Errorf("X-Test = %q, want %q (last applied wins for SetHeader)", got, "third")
	}
}

func TestPipeline_TransformRequest_EmptyBody(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "replace", Enabled: true, Priority: 0, Direction: DirectionRequest,
		Action: Action{Type: ActionReplaceBody, Pattern: "old", Value: "new"},
	})

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{}

	_, body := p.TransformRequest("GET", u, headers, nil)

	if body != nil {
		t.Errorf("body should remain nil for empty body, got %v", body)
	}
}

func TestPipeline_TransformResponse_RemoveHeader(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "remove-csp",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionResponse,
		Action: Action{
			Type:   ActionRemoveHeader,
			Header: "Content-Security-Policy",
		},
	})

	headers := http.Header{
		"Content-Security-Policy": {"default-src 'self'"},
		"Content-Type":            {"text/html"},
	}

	headers, _ = p.TransformResponse(200, headers, nil)

	if got := headers.Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP header should be removed, got %q", got)
	}
	if got := headers.Get("Content-Type"); got != "text/html" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html")
	}
}

func TestPipeline_TransformResponse_ReplaceBody(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID:        "replace-domain",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionResponse,
		Action: Action{
			Type:    ActionReplaceBody,
			Pattern: `https://cdn\.example\.com`,
			Value:   "https://local.proxy",
		},
	})

	headers := http.Header{"Content-Type": {"text/html"}}
	body := []byte(`<script src="https://cdn.example.com/app.js"></script>`)

	_, newBody := p.TransformResponse(200, headers, body)

	expected := `<script src="https://local.proxy/app.js"></script>`
	if string(newBody) != expected {
		t.Errorf("body = %q, want %q", string(newBody), expected)
	}
}

func TestPipeline_TransformResponse_DirectionFilter(t *testing.T) {
	p := NewPipeline()

	// Request-only rule should not apply to responses.
	p.AddRule(Rule{
		ID: "request-only", Enabled: true, Priority: 0, Direction: DirectionRequest,
		Action: Action{Type: ActionSetHeader, Header: "X-Request-Only", Value: "val"},
	})

	headers := http.Header{}
	headers, _ = p.TransformResponse(200, headers, nil)

	if got := headers.Get("X-Request-Only"); got != "" {
		t.Errorf("request-only rule should not apply to responses, got %q", got)
	}
}

func TestPipeline_TransformResponse_BothDirection(t *testing.T) {
	p := NewPipeline()

	p.AddRule(Rule{
		ID: "both-dir", Enabled: true, Priority: 0, Direction: DirectionBoth,
		Action: Action{Type: ActionAddHeader, Header: "X-Proxy", Value: "yorishiro"},
	})

	headers := http.Header{}
	headers, _ = p.TransformResponse(200, headers, nil)

	if got := headers.Get("X-Proxy"); got != "yorishiro" {
		t.Errorf("both-direction rule should apply to responses, got %q", got)
	}
}

func TestPipeline_TransformRequest_MultipleRules(t *testing.T) {
	p := NewPipeline()

	// Add auth header.
	p.AddRule(Rule{
		ID: "add-auth", Enabled: true, Priority: 10, Direction: DirectionRequest,
		Action: Action{Type: ActionSetHeader, Header: "Authorization", Value: "Bearer token"},
	})

	// Replace body content.
	p.AddRule(Rule{
		ID: "replace-host", Enabled: true, Priority: 20, Direction: DirectionRequest,
		Action: Action{Type: ActionReplaceBody, Pattern: "prod", Value: "staging"},
	})

	// Remove unwanted header.
	p.AddRule(Rule{
		ID: "remove-cookie", Enabled: true, Priority: 5, Direction: DirectionRequest,
		Action: Action{Type: ActionRemoveHeader, Header: "Cookie"},
	})

	u, _ := url.Parse("http://api.target.com/test")
	headers := http.Header{
		"Cookie":       {"session=abc123"},
		"Content-Type": {"application/json"},
	}
	body := []byte(`{"host": "prod.example.com"}`)

	headers, newBody := p.TransformRequest("POST", u, headers, body)

	if got := headers.Get("Cookie"); got != "" {
		t.Errorf("Cookie should be removed, got %q", got)
	}
	if got := headers.Get("Authorization"); got != "Bearer token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer token")
	}
	expected := `{"host": "staging.example.com"}`
	if string(newBody) != expected {
		t.Errorf("body = %q, want %q", string(newBody), expected)
	}
}

func TestPipeline_ConcurrentAccess(t *testing.T) {
	p := NewPipeline()

	// Add initial rules.
	for i := 0; i < 10; i++ {
		p.AddRule(Rule{
			ID: fmt.Sprintf("r%d", i), Enabled: true, Priority: i,
			Direction: DirectionBoth,
			Action:    Action{Type: ActionAddHeader, Header: fmt.Sprintf("X-Test-%d", i), Value: "val"},
		})
	}

	var wg sync.WaitGroup
	u, _ := url.Parse("http://example.com/test")

	// Concurrent reads (TransformRequest).
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := http.Header{}
			p.TransformRequest("GET", u, h, nil)
		}()
	}

	// Concurrent reads (TransformResponse).
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := http.Header{}
			p.TransformResponse(200, h, nil)
		}()
	}

	// Concurrent writes.
	for i := 10; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.AddRule(Rule{
				ID: fmt.Sprintf("concurrent-%d", id), Enabled: true, Priority: id,
				Direction: DirectionBoth,
				Action:    Action{Type: ActionAddHeader, Header: fmt.Sprintf("X-C-%d", id), Value: "v"},
			})
		}(i)
	}

	wg.Wait()
}

func TestPipeline_TransformRequest_NoRules(t *testing.T) {
	p := NewPipeline()

	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{"X-Original": {"value"}}
	body := []byte("original body")

	newHeaders, newBody := p.TransformRequest("GET", u, headers, body)

	if got := newHeaders.Get("X-Original"); got != "value" {
		t.Errorf("X-Original = %q, want %q", got, "value")
	}
	if string(newBody) != "original body" {
		t.Errorf("body = %q, want %q", string(newBody), "original body")
	}
}

func TestPipeline_TransformResponse_NoRules(t *testing.T) {
	p := NewPipeline()

	headers := http.Header{"X-Original": {"value"}}
	body := []byte("original body")

	newHeaders, newBody := p.TransformResponse(200, headers, body)

	if got := newHeaders.Get("X-Original"); got != "value" {
		t.Errorf("X-Original = %q, want %q", got, "value")
	}
	if string(newBody) != "original body" {
		t.Errorf("body = %q, want %q", string(newBody), "original body")
	}
}
