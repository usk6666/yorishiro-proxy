package intercept

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestEngine_AddRule(t *testing.T) {
	e := NewEngine()

	err := e.AddRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			PathPattern: "/api/.*",
			Methods:    []string{"POST"},
		},
	})
	if err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	if e.Len() != 1 {
		t.Errorf("Len() = %d, want 1", e.Len())
	}
}

func TestEngine_AddRule_DuplicateID(t *testing.T) {
	e := NewEngine()

	err := e.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
	})
	if err != nil {
		t.Fatalf("first AddRule() error = %v", err)
	}

	err = e.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
	})
	if err == nil {
		t.Fatal("second AddRule() expected duplicate error, got nil")
	}
}

func TestEngine_AddRule_InvalidRule(t *testing.T) {
	e := NewEngine()

	err := e.AddRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: "invalid",
	})
	if err == nil {
		t.Fatal("AddRule() expected error for invalid direction, got nil")
	}
}

func TestEngine_RemoveRule(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "r1", Enabled: true, Direction: DirectionRequest})
	e.AddRule(Rule{ID: "r2", Enabled: true, Direction: DirectionRequest})

	err := e.RemoveRule("r1")
	if err != nil {
		t.Fatalf("RemoveRule() error = %v", err)
	}

	if e.Len() != 1 {
		t.Errorf("Len() = %d, want 1", e.Len())
	}

	rules := e.Rules()
	if len(rules) != 1 || rules[0].ID != "r2" {
		t.Errorf("remaining rule ID = %q, want %q", rules[0].ID, "r2")
	}
}

func TestEngine_RemoveRule_NotFound(t *testing.T) {
	e := NewEngine()

	err := e.RemoveRule("nonexistent")
	if err == nil {
		t.Fatal("RemoveRule() expected error for nonexistent rule, got nil")
	}
}

func TestEngine_EnableRule(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "r1", Enabled: true, Direction: DirectionRequest})

	err := e.EnableRule("r1", false)
	if err != nil {
		t.Fatalf("EnableRule() error = %v", err)
	}

	r, _ := e.GetRule("r1")
	if r.Enabled {
		t.Error("rule should be disabled")
	}

	err = e.EnableRule("r1", true)
	if err != nil {
		t.Fatalf("EnableRule() error = %v", err)
	}

	r, _ = e.GetRule("r1")
	if !r.Enabled {
		t.Error("rule should be enabled")
	}
}

func TestEngine_EnableRule_NotFound(t *testing.T) {
	e := NewEngine()

	err := e.EnableRule("nonexistent", true)
	if err == nil {
		t.Fatal("EnableRule() expected error for nonexistent rule, got nil")
	}
}

func TestEngine_GetRule(t *testing.T) {
	e := NewEngine()

	original := Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			PathPattern:  "/api/.*",
			Methods:     []string{"POST", "PUT"},
			HeaderMatch: map[string]string{"Content-Type": "application/json"},
		},
	}
	e.AddRule(original)

	got, err := e.GetRule("r1")
	if err != nil {
		t.Fatalf("GetRule() error = %v", err)
	}

	if got.ID != original.ID {
		t.Errorf("ID = %q, want %q", got.ID, original.ID)
	}
	if got.Conditions.PathPattern != original.Conditions.PathPattern {
		t.Errorf("PathPattern = %q, want %q", got.Conditions.PathPattern, original.Conditions.PathPattern)
	}

	// Verify it's a copy by modifying the returned rule.
	got.Conditions.Methods[0] = "MODIFIED"
	got2, _ := e.GetRule("r1")
	if got2.Conditions.Methods[0] != "POST" {
		t.Error("GetRule() should return a copy, not a reference")
	}
}

func TestEngine_GetRule_NotFound(t *testing.T) {
	e := NewEngine()

	_, err := e.GetRule("nonexistent")
	if err == nil {
		t.Fatal("GetRule() expected error for nonexistent rule, got nil")
	}
}

func TestEngine_Rules_ReturnsCopy(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "r1", Enabled: true, Direction: DirectionRequest})
	e.AddRule(Rule{ID: "r2", Enabled: true, Direction: DirectionResponse})

	rules := e.Rules()
	if len(rules) != 2 {
		t.Fatalf("Rules() len = %d, want 2", len(rules))
	}

	// Modify the returned slice.
	rules[0].ID = "modified"

	// Original should be unchanged.
	r, _ := e.GetRule("r1")
	if r.ID != "r1" {
		t.Error("Rules() should return copies")
	}
}

func TestEngine_Rules_Empty(t *testing.T) {
	e := NewEngine()

	rules := e.Rules()
	if rules != nil {
		t.Errorf("Rules() = %v, want nil for empty engine", rules)
	}
}

func TestEngine_SetRules(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "old", Enabled: true, Direction: DirectionRequest})

	err := e.SetRules([]Rule{
		{ID: "new1", Enabled: true, Direction: DirectionRequest},
		{ID: "new2", Enabled: false, Direction: DirectionBoth},
	})
	if err != nil {
		t.Fatalf("SetRules() error = %v", err)
	}

	if e.Len() != 2 {
		t.Errorf("Len() = %d, want 2", e.Len())
	}

	_, err = e.GetRule("old")
	if err == nil {
		t.Error("old rule should have been replaced")
	}
}

func TestEngine_SetRules_DuplicateID(t *testing.T) {
	e := NewEngine()

	err := e.SetRules([]Rule{
		{ID: "r1", Enabled: true, Direction: DirectionRequest},
		{ID: "r1", Enabled: true, Direction: DirectionResponse},
	})
	if err == nil {
		t.Fatal("SetRules() expected error for duplicate ID, got nil")
	}
}

func TestEngine_SetRules_InvalidRule(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "existing", Enabled: true, Direction: DirectionRequest})

	err := e.SetRules([]Rule{
		{ID: "valid", Enabled: true, Direction: DirectionRequest},
		{ID: "invalid", Enabled: true, Direction: "bad"},
	})
	if err == nil {
		t.Fatal("SetRules() expected error for invalid rule, got nil")
	}

	// Existing rules should be preserved on error.
	if e.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (existing rules should be preserved on error)", e.Len())
	}
}

func TestEngine_SetRules_EmptySlice(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "r1", Enabled: true, Direction: DirectionRequest})

	err := e.SetRules([]Rule{})
	if err != nil {
		t.Fatalf("SetRules() error = %v", err)
	}

	if e.Len() != 0 {
		t.Errorf("Len() = %d, want 0", e.Len())
	}
}

func TestEngine_MatchesRequest_ORLogic(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "admin-api",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			PathPattern: "/api/admin.*",
		},
	})
	e.AddRule(Rule{
		ID:        "json-posts",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			Methods:     []string{"POST"},
			HeaderMatch: map[string]string{"Content-Type": "application/json"},
		},
	})

	tests := []struct {
		name    string
		method  string
		path    string
		headers http.Header
		want    bool
	}{
		{
			name:   "matches first rule only",
			method: "GET",
			path:   "/api/admin/users",
			want:   true,
		},
		{
			name:    "matches second rule only",
			method:  "POST",
			path:    "/api/public",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name:    "matches both rules",
			method:  "POST",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name:   "matches neither",
			method: "GET",
			path:   "/api/public",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Path: tt.path}
			got := e.MatchesRequest(tt.method, u, tt.headers)
			if got != tt.want {
				t.Errorf("MatchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_MatchesRequest_DisabledRuleSkipped(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "disabled",
		Enabled:   false,
		Direction: DirectionRequest,
		Conditions: Conditions{
			PathPattern: ".*",
		},
	})

	u := &url.URL{Path: "/anything"}
	if e.MatchesRequest("GET", u, nil) {
		t.Error("disabled rule should not match")
	}
}

func TestEngine_MatchesRequest_DirectionFilter(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "response-only",
		Enabled:   true,
		Direction: DirectionResponse,
		Conditions: Conditions{
			HeaderMatch: map[string]string{"Content-Type": ".*"},
		},
	})

	u := &url.URL{Path: "/api"}
	headers := http.Header{"Content-Type": {"text/html"}}
	if e.MatchesRequest("GET", u, headers) {
		t.Error("response-only rule should not match requests")
	}
}

func TestEngine_MatchesRequest_BothDirection(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "both",
		Enabled:   true,
		Direction: DirectionBoth,
		Conditions: Conditions{
			PathPattern: "/api/.*",
		},
	})

	u := &url.URL{Path: "/api/test"}
	if !e.MatchesRequest("GET", u, nil) {
		t.Error("both-direction rule should match requests")
	}
}

func TestEngine_MatchesResponse(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "html-responses",
		Enabled:   true,
		Direction: DirectionResponse,
		Conditions: Conditions{
			HeaderMatch: map[string]string{"Content-Type": "text/html"},
		},
	})

	tests := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{
			name:    "matching response",
			headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			want:    true,
		},
		{
			name:    "non-matching response",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.MatchesResponse(200, tt.headers)
			if got != tt.want {
				t.Errorf("MatchesResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_MatchesResponse_RequestOnlySkipped(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID:        "request-only",
		Enabled:   true,
		Direction: DirectionRequest,
	})

	if e.MatchesResponse(200, http.Header{}) {
		t.Error("request-only rule should not match responses")
	}
}

func TestEngine_MatchRequestRules(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Conditions: Conditions{PathPattern: "/api/.*"},
	})
	e.AddRule(Rule{
		ID: "r2", Enabled: true, Direction: DirectionRequest,
		Conditions: Conditions{Methods: []string{"POST"}},
	})
	e.AddRule(Rule{
		ID: "r3", Enabled: false, Direction: DirectionRequest,
		Conditions: Conditions{PathPattern: ".*"},
	})

	u := &url.URL{Path: "/api/users"}
	matched := e.MatchRequestRules("POST", u, nil)

	if len(matched) != 2 {
		t.Fatalf("MatchRequestRules() len = %d, want 2", len(matched))
	}
	if matched[0] != "r1" || matched[1] != "r2" {
		t.Errorf("MatchRequestRules() = %v, want [r1, r2]", matched)
	}
}

func TestEngine_MatchResponseRules(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{
		ID: "r1", Enabled: true, Direction: DirectionResponse,
		Conditions: Conditions{HeaderMatch: map[string]string{"Content-Type": "text/html"}},
	})
	e.AddRule(Rule{
		ID: "r2", Enabled: true, Direction: DirectionBoth,
	})

	headers := http.Header{"Content-Type": {"text/html"}}
	matched := e.MatchResponseRules(200, headers)

	if len(matched) != 2 {
		t.Fatalf("MatchResponseRules() len = %d, want 2", len(matched))
	}
}

func TestEngine_Clear(t *testing.T) {
	e := NewEngine()

	e.AddRule(Rule{ID: "r1", Enabled: true, Direction: DirectionRequest})
	e.AddRule(Rule{ID: "r2", Enabled: true, Direction: DirectionRequest})

	e.Clear()

	if e.Len() != 0 {
		t.Errorf("Len() after Clear = %d, want 0", e.Len())
	}
}

func TestEngine_NoRules_NoMatch(t *testing.T) {
	e := NewEngine()

	u := &url.URL{Path: "/anything"}
	if e.MatchesRequest("GET", u, nil) {
		t.Error("empty engine should not match")
	}
	if e.MatchesResponse(200, nil) {
		t.Error("empty engine should not match")
	}
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	e := NewEngine()

	// Pre-populate some rules.
	for i := 0; i < 10; i++ {
		e.AddRule(Rule{
			ID:        fmt.Sprintf("r%d", i),
			Enabled:   true,
			Direction: DirectionRequest,
			Conditions: Conditions{
				PathPattern: "/api/.*",
			},
		})
	}

	var wg sync.WaitGroup

	// Concurrent readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := &url.URL{Path: "/api/test"}
			for j := 0; j < 100; j++ {
				e.MatchesRequest("GET", u, nil)
				e.Rules()
				e.Len()
			}
		}()
	}

	// Concurrent writers.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ruleID := fmt.Sprintf("concurrent-%d", id)
			for j := 0; j < 20; j++ {
				e.AddRule(Rule{
					ID:        fmt.Sprintf("%s-%d", ruleID, j),
					Enabled:   true,
					Direction: DirectionRequest,
				})
			}
		}(i)
	}

	wg.Wait()
}
