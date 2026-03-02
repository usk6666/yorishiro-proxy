package rules

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCompileRule_ValidRule(t *testing.T) {
	r := Rule{
		ID:        "test-1",
		Enabled:   true,
		Priority:  0,
		Direction: DirectionRequest,
		Conditions: Conditions{
			URLPattern:  "/api/.*",
			Methods:     []string{"GET", "POST"},
			HeaderMatch: map[string]string{"Content-Type": "application/json"},
		},
		Action: Action{
			Type:   ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer token",
		},
	}

	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}
	if cr.urlPatternRe == nil {
		t.Error("urlPatternRe should be compiled")
	}
	if len(cr.headerMatchRes) != 1 {
		t.Errorf("headerMatchRes len = %d, want 1", len(cr.headerMatchRes))
	}
}

func TestCompileRule_EmptyID(t *testing.T) {
	r := Rule{
		Direction: DirectionRequest,
		Action:    Action{Type: ActionRemoveHeader, Header: "X-Test"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestCompileRule_InvalidDirection(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: "invalid",
		Action:    Action{Type: ActionRemoveHeader, Header: "X-Test"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for invalid direction")
	}
}

func TestCompileRule_InvalidActionType(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: "invalid"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for invalid action type")
	}
}

func TestCompileRule_AddHeaderNoName(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: ActionAddHeader, Value: "val"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for add_header without header name")
	}
}

func TestCompileRule_SetHeaderNoName(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: ActionSetHeader, Value: "val"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for set_header without header name")
	}
}

func TestCompileRule_RemoveHeaderNoName(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: ActionRemoveHeader},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for remove_header without header name")
	}
}

func TestCompileRule_ReplaceBodyNoPattern(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: ActionReplaceBody, Value: "replacement"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for replace_body without pattern")
	}
}

func TestCompileRule_InvalidURLPattern(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Conditions: Conditions{
			URLPattern: "[invalid",
		},
		Action: Action{Type: ActionRemoveHeader, Header: "X-Test"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for invalid URL pattern regex")
	}
}

func TestCompileRule_InvalidHeaderMatchPattern(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Conditions: Conditions{
			HeaderMatch: map[string]string{"X-Test": "[invalid"},
		},
		Action: Action{Type: ActionRemoveHeader, Header: "X-Test"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for invalid header match regex")
	}
}

func TestCompileRule_InvalidBodyPattern(t *testing.T) {
	r := Rule{
		ID:        "test",
		Direction: DirectionRequest,
		Action:    Action{Type: ActionReplaceBody, Pattern: "[invalid", Value: "replacement"},
	}
	_, err := compileRule(r)
	if err == nil {
		t.Fatal("expected error for invalid body replacement pattern")
	}
}

func TestCompiledRule_MatchesRequest(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		method  string
		url     string
		headers http.Header
		want    bool
	}{
		{
			name: "match all (empty conditions)",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Action: Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   true,
		},
		{
			name: "match URL pattern on path",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: "/api/.*"},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   true,
		},
		{
			name: "match URL pattern on hostname",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `example\.com`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   true,
		},
		{
			name: "match URL pattern on full URL",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `http://example\.com/api/test`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   true,
		},
		{
			name: "no match URL pattern on hostname",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `other\.com`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   false,
		},
		{
			name: "no match URL pattern",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: "/api/admin"},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/public/test",
			want:   false,
		},
		{
			name: "match method",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{Methods: []string{"POST", "PUT"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "POST",
			url:    "http://example.com/test",
			want:   true,
		},
		{
			name: "no match method",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{Methods: []string{"POST"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/test",
			want:   false,
		},
		{
			name: "method case insensitive",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{Methods: []string{"post"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "POST",
			url:    "http://example.com/test",
			want:   true,
		},
		{
			name: "match header",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{HeaderMatch: map[string]string{"Content-Type": "application/json"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method:  "GET",
			url:     "http://example.com/test",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name: "no match header",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{HeaderMatch: map[string]string{"Content-Type": "application/xml"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method:  "GET",
			url:     "http://example.com/test",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name: "nil headers with header match",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{HeaderMatch: map[string]string{"X-Test": ".*"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method:  "GET",
			url:     "http://example.com/test",
			headers: nil,
			want:    false,
		},
		{
			name: "nil URL",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: "/api/.*"},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "",
			want:   false,
		},
		{
			name: "combined conditions all match",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{
					URLPattern:  `example\.com/api/.*`,
					Methods:     []string{"POST"},
					HeaderMatch: map[string]string{"Content-Type": "json"},
				},
				Action: Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method:  "POST",
			url:     "http://example.com/api/test",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name: "combined conditions partial match",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{
					URLPattern: "/api/.*",
					Methods:    []string{"POST"},
				},
				Action: Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/api/test",
			want:   false,
		},
		{
			name: "match URL pattern with scheme",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `^https://`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "https://example.com/test",
			want:   true,
		},
		{
			name: "no match URL pattern with wrong scheme",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `^https://`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/test",
			want:   false,
		},
		{
			name: "match URL pattern with query string",
			rule: Rule{
				ID: "r1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: `key=value`},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			method: "GET",
			url:    "http://example.com/test?key=value",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := compileRule(tt.rule)
			if err != nil {
				t.Fatalf("compileRule: %v", err)
			}

			var u *url.URL
			if tt.url != "" {
				u, _ = url.Parse(tt.url)
			}

			got := cr.matchesRequest(tt.method, u, tt.headers)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompiledRule_MatchesResponse(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name: "match all (empty conditions)",
			rule: Rule{
				ID: "r1", Direction: DirectionResponse,
				Action: Action{Type: ActionRemoveHeader, Header: "X"},
			},
			statusCode: 200,
			want:       true,
		},
		{
			name: "match header",
			rule: Rule{
				ID: "r1", Direction: DirectionResponse,
				Conditions: Conditions{HeaderMatch: map[string]string{"Content-Type": "text/html"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			statusCode: 200,
			headers:    http.Header{"Content-Type": {"text/html"}},
			want:       true,
		},
		{
			name: "no match header",
			rule: Rule{
				ID: "r1", Direction: DirectionResponse,
				Conditions: Conditions{HeaderMatch: map[string]string{"Content-Type": "text/html"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			statusCode: 200,
			headers:    http.Header{"Content-Type": {"application/json"}},
			want:       false,
		},
		{
			name: "nil headers with header match",
			rule: Rule{
				ID: "r1", Direction: DirectionResponse,
				Conditions: Conditions{HeaderMatch: map[string]string{"X-Test": ".*"}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			statusCode: 200,
			headers:    nil,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := compileRule(tt.rule)
			if err != nil {
				t.Fatalf("compileRule: %v", err)
			}

			got := cr.matchesResponse(tt.statusCode, tt.headers)
			if got != tt.want {
				t.Errorf("matchesResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloneRule(t *testing.T) {
	original := Rule{
		ID:        "test",
		Enabled:   true,
		Priority:  5,
		Direction: DirectionBoth,
		Conditions: Conditions{
			URLPattern:  "/api/.*",
			Methods:     []string{"GET", "POST"},
			HeaderMatch: map[string]string{"X-Test": "value"},
		},
		Action: Action{
			Type:    ActionReplaceBody,
			Pattern: "old",
			Value:   "new",
		},
	}

	cloned := cloneRule(original)

	// Modify original to verify independence.
	original.ID = "modified"
	original.Conditions.Methods[0] = "DELETE"
	original.Conditions.HeaderMatch["X-Test"] = "changed"

	if cloned.ID != "test" {
		t.Errorf("cloned ID = %q, want %q", cloned.ID, "test")
	}
	if cloned.Conditions.Methods[0] != "GET" {
		t.Errorf("cloned Methods[0] = %q, want %q", cloned.Conditions.Methods[0], "GET")
	}
	if cloned.Conditions.HeaderMatch["X-Test"] != "value" {
		t.Errorf("cloned HeaderMatch[X-Test] = %q, want %q", cloned.Conditions.HeaderMatch["X-Test"], "value")
	}
	if cloned.Action.Pattern != "old" {
		t.Errorf("cloned Action.Pattern = %q, want %q", cloned.Action.Pattern, "old")
	}
}

func TestValidateAction(t *testing.T) {
	tests := []struct {
		name    string
		action  Action
		wantErr bool
	}{
		{
			name:    "add_header valid",
			action:  Action{Type: ActionAddHeader, Header: "X-Test", Value: "val"},
			wantErr: false,
		},
		{
			name:    "add_header no header",
			action:  Action{Type: ActionAddHeader, Value: "val"},
			wantErr: true,
		},
		{
			name:    "set_header valid",
			action:  Action{Type: ActionSetHeader, Header: "X-Test", Value: "val"},
			wantErr: false,
		},
		{
			name:    "set_header no header",
			action:  Action{Type: ActionSetHeader},
			wantErr: true,
		},
		{
			name:    "remove_header valid",
			action:  Action{Type: ActionRemoveHeader, Header: "X-Test"},
			wantErr: false,
		},
		{
			name:    "remove_header no header",
			action:  Action{Type: ActionRemoveHeader},
			wantErr: true,
		},
		{
			name:    "replace_body valid",
			action:  Action{Type: ActionReplaceBody, Pattern: "old", Value: "new"},
			wantErr: false,
		},
		{
			name:    "replace_body no pattern",
			action:  Action{Type: ActionReplaceBody, Value: "new"},
			wantErr: true,
		},
		{
			name:    "add_header empty value is valid",
			action:  Action{Type: ActionAddHeader, Header: "X-Test"},
			wantErr: false,
		},
		{
			name:    "add_header CRLF in header name",
			action:  Action{Type: ActionAddHeader, Header: "X-Test\r\nInjected", Value: "val"},
			wantErr: true,
		},
		{
			name:    "add_header LF in header name",
			action:  Action{Type: ActionAddHeader, Header: "X-Test\nInjected", Value: "val"},
			wantErr: true,
		},
		{
			name:    "add_header CR in header value",
			action:  Action{Type: ActionAddHeader, Header: "X-Test", Value: "val\rinjected"},
			wantErr: true,
		},
		{
			name:    "add_header LF in header value",
			action:  Action{Type: ActionAddHeader, Header: "X-Test", Value: "val\ninjected: evil"},
			wantErr: true,
		},
		{
			name:    "set_header CRLF in value",
			action:  Action{Type: ActionSetHeader, Header: "X-Test", Value: "val\r\nX-Injected: evil"},
			wantErr: true,
		},
		{
			name:    "remove_header CRLF in header name",
			action:  Action{Type: ActionRemoveHeader, Header: "X-Test\r\nInjected"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAction(tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAction() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainsCRLF(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"normal-value", false},
		{"", false},
		{"value\r\ninjected", true},
		{"value\ninjected", true},
		{"value\rinjected", true},
		{"\r", true},
		{"\n", true},
	}

	for _, tt := range tests {
		got := containsCRLF(tt.input)
		if got != tt.want {
			t.Errorf("containsCRLF(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestCompileRule_RegexPatternTooLong(t *testing.T) {
	longPattern := strings.Repeat("a", maxRegexPatternLen+1)
	exactPattern := strings.Repeat("a", maxRegexPatternLen)

	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "url_pattern at limit",
			rule: Rule{
				ID: "t1", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: exactPattern},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			wantErr: false,
		},
		{
			name: "url_pattern exceeds limit",
			rule: Rule{
				ID: "t2", Direction: DirectionRequest,
				Conditions: Conditions{URLPattern: longPattern},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			wantErr: true,
		},
		{
			name: "header_match pattern exceeds limit",
			rule: Rule{
				ID: "t3", Direction: DirectionRequest,
				Conditions: Conditions{HeaderMatch: map[string]string{"X-Test": longPattern}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			wantErr: true,
		},
		{
			name: "header_match pattern at limit",
			rule: Rule{
				ID: "t4", Direction: DirectionRequest,
				Conditions: Conditions{HeaderMatch: map[string]string{"X-Test": exactPattern}},
				Action:     Action{Type: ActionRemoveHeader, Header: "X"},
			},
			wantErr: false,
		},
		{
			name: "body replacement pattern exceeds limit",
			rule: Rule{
				ID: "t5", Direction: DirectionRequest,
				Action: Action{Type: ActionReplaceBody, Pattern: longPattern, Value: "new"},
			},
			wantErr: true,
		},
		{
			name: "body replacement pattern at limit",
			rule: Rule{
				ID: "t6", Direction: DirectionRequest,
				Action: Action{Type: ActionReplaceBody, Pattern: exactPattern, Value: "new"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
