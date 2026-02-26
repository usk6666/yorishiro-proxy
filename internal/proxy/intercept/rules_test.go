package intercept

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCompileRule_ValidRule(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
	}{
		{
			name: "minimal rule with request direction",
			rule: Rule{
				ID:        "r1",
				Enabled:   true,
				Direction: DirectionRequest,
			},
		},
		{
			name: "rule with all conditions",
			rule: Rule{
				ID:        "r2",
				Enabled:   true,
				Direction: DirectionBoth,
				Conditions: Conditions{
					URLPattern:  "/api/admin.*",
					Methods:     []string{"POST", "PUT", "DELETE"},
					HeaderMatch: map[string]string{"Content-Type": "application/json"},
				},
			},
		},
		{
			name: "disabled rule",
			rule: Rule{
				ID:        "r3",
				Enabled:   false,
				Direction: DirectionResponse,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := compileRule(tt.rule)
			if err != nil {
				t.Fatalf("compileRule() error = %v", err)
			}
			if cr.rule.ID != tt.rule.ID {
				t.Errorf("compiled rule ID = %q, want %q", cr.rule.ID, tt.rule.ID)
			}
		})
	}
}

func TestCompileRule_EmptyID(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "",
		Enabled:   true,
		Direction: DirectionRequest,
	})
	if err == nil {
		t.Fatal("compileRule() expected error for empty ID, got nil")
	}
}

func TestCompileRule_InvalidDirection(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: "invalid",
	})
	if err == nil {
		t.Fatal("compileRule() expected error for invalid direction, got nil")
	}
}

func TestCompileRule_InvalidURLPattern(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			URLPattern: "[invalid",
		},
	})
	if err == nil {
		t.Fatal("compileRule() expected error for invalid URL pattern, got nil")
	}
}

func TestCompileRule_InvalidHeaderPattern(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HeaderMatch: map[string]string{"Content-Type": "[invalid"},
		},
	})
	if err == nil {
		t.Fatal("compileRule() expected error for invalid header pattern, got nil")
	}
}

func TestMatchesRequest_URLPattern(t *testing.T) {
	tests := []struct {
		name       string
		urlPattern string
		path       string
		want       bool
	}{
		{
			name:       "exact path match",
			urlPattern: "^/api/admin$",
			path:       "/api/admin",
			want:       true,
		},
		{
			name:       "prefix match with wildcard",
			urlPattern: "/api/admin.*",
			path:       "/api/admin/users",
			want:       true,
		},
		{
			name:       "no match",
			urlPattern: "^/api/admin",
			path:       "/api/public",
			want:       false,
		},
		{
			name:       "empty pattern matches all",
			urlPattern: "",
			path:       "/anything",
			want:       true,
		},
		{
			name:       "nil URL with pattern",
			urlPattern: "/api",
			path:       "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{
				ID:        "test",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					URLPattern: tt.urlPattern,
				},
			}
			cr, err := compileRule(r)
			if err != nil {
				t.Fatalf("compileRule() error = %v", err)
			}

			var u *url.URL
			if tt.path != "" {
				u = &url.URL{Path: tt.path}
			}

			got := cr.matchesRequest("GET", u, nil)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRequest_Methods(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		method  string
		want    bool
	}{
		{
			name:    "matching method",
			methods: []string{"POST", "PUT"},
			method:  "POST",
			want:    true,
		},
		{
			name:    "case insensitive match",
			methods: []string{"post"},
			method:  "POST",
			want:    true,
		},
		{
			name:    "non-matching method",
			methods: []string{"POST", "PUT"},
			method:  "GET",
			want:    false,
		},
		{
			name:    "empty methods matches all",
			methods: nil,
			method:  "DELETE",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{
				ID:        "test",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					Methods: tt.methods,
				},
			}
			cr, err := compileRule(r)
			if err != nil {
				t.Fatalf("compileRule() error = %v", err)
			}

			got := cr.matchesRequest(tt.method, nil, nil)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRequest_HeaderMatch(t *testing.T) {
	tests := []struct {
		name        string
		headerMatch map[string]string
		headers     http.Header
		want        bool
	}{
		{
			name:        "matching single header",
			headerMatch: map[string]string{"Content-Type": "application/json"},
			headers:     http.Header{"Content-Type": {"application/json"}},
			want:        true,
		},
		{
			name:        "regex header match",
			headerMatch: map[string]string{"Content-Type": "application/(json|xml)"},
			headers:     http.Header{"Content-Type": {"application/xml"}},
			want:        true,
		},
		{
			name:        "non-matching header",
			headerMatch: map[string]string{"Content-Type": "application/json"},
			headers:     http.Header{"Content-Type": {"text/html"}},
			want:        false,
		},
		{
			name:        "missing header",
			headerMatch: map[string]string{"X-Custom": "value"},
			headers:     http.Header{},
			want:        false,
		},
		{
			name:        "nil headers with header match",
			headerMatch: map[string]string{"Content-Type": "application/json"},
			headers:     nil,
			want:        false,
		},
		{
			name:        "case insensitive header name",
			headerMatch: map[string]string{"content-type": "application/json"},
			headers:     http.Header{"Content-Type": {"application/json"}},
			want:        true,
		},
		{
			name:        "multiple headers AND logic",
			headerMatch: map[string]string{"Content-Type": "application/json", "Authorization": "Bearer.*"},
			headers:     http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer token123"}},
			want:        true,
		},
		{
			name:        "multiple headers one missing",
			headerMatch: map[string]string{"Content-Type": "application/json", "Authorization": "Bearer.*"},
			headers:     http.Header{"Content-Type": {"application/json"}},
			want:        false,
		},
		{
			name:        "empty header match matches all",
			headerMatch: nil,
			headers:     http.Header{"Content-Type": {"anything"}},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{
				ID:        "test",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					HeaderMatch: tt.headerMatch,
				},
			}
			cr, err := compileRule(r)
			if err != nil {
				t.Fatalf("compileRule() error = %v", err)
			}

			got := cr.matchesRequest("GET", nil, tt.headers)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRequest_CombinedConditions(t *testing.T) {
	r := Rule{
		ID:        "combined",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			URLPattern:  "/api/admin.*",
			Methods:     []string{"POST", "PUT", "DELETE"},
			HeaderMatch: map[string]string{"Content-Type": "application/json"},
		},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}

	tests := []struct {
		name    string
		method  string
		path    string
		headers http.Header
		want    bool
	}{
		{
			name:    "all match",
			method:  "POST",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name:    "wrong method",
			method:  "GET",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name:    "wrong path",
			method:  "POST",
			path:    "/api/public",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name:    "wrong header",
			method:  "POST",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"text/html"}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Path: tt.path}
			got := cr.matchesRequest(tt.method, u, tt.headers)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesResponse_HeaderMatch(t *testing.T) {
	r := Rule{
		ID:        "resp",
		Enabled:   true,
		Direction: DirectionResponse,
		Conditions: Conditions{
			HeaderMatch: map[string]string{"Content-Type": "text/html"},
		},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}

	tests := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{
			name:    "matching response header",
			headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			want:    true,
		},
		{
			name:    "non-matching response header",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cr.matchesResponse(200, tt.headers)
			if got != tt.want {
				t.Errorf("matchesResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesResponse_NoConditions(t *testing.T) {
	r := Rule{
		ID:        "resp-all",
		Enabled:   true,
		Direction: DirectionResponse,
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}

	got := cr.matchesResponse(404, http.Header{"Content-Type": {"text/html"}})
	if !got {
		t.Error("matchesResponse() with no conditions should match all responses")
	}
}
