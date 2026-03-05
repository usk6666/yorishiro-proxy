package intercept

import (
	"net/http"
	"net/url"
	"strings"
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
					HostPattern: "api\\.example\\.com",
					PathPattern: "/api/admin.*",
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

func TestCompileRule_InvalidPathPattern(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			PathPattern: "[invalid",
		},
	})
	if err == nil {
		t.Fatal("compileRule() expected error for invalid path pattern, got nil")
	}
}

func TestCompileRule_InvalidHostPattern(t *testing.T) {
	_, err := compileRule(Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HostPattern: "[invalid",
		},
	})
	if err == nil {
		t.Fatal("compileRule() expected error for invalid host pattern, got nil")
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

func TestMatchesRequest_PathPattern(t *testing.T) {
	tests := []struct {
		name        string
		pathPattern string
		path        string
		want        bool
	}{
		{
			name:        "exact path match",
			pathPattern: "^/api/admin$",
			path:        "/api/admin",
			want:        true,
		},
		{
			name:        "prefix match with wildcard",
			pathPattern: "/api/admin.*",
			path:        "/api/admin/users",
			want:        true,
		},
		{
			name:        "no match",
			pathPattern: "^/api/admin",
			path:        "/api/public",
			want:        false,
		},
		{
			name:        "empty pattern matches all",
			pathPattern: "",
			path:        "/anything",
			want:        true,
		},
		{
			name:        "nil URL with pattern",
			pathPattern: "/api",
			path:        "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{
				ID:        "test",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					PathPattern: tt.pathPattern,
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

func TestMatchesRequest_HostPattern(t *testing.T) {
	tests := []struct {
		name        string
		hostPattern string
		host        string
		want        bool
	}{
		{
			name:        "exact host match",
			hostPattern: "^httpbin\\.org$",
			host:        "httpbin.org",
			want:        true,
		},
		{
			name:        "subdomain wildcard",
			hostPattern: ".*\\.example\\.com",
			host:        "api.example.com",
			want:        true,
		},
		{
			name:        "no match",
			hostPattern: "^httpbin\\.org$",
			host:        "other.com",
			want:        false,
		},
		{
			name:        "empty pattern matches all",
			hostPattern: "",
			host:        "anything.com",
			want:        true,
		},
		{
			name:        "host with port stripped",
			hostPattern: "^httpbin\\.org$",
			host:        "httpbin.org:8080",
			want:        true,
		},
		{
			name:        "nil URL with pattern falls back to Host header",
			hostPattern: "^httpbin\\.org$",
			host:        "", // will use Host header
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
					HostPattern: tt.hostPattern,
				},
			}
			cr, err := compileRule(r)
			if err != nil {
				t.Fatalf("compileRule() error = %v", err)
			}

			var u *url.URL
			var headers http.Header
			if tt.host != "" {
				u = &url.URL{Host: tt.host}
			} else if tt.hostPattern != "" {
				// Simulate HTTPS MITM where u.Host is empty, use Host header.
				headers = http.Header{"Host": {"httpbin.org"}}
			}

			got := cr.matchesRequest("GET", u, headers)
			if got != tt.want {
				t.Errorf("matchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesRequest_HostPattern_HostHeaderFallback(t *testing.T) {
	r := Rule{
		ID:        "test",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HostPattern: "^target\\.com$",
		},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}

	// URL with empty host (HTTPS MITM scenario).
	u := &url.URL{Path: "/api/test"}
	headers := http.Header{"Host": {"target.com:443"}}

	got := cr.matchesRequest("GET", u, headers)
	if !got {
		t.Error("matchesRequest() should match Host header fallback with port stripped")
	}
}

func TestMatchesRequest_HostPattern_NilURLNilHeaders(t *testing.T) {
	r := Rule{
		ID:        "test",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HostPattern: "anything",
		},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatalf("compileRule() error = %v", err)
	}

	got := cr.matchesRequest("GET", nil, nil)
	if got {
		t.Error("matchesRequest() should not match when URL and headers are nil and host_pattern is set")
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
			HostPattern: "api\\.target\\.com",
			PathPattern: "/api/admin.*",
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
		host    string
		path    string
		headers http.Header
		want    bool
	}{
		{
			name:    "all match",
			method:  "POST",
			host:    "api.target.com",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    true,
		},
		{
			name:    "wrong host",
			method:  "POST",
			host:    "other.com",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name:    "wrong method",
			method:  "GET",
			host:    "api.target.com",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name:    "wrong path",
			method:  "POST",
			host:    "api.target.com",
			path:    "/api/public",
			headers: http.Header{"Content-Type": {"application/json"}},
			want:    false,
		},
		{
			name:    "wrong header",
			method:  "POST",
			host:    "api.target.com",
			path:    "/api/admin/users",
			headers: http.Header{"Content-Type": {"text/html"}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Host: tt.host, Path: tt.path}
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

func TestCompileRule_PatternTooLong(t *testing.T) {
	longPattern := strings.Repeat("a", maxRegexPatternLen+1)
	exactPattern := strings.Repeat("a", maxRegexPatternLen)

	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "host_pattern at max length accepted",
			rule: Rule{
				ID:        "r1",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					HostPattern: exactPattern,
				},
			},
			wantErr: false,
		},
		{
			name: "host_pattern exceeds max length rejected",
			rule: Rule{
				ID:        "r2",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					HostPattern: longPattern,
				},
			},
			wantErr: true,
		},
		{
			name: "path_pattern at max length accepted",
			rule: Rule{
				ID:        "r3",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					PathPattern: exactPattern,
				},
			},
			wantErr: false,
		},
		{
			name: "path_pattern exceeds max length rejected",
			rule: Rule{
				ID:        "r4",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					PathPattern: longPattern,
				},
			},
			wantErr: true,
		},
		{
			name: "header_match pattern at max length accepted",
			rule: Rule{
				ID:        "r5",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					HeaderMatch: map[string]string{"Content-Type": exactPattern},
				},
			},
			wantErr: false,
		},
		{
			name: "header_match pattern exceeds max length rejected",
			rule: Rule{
				ID:        "r6",
				Enabled:   true,
				Direction: DirectionRequest,
				Conditions: Conditions{
					HeaderMatch: map[string]string{"Content-Type": longPattern},
				},
			},
			wantErr: true,
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

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"host only", "example.com", "example.com"},
		{"host with port", "example.com:8080", "example.com"},
		{"ipv4 with port", "127.0.0.1:8080", "127.0.0.1"},
		{"ipv6 with port", "[::1]:8080", "::1"},
		{"ipv6 without port", "[::1]", "::1"},
		{"localhost", "localhost", "localhost"},
		{"localhost with port", "localhost:3000", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostname(tt.input)
			if got != tt.expected {
				t.Errorf("extractHostname(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
