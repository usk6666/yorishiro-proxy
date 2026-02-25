package proxy

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestNewCaptureScope(t *testing.T) {
	s := NewCaptureScope()
	if s == nil {
		t.Fatal("NewCaptureScope returned nil")
	}
	if !s.IsEmpty() {
		t.Error("new CaptureScope should be empty")
	}
}

func TestCaptureScope_ShouldCapture_NoRules(t *testing.T) {
	s := NewCaptureScope()

	// With no rules, everything should be captured.
	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"any GET request", "GET", "http://example.com/path", true},
		{"any POST request", "POST", "https://api.example.com/data", true},
		{"any DELETE request", "DELETE", "http://internal.local/admin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_IncludeOnly(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{
			{Hostname: "example.com"},
			{Hostname: "api.example.com"},
		},
		nil,
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"included hostname", "GET", "http://example.com/path", true},
		{"included subdomain", "POST", "https://api.example.com/data", true},
		{"excluded hostname", "GET", "http://other.com/path", false},
		{"unrelated domain", "GET", "http://google.com/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_ExcludeOnly(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		nil,
		[]ScopeRule{
			{Hostname: "ads.example.com"},
			{Hostname: "tracking.com"},
		},
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"non-excluded domain", "GET", "http://example.com/path", true},
		{"excluded domain", "GET", "http://ads.example.com/banner", false},
		{"another excluded domain", "POST", "https://tracking.com/pixel", false},
		{"unrelated domain", "GET", "http://api.example.com/data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_IncludeAndExclude(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{
			{Hostname: "*.example.com"},
		},
		[]ScopeRule{
			{Hostname: "ads.example.com"},
		},
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"included subdomain", "GET", "http://api.example.com/path", true},
		{"excluded subdomain overrides include", "GET", "http://ads.example.com/banner", false},
		{"another included subdomain", "POST", "https://www.example.com/data", true},
		{"non-matching domain", "GET", "http://other.com/path", false},
		{"bare domain not matched by wildcard", "GET", "http://example.com/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_MethodFilter(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{
			{Method: "GET"},
			{Method: "POST"},
		},
		nil,
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"GET matches", "GET", "http://example.com/path", true},
		{"POST matches", "POST", "http://example.com/path", true},
		{"DELETE not included", "DELETE", "http://example.com/path", false},
		{"case insensitive", "get", "http://example.com/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_URLPrefixFilter(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{
			{URLPrefix: "/api/"},
		},
		nil,
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"matches prefix", "GET", "http://example.com/api/v1/users", true},
		{"exact prefix", "GET", "http://example.com/api/", true},
		{"no match", "GET", "http://example.com/static/logo.png", false},
		{"partial prefix no match", "GET", "http://example.com/apiv2/data", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_CombinedFieldsInRule(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{
			{Hostname: "api.example.com", Method: "POST", URLPrefix: "/v2/"},
		},
		nil,
	)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"all fields match", "POST", "http://api.example.com/v2/data", true},
		{"wrong method", "GET", "http://api.example.com/v2/data", false},
		{"wrong hostname", "POST", "http://other.com/v2/data", false},
		{"wrong path", "POST", "http://api.example.com/v1/data", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture(tt.method, u); got != tt.want {
				t.Errorf("ShouldCapture(%q, %q) = %v, want %v", tt.method, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_WildcardHostname(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		hostname string
		rawURL   string
		want     bool
	}{
		{"wildcard matches subdomain", "*.example.com", "sub.example.com", "http://sub.example.com/path", true},
		{"wildcard matches deep subdomain", "*.example.com", "a.b.example.com", "http://a.b.example.com/path", true},
		{"wildcard does not match bare domain", "*.example.com", "example.com", "http://example.com/path", false},
		{"exact match", "example.com", "example.com", "http://example.com/path", true},
		{"exact does not match subdomain", "example.com", "sub.example.com", "http://sub.example.com/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCaptureScope()
			s.SetRules([]ScopeRule{{Hostname: tt.pattern}}, nil)

			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			if got := s.ShouldCapture("GET", u); got != tt.want {
				t.Errorf("ShouldCapture(GET, %q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ShouldCapture_NilURL(t *testing.T) {
	s := NewCaptureScope()

	// No rules: nil URL should be captured.
	if got := s.ShouldCapture("GET", nil); !got {
		t.Error("ShouldCapture with nil URL and no rules should return true")
	}

	// With hostname rule: nil URL should not match.
	s.SetRules([]ScopeRule{{Hostname: "example.com"}}, nil)
	if got := s.ShouldCapture("GET", nil); got {
		t.Error("ShouldCapture with nil URL and hostname rule should return false")
	}
}

func TestCaptureScope_SetRules_And_Rules(t *testing.T) {
	s := NewCaptureScope()

	includes := []ScopeRule{{Hostname: "a.com"}, {Method: "POST"}}
	excludes := []ScopeRule{{Hostname: "b.com"}}

	s.SetRules(includes, excludes)

	gotInc, gotExc := s.Rules()

	if len(gotInc) != 2 {
		t.Errorf("expected 2 include rules, got %d", len(gotInc))
	}
	if len(gotExc) != 1 {
		t.Errorf("expected 1 exclude rule, got %d", len(gotExc))
	}

	// Verify that modifying the returned slice does not affect the scope.
	gotInc[0].Hostname = "modified.com"
	inc2, _ := s.Rules()
	if inc2[0].Hostname == "modified.com" {
		t.Error("Rules() should return a copy, not a reference")
	}
}

func TestCaptureScope_Clear(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{{Hostname: "example.com"}},
		[]ScopeRule{{Hostname: "other.com"}},
	)

	if s.IsEmpty() {
		t.Error("scope should not be empty after SetRules")
	}

	s.Clear()

	if !s.IsEmpty() {
		t.Error("scope should be empty after Clear")
	}

	// After clear, all requests should be captured.
	u, _ := url.Parse("http://anything.com/path")
	if !s.ShouldCapture("GET", u) {
		t.Error("after Clear, all requests should be captured")
	}
}

func TestCaptureScope_ShouldCaptureRequest(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{{Hostname: "target.com"}}, nil)

	tests := []struct {
		name   string
		method string
		rawURL string
		want   bool
	}{
		{"matching request", "GET", "http://target.com/api", true},
		{"non-matching request", "GET", "http://other.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			req := &http.Request{Method: tt.method, URL: u}
			if got := s.ShouldCaptureRequest(req); got != tt.want {
				t.Errorf("ShouldCaptureRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCaptureScope_ConcurrentAccess(t *testing.T) {
	s := NewCaptureScope()
	u, _ := url.Parse("http://example.com/path")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			s.ShouldCapture("GET", u)
		}()
		go func() {
			defer wg.Done()
			s.SetRules([]ScopeRule{{Hostname: "example.com"}}, nil)
		}()
		go func() {
			defer wg.Done()
			s.Rules()
		}()
	}
	wg.Wait()
}

func TestCaptureScope_ExcludePrecedence(t *testing.T) {
	// When a request matches both include and exclude, exclude wins.
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{{Hostname: "example.com"}},
		[]ScopeRule{{Hostname: "example.com", URLPrefix: "/admin/"}},
	)

	tests := []struct {
		name   string
		rawURL string
		want   bool
	}{
		{"included and not excluded", "http://example.com/api/data", true},
		{"included but excluded by path", "http://example.com/admin/settings", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			if got := s.ShouldCapture("GET", u); got != tt.want {
				t.Errorf("ShouldCapture(GET, %q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"case insensitive", "Example.COM", "example.com", true},
		{"no match", "example.com", "other.com", false},
		{"wildcard match", "*.example.com", "sub.example.com", true},
		{"wildcard deep", "*.example.com", "a.b.example.com", true},
		{"wildcard no bare", "*.example.com", "example.com", false},
		{"empty hostname", "example.com", "", false},
		{"empty pattern", "", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchHostname(tt.pattern, tt.hostname); got != tt.want {
				t.Errorf("matchHostname(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
			}
		})
	}
}

func TestMatchURLPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		rawURL string
		want   bool
	}{
		{"matches", "/api/", "http://example.com/api/v1", true},
		{"no match", "/api/", "http://example.com/static/", false},
		{"root", "/", "http://example.com/anything", true},
		{"exact", "/api", "http://example.com/api", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			if got := matchURLPrefix(tt.prefix, u); got != tt.want {
				t.Errorf("matchURLPrefix(%q, %q) = %v, want %v", tt.prefix, tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestMatchURLPrefix_NilURL(t *testing.T) {
	if matchURLPrefix("/api/", nil) {
		t.Error("matchURLPrefix with nil URL should return false")
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{"with port", "http://example.com:8080/path", "example.com"},
		{"without port", "http://example.com/path", "example.com"},
		{"https", "https://secure.example.com/path", "secure.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			if got := extractHostname(u); got != tt.want {
				t.Errorf("extractHostname(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestExtractHostname_NilURL(t *testing.T) {
	if got := extractHostname(nil); got != "" {
		t.Errorf("extractHostname(nil) = %q, want empty", got)
	}
}

func TestCaptureScope_SetRules_NilSlices(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(nil, nil)

	if !s.IsEmpty() {
		t.Error("SetRules(nil, nil) should leave scope empty")
	}

	u, _ := url.Parse("http://example.com/path")
	if !s.ShouldCapture("GET", u) {
		t.Error("empty scope should capture all")
	}
}

func TestCaptureScope_SetRules_EmptySlices(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{}, []ScopeRule{})

	// Empty slices are treated as "no rules" (different from nil internally
	// but functionally equivalent for IsEmpty check: len == 0).
	u, _ := url.Parse("http://example.com/path")
	if !s.ShouldCapture("GET", u) {
		t.Error("scope with empty rule slices should capture all")
	}
}

func TestCaptureScope_HostnameWithPort(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{{Hostname: "example.com"}}, nil)

	// URL with port; hostname extraction should strip port.
	u, _ := url.Parse("http://example.com:8080/path")
	if !s.ShouldCapture("GET", u) {
		t.Error("hostname matching should ignore port in URL")
	}
}

func TestCaptureScope_MergeRules_AddIncludes(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{{Hostname: "existing.com"}}, nil)

	s.MergeRules(
		[]ScopeRule{{Hostname: "new.com"}},
		nil, nil, nil,
	)

	includes, _ := s.Rules()
	if len(includes) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(includes))
	}
}

func TestCaptureScope_MergeRules_RemoveIncludes(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{{Hostname: "a.com"}, {Hostname: "b.com"}}, nil)

	s.MergeRules(
		nil,
		[]ScopeRule{{Hostname: "a.com"}},
		nil, nil,
	)

	includes, _ := s.Rules()
	if len(includes) != 1 {
		t.Fatalf("expected 1 include, got %d", len(includes))
	}
	if includes[0].Hostname != "b.com" {
		t.Errorf("expected b.com, got %q", includes[0].Hostname)
	}
}

func TestCaptureScope_MergeRules_AddExcludes(t *testing.T) {
	s := NewCaptureScope()

	s.MergeRules(
		nil, nil,
		[]ScopeRule{{Hostname: "cdn.com"}},
		nil,
	)

	_, excludes := s.Rules()
	if len(excludes) != 1 {
		t.Fatalf("expected 1 exclude, got %d", len(excludes))
	}
	if excludes[0].Hostname != "cdn.com" {
		t.Errorf("expected cdn.com, got %q", excludes[0].Hostname)
	}
}

func TestCaptureScope_MergeRules_RemoveExcludes(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(nil, []ScopeRule{{Hostname: "old.com"}, {Hostname: "keep.com"}})

	s.MergeRules(
		nil, nil,
		nil,
		[]ScopeRule{{Hostname: "old.com"}},
	)

	_, excludes := s.Rules()
	if len(excludes) != 1 {
		t.Fatalf("expected 1 exclude, got %d", len(excludes))
	}
	if excludes[0].Hostname != "keep.com" {
		t.Errorf("expected keep.com, got %q", excludes[0].Hostname)
	}
}

func TestCaptureScope_MergeRules_DuplicateSkipped(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules([]ScopeRule{{Hostname: "existing.com"}}, nil)

	s.MergeRules(
		[]ScopeRule{{Hostname: "existing.com"}},
		nil, nil, nil,
	)

	includes, _ := s.Rules()
	if len(includes) != 1 {
		t.Errorf("expected 1 include (duplicate should be skipped), got %d", len(includes))
	}
}

func TestCaptureScope_MergeRules_CombinedDeltas(t *testing.T) {
	s := NewCaptureScope()
	s.SetRules(
		[]ScopeRule{{Hostname: "keep.com"}, {Hostname: "remove.com"}},
		[]ScopeRule{{Hostname: "old-cdn.com"}},
	)

	s.MergeRules(
		[]ScopeRule{{Hostname: "add.com"}},
		[]ScopeRule{{Hostname: "remove.com"}},
		[]ScopeRule{{Hostname: "new-cdn.com"}},
		[]ScopeRule{{Hostname: "old-cdn.com"}},
	)

	includes, excludes := s.Rules()
	if len(includes) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(includes))
	}
	if len(excludes) != 1 {
		t.Fatalf("expected 1 exclude, got %d", len(excludes))
	}
	if excludes[0].Hostname != "new-cdn.com" {
		t.Errorf("expected new-cdn.com, got %q", excludes[0].Hostname)
	}
}

func TestCaptureScope_MergeRules_ConcurrentAccess(t *testing.T) {
	s := NewCaptureScope()
	u, _ := url.Parse("http://example.com/path")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			s.MergeRules(
				[]ScopeRule{{Hostname: "a.com"}},
				[]ScopeRule{{Hostname: "b.com"}},
				nil, nil,
			)
		}()
		go func() {
			defer wg.Done()
			s.ShouldCapture("GET", u)
		}()
		go func() {
			defer wg.Done()
			s.Rules()
		}()
	}
	wg.Wait()
}
