package proxy

import (
	"net/url"
	"sync"
	"testing"
)

func TestNewTargetScope(t *testing.T) {
	s := NewTargetScope()
	if s == nil {
		t.Fatal("NewTargetScope returned nil")
	}
	if s.HasRules() {
		t.Error("new TargetScope should have no rules")
	}
}

func TestTargetScope_CheckTarget_NoRules(t *testing.T) {
	s := NewTargetScope()

	// With no rules, everything should be allowed (open by default).
	tests := []struct {
		name     string
		scheme   string
		hostname string
		port     int
		path     string
	}{
		{"any http target", "http", "example.com", 80, "/path"},
		{"any https target", "https", "api.example.com", 443, "/data"},
		{"custom port", "http", "internal.local", 8080, "/admin"},
		{"empty values", "", "", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if !allowed {
				t.Errorf("CheckTarget(%q, %q, %d, %q) blocked with reason %q, want allowed",
					tt.scheme, tt.hostname, tt.port, tt.path, reason)
			}
			if reason != "" {
				t.Errorf("CheckTarget allowed but reason = %q, want empty", reason)
			}
		})
	}
}

func TestTargetScope_CheckTarget_AllowsOnly(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com"},
			{Hostname: "api.example.com"},
		},
		nil,
	)

	tests := []struct {
		name       string
		scheme     string
		hostname   string
		port       int
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"allowed hostname", "http", "example.com", 80, "/path", true, ""},
		{"allowed subdomain", "https", "api.example.com", 443, "/data", true, ""},
		{"not in allow list", "http", "other.com", 80, "/path", false, "not in allow list"},
		{"unrelated domain", "http", "google.com", 80, "/", false, "not in allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d, %q) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_CheckTarget_DeniesOnly(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		nil,
		[]TargetRule{
			{Hostname: "malicious.com"},
			{Hostname: "ads.example.com"},
		},
	)

	tests := []struct {
		name       string
		scheme     string
		hostname   string
		port       int
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"non-denied domain", "http", "example.com", 80, "/path", true, ""},
		{"denied domain", "http", "malicious.com", 80, "/exploit", false, "denied by target scope"},
		{"another denied domain", "https", "ads.example.com", 443, "/banner", false, "denied by target scope"},
		{"unrelated domain allowed", "http", "api.example.com", 80, "/data", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d, %q) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_CheckTarget_AllowsAndDenies(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "*.example.com"},
		},
		[]TargetRule{
			{Hostname: "admin.example.com"},
		},
	)

	tests := []struct {
		name       string
		scheme     string
		hostname   string
		port       int
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"allowed subdomain", "http", "api.example.com", 80, "/path", true, ""},
		{"denied subdomain overrides allow", "http", "admin.example.com", 80, "/settings", false, "denied by target scope"},
		{"another allowed subdomain", "https", "www.example.com", 443, "/data", true, ""},
		{"non-matching domain", "http", "other.com", 80, "/path", false, "not in allow list"},
		{"bare domain not matched by wildcard", "http", "example.com", 80, "/path", false, "not in allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d, %q) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_CheckTarget_WildcardHostname(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		hostname  string
		wantAllow bool
	}{
		{"wildcard matches subdomain", "*.example.com", "sub.example.com", true},
		{"wildcard matches deep subdomain", "*.example.com", "a.b.example.com", true},
		{"wildcard does not match bare domain", "*.example.com", "example.com", false},
		{"exact match", "example.com", "example.com", true},
		{"exact does not match subdomain", "example.com", "sub.example.com", false},
		{"case insensitive wildcard", "*.Example.COM", "sub.example.com", true},
		{"case insensitive exact", "EXAMPLE.COM", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetRules([]TargetRule{{Hostname: tt.pattern}}, nil)

			allowed, _ := s.CheckTarget("http", tt.hostname, 80, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with hostname %q (pattern %q) allowed = %v, want %v",
					tt.hostname, tt.pattern, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_CheckTarget_PortFilter(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Ports: []int{80, 443}},
		},
		nil,
	)

	tests := []struct {
		name      string
		port      int
		wantAllow bool
	}{
		{"port 80 allowed", 80, true},
		{"port 443 allowed", 443, true},
		{"port 8080 not allowed", 8080, false},
		{"port 0 not allowed", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget("http", "example.com", tt.port, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with port %d: allowed = %v, want %v",
					tt.port, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_CheckTarget_EmptyPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Ports: nil},
		},
		nil,
	)

	// Nil ports means all ports match.
	for _, port := range []int{80, 443, 8080, 9999, 0} {
		allowed, _ := s.CheckTarget("http", "example.com", port, "/")
		if !allowed {
			t.Errorf("CheckTarget with nil ports and port %d: should be allowed", port)
		}
	}

	// Empty slice also means all ports match.
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Ports: []int{}},
		},
		nil,
	)

	for _, port := range []int{80, 443, 8080} {
		allowed, _ := s.CheckTarget("http", "example.com", port, "/")
		if !allowed {
			t.Errorf("CheckTarget with empty ports and port %d: should be allowed", port)
		}
	}
}

func TestTargetScope_CheckTarget_PathPrefixFilter(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", PathPrefix: "/api/"},
		},
		nil,
	)

	tests := []struct {
		name      string
		path      string
		wantAllow bool
	}{
		{"matches prefix", "/api/v1/users", true},
		{"exact prefix", "/api/", true},
		{"no match", "/static/logo.png", false},
		{"partial no match", "/apiv2/data", false},
		{"empty path no match", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget("http", "example.com", 80, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with path %q: allowed = %v, want %v",
					tt.path, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_CheckTarget_EmptyPathPrefix(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", PathPrefix: ""},
		},
		nil,
	)

	// Empty PathPrefix means all paths match.
	for _, path := range []string{"/", "/api/v1", "/admin", ""} {
		allowed, _ := s.CheckTarget("http", "example.com", 80, path)
		if !allowed {
			t.Errorf("CheckTarget with empty PathPrefix and path %q: should be allowed", path)
		}
	}
}

func TestTargetScope_CheckTarget_SchemeFilter(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Schemes: []string{"https"}},
		},
		nil,
	)

	tests := []struct {
		name      string
		scheme    string
		wantAllow bool
	}{
		{"https allowed", "https", true},
		{"http not allowed", "http", false},
		{"case insensitive", "HTTPS", true},
		{"empty scheme not allowed", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget(tt.scheme, "example.com", 443, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with scheme %q: allowed = %v, want %v",
					tt.scheme, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_CheckTarget_EmptySchemes(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Schemes: nil},
		},
		nil,
	)

	// Nil schemes means all schemes match.
	for _, scheme := range []string{"http", "https", "ftp", ""} {
		allowed, _ := s.CheckTarget(scheme, "example.com", 80, "/")
		if !allowed {
			t.Errorf("CheckTarget with nil schemes and scheme %q: should be allowed", scheme)
		}
	}
}

func TestTargetScope_CheckTarget_CombinedFields(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{
				Hostname:   "api.example.com",
				Ports:      []int{443},
				PathPrefix: "/v2/",
				Schemes:    []string{"https"},
			},
		},
		nil,
	)

	tests := []struct {
		name       string
		scheme     string
		hostname   string
		port       int
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"all fields match", "https", "api.example.com", 443, "/v2/data", true, ""},
		{"wrong scheme", "http", "api.example.com", 443, "/v2/data", false, "not in allow list"},
		{"wrong hostname", "https", "other.com", 443, "/v2/data", false, "not in allow list"},
		{"wrong port", "https", "api.example.com", 80, "/v2/data", false, "not in allow list"},
		{"wrong path", "https", "api.example.com", 443, "/v1/data", false, "not in allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d, %q) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_CheckTarget_DenyWithPortAndPath(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		nil,
		[]TargetRule{
			{Hostname: "example.com", Ports: []int{8080}, PathPrefix: "/admin/"},
		},
	)

	tests := []struct {
		name      string
		port      int
		path      string
		wantAllow bool
	}{
		{"denied port and path", 8080, "/admin/settings", false},
		{"different port allowed", 80, "/admin/settings", true},
		{"different path allowed", 8080, "/api/data", true},
		{"both different allowed", 443, "/api/data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget("http", "example.com", tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with port %d, path %q: allowed = %v, want %v",
					tt.port, tt.path, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_CheckURL(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com"},
		},
		nil,
	)

	tests := []struct {
		name       string
		rawURL     string
		wantAllow  bool
		wantReason string
	}{
		{"matching http", "http://example.com/path", true, ""},
		{"matching https", "https://example.com/api", true, ""},
		{"matching with port", "http://example.com:8080/path", true, ""},
		{"non-matching", "http://other.com/path", false, "not in allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tt.rawURL, err)
			}
			allowed, reason := s.CheckURL(u)
			if allowed != tt.wantAllow {
				t.Errorf("CheckURL(%q) allowed = %v, want %v", tt.rawURL, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckURL(%q) reason = %q, want %q", tt.rawURL, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_CheckURL_NilURL(t *testing.T) {
	s := NewTargetScope()

	// No rules: nil URL should be allowed.
	allowed, reason := s.CheckURL(nil)
	if !allowed {
		t.Errorf("CheckURL(nil) with no rules: allowed = false, reason = %q", reason)
	}

	// With allow rules: nil URL should not match (empty hostname).
	s.SetRules([]TargetRule{{Hostname: "example.com"}}, nil)
	allowed, reason = s.CheckURL(nil)
	if allowed {
		t.Error("CheckURL(nil) with allow rules should be blocked")
	}
	if reason != "not in allow list" {
		t.Errorf("CheckURL(nil) reason = %q, want %q", reason, "not in allow list")
	}
}

func TestTargetScope_CheckURL_DefaultPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Ports: []int{80}},
		},
		nil,
	)

	// http://example.com/path should have default port 80.
	u, _ := url.Parse("http://example.com/path")
	allowed, _ := s.CheckURL(u)
	if !allowed {
		t.Error("http URL without explicit port should default to 80")
	}

	// https://example.com/path should have default port 443 (not in allow list).
	u, _ = url.Parse("https://example.com/path")
	allowed, _ = s.CheckURL(u)
	if allowed {
		t.Error("https URL without explicit port should default to 443, not match port 80")
	}

	// http://example.com:8080/path has explicit port 8080 (not in allow list).
	u, _ = url.Parse("http://example.com:8080/path")
	allowed, _ = s.CheckURL(u)
	if allowed {
		t.Error("URL with port 8080 should not match port 80")
	}
}

func TestTargetScope_CheckURL_SchemeExtraction(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "example.com", Schemes: []string{"https"}},
		},
		nil,
	)

	u, _ := url.Parse("https://example.com/path")
	allowed, _ := s.CheckURL(u)
	if !allowed {
		t.Error("https URL should match scheme filter")
	}

	u, _ = url.Parse("http://example.com/path")
	allowed, _ = s.CheckURL(u)
	if allowed {
		t.Error("http URL should not match https-only scheme filter")
	}
}

func TestTargetScope_SetRules_And_Rules(t *testing.T) {
	s := NewTargetScope()

	allows := []TargetRule{
		{Hostname: "a.com", Ports: []int{80, 443}},
		{Hostname: "b.com", Schemes: []string{"https"}},
	}
	denies := []TargetRule{
		{Hostname: "c.com"},
	}

	s.SetRules(allows, denies)

	gotAllows, gotDenies := s.Rules()

	if len(gotAllows) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(gotAllows))
	}
	if len(gotDenies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(gotDenies))
	}

	// Verify that modifying the returned slice does not affect the scope.
	gotAllows[0].Hostname = "modified.com"
	allows2, _ := s.Rules()
	if allows2[0].Hostname == "modified.com" {
		t.Error("Rules() should return a copy, not a reference")
	}

	// Verify that modifying the returned Ports slice does not affect the scope.
	gotAllows2, _ := s.Rules()
	if len(gotAllows2[0].Ports) > 0 {
		gotAllows2[0].Ports[0] = 9999
		allows3, _ := s.Rules()
		if allows3[0].Ports[0] == 9999 {
			t.Error("Rules() should deep copy Ports slice")
		}
	}
}

func TestTargetScope_SetRules_NilSlices(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(nil, nil)

	if s.HasRules() {
		t.Error("SetRules(nil, nil) should leave scope without rules")
	}

	allowed, reason := s.CheckTarget("http", "example.com", 80, "/")
	if !allowed {
		t.Errorf("empty scope should allow all, got blocked with reason %q", reason)
	}
}

func TestTargetScope_SetRules_EmptySlices(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{}, []TargetRule{})

	// Empty slices: len == 0, so effectively no rules.
	allowed, _ := s.CheckTarget("http", "example.com", 80, "/")
	if !allowed {
		t.Error("scope with empty rule slices should allow all")
	}
}

func TestTargetScope_HasRules(t *testing.T) {
	s := NewTargetScope()

	if s.HasRules() {
		t.Error("new scope should have no rules")
	}

	s.SetRules([]TargetRule{{Hostname: "a.com"}}, nil)
	if !s.HasRules() {
		t.Error("scope with allows should have rules")
	}

	s.SetRules(nil, []TargetRule{{Hostname: "b.com"}})
	if !s.HasRules() {
		t.Error("scope with denies should have rules")
	}

	s.SetRules(nil, nil)
	if s.HasRules() {
		t.Error("scope after clearing should have no rules")
	}
}

func TestTargetScope_MergeRules_AddAllows(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{{Hostname: "existing.com"}}, nil)

	s.MergeRules(
		[]TargetRule{{Hostname: "new.com"}},
		nil, nil, nil,
	)

	allows, _ := s.Rules()
	if len(allows) != 2 {
		t.Fatalf("expected 2 allows, got %d", len(allows))
	}
}

func TestTargetScope_MergeRules_RemoveAllows(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{{Hostname: "a.com"}, {Hostname: "b.com"}}, nil)

	s.MergeRules(
		nil,
		[]TargetRule{{Hostname: "a.com"}},
		nil, nil,
	)

	allows, _ := s.Rules()
	if len(allows) != 1 {
		t.Fatalf("expected 1 allow, got %d", len(allows))
	}
	if allows[0].Hostname != "b.com" {
		t.Errorf("expected b.com, got %q", allows[0].Hostname)
	}
}

func TestTargetScope_MergeRules_AddDenies(t *testing.T) {
	s := NewTargetScope()

	s.MergeRules(
		nil, nil,
		[]TargetRule{{Hostname: "evil.com"}},
		nil,
	)

	_, denies := s.Rules()
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(denies))
	}
	if denies[0].Hostname != "evil.com" {
		t.Errorf("expected evil.com, got %q", denies[0].Hostname)
	}
}

func TestTargetScope_MergeRules_RemoveDenies(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(nil, []TargetRule{{Hostname: "old.com"}, {Hostname: "keep.com"}})

	s.MergeRules(
		nil, nil,
		nil,
		[]TargetRule{{Hostname: "old.com"}},
	)

	_, denies := s.Rules()
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(denies))
	}
	if denies[0].Hostname != "keep.com" {
		t.Errorf("expected keep.com, got %q", denies[0].Hostname)
	}
}

func TestTargetScope_MergeRules_DuplicateSkipped(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{{Hostname: "existing.com"}}, nil)

	s.MergeRules(
		[]TargetRule{{Hostname: "existing.com"}},
		nil, nil, nil,
	)

	allows, _ := s.Rules()
	if len(allows) != 1 {
		t.Errorf("expected 1 allow (duplicate should be skipped), got %d", len(allows))
	}
}

func TestTargetScope_MergeRules_DuplicateWithPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{{Hostname: "a.com", Ports: []int{80, 443}}}, nil)

	// Same rule (same ports) should be skipped.
	s.MergeRules(
		[]TargetRule{{Hostname: "a.com", Ports: []int{80, 443}}},
		nil, nil, nil,
	)
	allows, _ := s.Rules()
	if len(allows) != 1 {
		t.Errorf("expected 1 allow (duplicate with same ports), got %d", len(allows))
	}

	// Different ports should be added.
	s.MergeRules(
		[]TargetRule{{Hostname: "a.com", Ports: []int{8080}}},
		nil, nil, nil,
	)
	allows, _ = s.Rules()
	if len(allows) != 2 {
		t.Errorf("expected 2 allows (different ports), got %d", len(allows))
	}
}

func TestTargetScope_MergeRules_CombinedDeltas(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{{Hostname: "keep.com"}, {Hostname: "remove.com"}},
		[]TargetRule{{Hostname: "old-deny.com"}},
	)

	s.MergeRules(
		[]TargetRule{{Hostname: "add.com"}},
		[]TargetRule{{Hostname: "remove.com"}},
		[]TargetRule{{Hostname: "new-deny.com"}},
		[]TargetRule{{Hostname: "old-deny.com"}},
	)

	allows, denies := s.Rules()
	if len(allows) != 2 {
		t.Fatalf("expected 2 allows, got %d", len(allows))
	}
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(denies))
	}
	if denies[0].Hostname != "new-deny.com" {
		t.Errorf("expected new-deny.com, got %q", denies[0].Hostname)
	}
}

func TestTargetScope_MergeRules_CaseInsensitiveDuplicate(t *testing.T) {
	s := NewTargetScope()
	s.SetRules([]TargetRule{{Hostname: "Example.COM"}}, nil)

	// Hostname comparison for equality in containsTargetRule is case-insensitive.
	s.MergeRules(
		[]TargetRule{{Hostname: "example.com"}},
		nil, nil, nil,
	)

	allows, _ := s.Rules()
	if len(allows) != 1 {
		t.Errorf("expected 1 allow (case-insensitive duplicate), got %d", len(allows))
	}
}

func TestTargetScope_ConcurrentAccess(t *testing.T) {
	s := NewTargetScope()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			s.CheckTarget("http", "example.com", 80, "/path")
		}()
		go func() {
			defer wg.Done()
			s.SetRules([]TargetRule{{Hostname: "example.com"}}, nil)
		}()
		go func() {
			defer wg.Done()
			s.Rules()
		}()
		go func() {
			defer wg.Done()
			s.HasRules()
		}()
	}
	wg.Wait()
}

func TestTargetScope_ConcurrentMergeRules(t *testing.T) {
	s := NewTargetScope()
	u, _ := url.Parse("http://example.com/path")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			s.MergeRules(
				[]TargetRule{{Hostname: "a.com"}},
				[]TargetRule{{Hostname: "b.com"}},
				nil, nil,
			)
		}()
		go func() {
			defer wg.Done()
			s.CheckURL(u)
		}()
		go func() {
			defer wg.Done()
			s.Rules()
		}()
	}
	wg.Wait()
}

func TestTargetScope_DenyPrecedence(t *testing.T) {
	// When a target matches both allow and deny, deny wins.
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{{Hostname: "example.com"}},
		[]TargetRule{{Hostname: "example.com", PathPrefix: "/admin/"}},
	)

	tests := []struct {
		name       string
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"allowed and not denied", "/api/data", true, ""},
		{"allowed but denied by path", "/admin/settings", false, "denied by target scope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", "example.com", 80, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget with path %q: allowed = %v, want %v",
					tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestDefaultPort(t *testing.T) {
	tests := []struct {
		name    string
		scheme  string
		portStr string
		want    int
	}{
		{"explicit port", "http", "8080", 8080},
		{"http default", "http", "", 80},
		{"https default", "https", "", 443},
		{"unknown scheme no port", "ftp", "", 0},
		{"empty scheme no port", "", "", 0},
		{"invalid port string", "http", "abc", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultPort(tt.scheme, tt.portStr)
			if got != tt.want {
				t.Errorf("defaultPort(%q, %q) = %d, want %d", tt.scheme, tt.portStr, got, tt.want)
			}
		})
	}
}

func TestContainsInt(t *testing.T) {
	tests := []struct {
		name  string
		slice []int
		val   int
		want  bool
	}{
		{"found", []int{80, 443, 8080}, 443, true},
		{"not found", []int{80, 443}, 8080, false},
		{"empty slice", []int{}, 80, false},
		{"nil slice", nil, 80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsInt(tt.slice, tt.val); got != tt.want {
				t.Errorf("containsInt(%v, %d) = %v, want %v", tt.slice, tt.val, got, tt.want)
			}
		})
	}
}

func TestContainsStringFold(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		val   string
		want  bool
	}{
		{"found exact", []string{"http", "https"}, "http", true},
		{"found case insensitive", []string{"HTTP", "HTTPS"}, "https", true},
		{"not found", []string{"http"}, "ftp", false},
		{"empty slice", []string{}, "http", false},
		{"nil slice", nil, "http", false},
		{"empty val in slice", []string{""}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsStringFold(tt.slice, tt.val); got != tt.want {
				t.Errorf("containsStringFold(%v, %q) = %v, want %v", tt.slice, tt.val, got, tt.want)
			}
		})
	}
}

func TestTargetRuleEqual(t *testing.T) {
	tests := []struct {
		name string
		a    TargetRule
		b    TargetRule
		want bool
	}{
		{
			"identical rules",
			TargetRule{Hostname: "a.com", Ports: []int{80}, PathPrefix: "/api/", Schemes: []string{"http"}},
			TargetRule{Hostname: "a.com", Ports: []int{80}, PathPrefix: "/api/", Schemes: []string{"http"}},
			true,
		},
		{
			"hostname case insensitive",
			TargetRule{Hostname: "A.COM"},
			TargetRule{Hostname: "a.com"},
			true,
		},
		{
			"different hostname",
			TargetRule{Hostname: "a.com"},
			TargetRule{Hostname: "b.com"},
			false,
		},
		{
			"different ports",
			TargetRule{Hostname: "a.com", Ports: []int{80}},
			TargetRule{Hostname: "a.com", Ports: []int{443}},
			false,
		},
		{
			"different path prefix",
			TargetRule{Hostname: "a.com", PathPrefix: "/api/"},
			TargetRule{Hostname: "a.com", PathPrefix: "/web/"},
			false,
		},
		{
			"different schemes",
			TargetRule{Hostname: "a.com", Schemes: []string{"http"}},
			TargetRule{Hostname: "a.com", Schemes: []string{"https"}},
			false,
		},
		{
			"scheme case insensitive",
			TargetRule{Hostname: "a.com", Schemes: []string{"HTTP"}},
			TargetRule{Hostname: "a.com", Schemes: []string{"http"}},
			true,
		},
		{
			"nil vs empty ports treated equal",
			TargetRule{Hostname: "a.com", Ports: nil},
			TargetRule{Hostname: "a.com", Ports: []int{}},
			true,
		},
		{
			"both nil ports",
			TargetRule{Hostname: "a.com", Ports: nil},
			TargetRule{Hostname: "a.com", Ports: nil},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetRuleEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("targetRuleEqual(%+v, %+v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCloneTargetRules(t *testing.T) {
	// Nil input returns nil.
	if got := cloneTargetRules(nil); got != nil {
		t.Error("cloneTargetRules(nil) should return nil")
	}

	// Clone should produce independent copy.
	original := []TargetRule{
		{Hostname: "a.com", Ports: []int{80, 443}, Schemes: []string{"http", "https"}},
		{Hostname: "b.com"},
	}

	cloned := cloneTargetRules(original)

	if len(cloned) != len(original) {
		t.Fatalf("cloned length %d != original %d", len(cloned), len(original))
	}

	// Modify cloned and verify original is unaffected.
	cloned[0].Hostname = "modified.com"
	if original[0].Hostname == "modified.com" {
		t.Error("modifying cloned hostname should not affect original")
	}

	cloned[0].Ports[0] = 9999
	if original[0].Ports[0] == 9999 {
		t.Error("modifying cloned ports should not affect original")
	}

	cloned[0].Schemes[0] = "ftp"
	if original[0].Schemes[0] == "ftp" {
		t.Error("modifying cloned schemes should not affect original")
	}
}

func TestTargetScope_MultipleAllowRules(t *testing.T) {
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{
			{Hostname: "api.example.com", Schemes: []string{"https"}},
			{Hostname: "cdn.example.com", Ports: []int{443}},
			{Hostname: "*.internal.com"},
		},
		nil,
	)

	tests := []struct {
		name      string
		scheme    string
		hostname  string
		port      int
		path      string
		wantAllow bool
	}{
		{"matches first rule", "https", "api.example.com", 443, "/v1/users", true},
		{"matches second rule", "http", "cdn.example.com", 443, "/assets/logo.png", true},
		{"matches third rule", "http", "service.internal.com", 8080, "/", true},
		{"matches no rule", "http", "external.com", 80, "/", false},
		{"first rule wrong scheme", "http", "api.example.com", 80, "/v1/users", false},
		{"second rule wrong port", "http", "cdn.example.com", 80, "/assets/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d, %q) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, tt.path, allowed, tt.wantAllow)
			}
		})
	}
}

func TestTargetScope_DenyOverridesAllow_SameHostname(t *testing.T) {
	// Exact same hostname in both allows and denies: deny wins.
	s := NewTargetScope()
	s.SetRules(
		[]TargetRule{{Hostname: "example.com"}},
		[]TargetRule{{Hostname: "example.com"}},
	)

	allowed, reason := s.CheckTarget("http", "example.com", 80, "/")
	if allowed {
		t.Error("deny should override allow for same hostname")
	}
	if reason != "denied by target scope" {
		t.Errorf("reason = %q, want %q", reason, "denied by target scope")
	}
}
