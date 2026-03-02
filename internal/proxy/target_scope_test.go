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
	s.SetAgentRules(
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
		{"not in agent allow list", "http", "other.com", 80, "/path", false, "not in agent allow list"},
		{"unrelated domain", "http", "google.com", 80, "/", false, "not in agent allow list"},
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
	s.SetAgentRules(
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
		{"denied domain", "http", "malicious.com", 80, "/exploit", false, "blocked by agent deny rule"},
		{"another denied domain", "https", "ads.example.com", 443, "/banner", false, "blocked by agent deny rule"},
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
	s.SetAgentRules(
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
		{"denied subdomain overrides allow", "http", "admin.example.com", 80, "/settings", false, "blocked by agent deny rule"},
		{"another allowed subdomain", "https", "www.example.com", 443, "/data", true, ""},
		{"non-matching domain", "http", "other.com", 80, "/path", false, "not in agent allow list"},
		{"bare domain not matched by wildcard", "http", "example.com", 80, "/path", false, "not in agent allow list"},
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
			s.SetAgentRules([]TargetRule{{Hostname: tt.pattern}}, nil)

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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
		{"wrong scheme", "http", "api.example.com", 443, "/v2/data", false, "not in agent allow list"},
		{"wrong hostname", "https", "other.com", 443, "/v2/data", false, "not in agent allow list"},
		{"wrong port", "https", "api.example.com", 80, "/v2/data", false, "not in agent allow list"},
		{"wrong path", "https", "api.example.com", 443, "/v1/data", false, "not in agent allow list"},
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
	s.SetAgentRules(
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
	s.SetAgentRules(
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
		{"non-matching", "http://other.com/path", false, "not in agent allow list"},
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
	s.SetAgentRules([]TargetRule{{Hostname: "example.com"}}, nil)
	allowed, reason = s.CheckURL(nil)
	if allowed {
		t.Error("CheckURL(nil) with allow rules should be blocked")
	}
	if reason != "not in agent allow list" {
		t.Errorf("CheckURL(nil) reason = %q, want %q", reason, "not in agent allow list")
	}
}

func TestTargetScope_CheckURL_DefaultPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules(
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
	s.SetAgentRules(
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

func TestTargetScope_SetAgentRules_And_AgentRules(t *testing.T) {
	s := NewTargetScope()

	allows := []TargetRule{
		{Hostname: "a.com", Ports: []int{80, 443}},
		{Hostname: "b.com", Schemes: []string{"https"}},
	}
	denies := []TargetRule{
		{Hostname: "c.com"},
	}

	s.SetAgentRules(allows, denies)

	gotAllows, gotDenies := s.AgentRules()

	if len(gotAllows) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(gotAllows))
	}
	if len(gotDenies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(gotDenies))
	}

	// Verify that modifying the returned slice does not affect the scope.
	gotAllows[0].Hostname = "modified.com"
	allows2, _ := s.AgentRules()
	if allows2[0].Hostname == "modified.com" {
		t.Error("Rules() should return a copy, not a reference")
	}

	// Verify that modifying the returned Ports slice does not affect the scope.
	gotAllows2, _ := s.AgentRules()
	if len(gotAllows2[0].Ports) > 0 {
		gotAllows2[0].Ports[0] = 9999
		allows3, _ := s.AgentRules()
		if allows3[0].Ports[0] == 9999 {
			t.Error("Rules() should deep copy Ports slice")
		}
	}
}

func TestTargetScope_SetAgentRules_NilSlices(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules(nil, nil)

	if s.HasRules() {
		t.Error("SetAgentRules(nil, nil) should leave scope without rules")
	}

	allowed, reason := s.CheckTarget("http", "example.com", 80, "/")
	if !allowed {
		t.Errorf("empty scope should allow all, got blocked with reason %q", reason)
	}
}

func TestTargetScope_SetAgentRules_EmptySlices(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{}, []TargetRule{})

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

	s.SetAgentRules([]TargetRule{{Hostname: "a.com"}}, nil)
	if !s.HasRules() {
		t.Error("scope with allows should have rules")
	}

	s.SetAgentRules(nil, []TargetRule{{Hostname: "b.com"}})
	if !s.HasRules() {
		t.Error("scope with denies should have rules")
	}

	s.SetAgentRules(nil, nil)
	if s.HasRules() {
		t.Error("scope after clearing should have no rules")
	}
}

func TestTargetScope_MergeAgentRules_AddAllows(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{{Hostname: "existing.com"}}, nil)

	s.MergeAgentRules(
		[]TargetRule{{Hostname: "new.com"}},
		nil, nil, nil,
	)

	allows, _ := s.AgentRules()
	if len(allows) != 2 {
		t.Fatalf("expected 2 allows, got %d", len(allows))
	}
}

func TestTargetScope_MergeAgentRules_RemoveAllows(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{{Hostname: "a.com"}, {Hostname: "b.com"}}, nil)

	s.MergeAgentRules(
		nil,
		[]TargetRule{{Hostname: "a.com"}},
		nil, nil,
	)

	allows, _ := s.AgentRules()
	if len(allows) != 1 {
		t.Fatalf("expected 1 allow, got %d", len(allows))
	}
	if allows[0].Hostname != "b.com" {
		t.Errorf("expected b.com, got %q", allows[0].Hostname)
	}
}

func TestTargetScope_MergeAgentRules_AddDenies(t *testing.T) {
	s := NewTargetScope()

	s.MergeAgentRules(
		nil, nil,
		[]TargetRule{{Hostname: "evil.com"}},
		nil,
	)

	_, denies := s.AgentRules()
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(denies))
	}
	if denies[0].Hostname != "evil.com" {
		t.Errorf("expected evil.com, got %q", denies[0].Hostname)
	}
}

func TestTargetScope_MergeAgentRules_RemoveDenies(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules(nil, []TargetRule{{Hostname: "old.com"}, {Hostname: "keep.com"}})

	s.MergeAgentRules(
		nil, nil,
		nil,
		[]TargetRule{{Hostname: "old.com"}},
	)

	_, denies := s.AgentRules()
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(denies))
	}
	if denies[0].Hostname != "keep.com" {
		t.Errorf("expected keep.com, got %q", denies[0].Hostname)
	}
}

func TestTargetScope_MergeAgentRules_DuplicateSkipped(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{{Hostname: "existing.com"}}, nil)

	s.MergeAgentRules(
		[]TargetRule{{Hostname: "existing.com"}},
		nil, nil, nil,
	)

	allows, _ := s.AgentRules()
	if len(allows) != 1 {
		t.Errorf("expected 1 allow (duplicate should be skipped), got %d", len(allows))
	}
}

func TestTargetScope_MergeAgentRules_DuplicateWithPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{{Hostname: "a.com", Ports: []int{80, 443}}}, nil)

	// Same rule (same ports) should be skipped.
	s.MergeAgentRules(
		[]TargetRule{{Hostname: "a.com", Ports: []int{80, 443}}},
		nil, nil, nil,
	)
	allows, _ := s.AgentRules()
	if len(allows) != 1 {
		t.Errorf("expected 1 allow (duplicate with same ports), got %d", len(allows))
	}

	// Different ports should be added.
	s.MergeAgentRules(
		[]TargetRule{{Hostname: "a.com", Ports: []int{8080}}},
		nil, nil, nil,
	)
	allows, _ = s.AgentRules()
	if len(allows) != 2 {
		t.Errorf("expected 2 allows (different ports), got %d", len(allows))
	}
}

func TestTargetScope_MergeAgentRules_CombinedDeltas(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules(
		[]TargetRule{{Hostname: "keep.com"}, {Hostname: "remove.com"}},
		[]TargetRule{{Hostname: "old-deny.com"}},
	)

	s.MergeAgentRules(
		[]TargetRule{{Hostname: "add.com"}},
		[]TargetRule{{Hostname: "remove.com"}},
		[]TargetRule{{Hostname: "new-deny.com"}},
		[]TargetRule{{Hostname: "old-deny.com"}},
	)

	allows, denies := s.AgentRules()
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

func TestTargetScope_MergeAgentRules_CaseInsensitiveDuplicate(t *testing.T) {
	s := NewTargetScope()
	s.SetAgentRules([]TargetRule{{Hostname: "Example.COM"}}, nil)

	// Hostname comparison for equality in containsTargetRule is case-insensitive.
	s.MergeAgentRules(
		[]TargetRule{{Hostname: "example.com"}},
		nil, nil, nil,
	)

	allows, _ := s.AgentRules()
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
			s.SetAgentRules([]TargetRule{{Hostname: "example.com"}}, nil)
		}()
		go func() {
			defer wg.Done()
			s.AgentRules()
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
			s.MergeAgentRules(
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
			s.AgentRules()
		}()
	}
	wg.Wait()
}

func TestTargetScope_DenyPrecedence(t *testing.T) {
	// When a target matches both allow and deny, deny wins.
	s := NewTargetScope()
	s.SetAgentRules(
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
		{"allowed but denied by path", "/admin/settings", false, "blocked by agent deny rule"},
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
	s.SetAgentRules(
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
	s.SetAgentRules(
		[]TargetRule{{Hostname: "example.com"}},
		[]TargetRule{{Hostname: "example.com"}},
	)

	allowed, reason := s.CheckTarget("http", "example.com", 80, "/")
	if allowed {
		t.Error("deny should override allow for same hostname")
	}
	if reason != "blocked by agent deny rule" {
		t.Errorf("reason = %q, want %q", reason, "blocked by agent deny rule")
	}
}

func TestTargetScope_MergeAgentRules_DeepCopy(t *testing.T) {
	// Verify that MergeRules deep copies the Ports and Schemes slices
	// so that mutations to the caller's slices do not affect internal state.
	s := NewTargetScope()

	ports := []int{80, 443}
	schemes := []string{"http", "https"}
	allowRule := TargetRule{Hostname: "allow.com", Ports: ports, Schemes: schemes}

	denyPorts := []int{8080}
	denySchemes := []string{"http"}
	denyRule := TargetRule{Hostname: "deny.com", Ports: denyPorts, Schemes: denySchemes}

	s.MergeAgentRules(
		[]TargetRule{allowRule},
		nil,
		[]TargetRule{denyRule},
		nil,
	)

	// Mutate the caller's slices after MergeRules.
	ports[0] = 9999
	schemes[0] = "ftp"
	denyPorts[0] = 7777
	denySchemes[0] = "wss"

	allows, denies := s.AgentRules()
	if len(allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(allows))
	}
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(denies))
	}

	// Allow rule should be unaffected by caller mutation.
	if allows[0].Ports[0] != 80 {
		t.Errorf("allow Ports[0] = %d, want 80 (caller mutation leaked)", allows[0].Ports[0])
	}
	if allows[0].Ports[1] != 443 {
		t.Errorf("allow Ports[1] = %d, want 443", allows[0].Ports[1])
	}
	if allows[0].Schemes[0] != "http" {
		t.Errorf("allow Schemes[0] = %q, want %q (caller mutation leaked)", allows[0].Schemes[0], "http")
	}
	if allows[0].Schemes[1] != "https" {
		t.Errorf("allow Schemes[1] = %q, want %q", allows[0].Schemes[1], "https")
	}

	// Deny rule should be unaffected by caller mutation.
	if denies[0].Ports[0] != 8080 {
		t.Errorf("deny Ports[0] = %d, want 8080 (caller mutation leaked)", denies[0].Ports[0])
	}
	if denies[0].Schemes[0] != "http" {
		t.Errorf("deny Schemes[0] = %q, want %q (caller mutation leaked)", denies[0].Schemes[0], "http")
	}
}

// ==================== Two-Layer (Policy + Agent) Tests ====================

func TestTargetScope_PolicyDenies_AlwaysBlock(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{
		{Hostname: "forbidden.com"},
		{Hostname: "*.evil.com"},
	})

	tests := []struct {
		name       string
		hostname   string
		wantAllow  bool
		wantReason string
	}{
		{"policy deny blocks exact hostname", "forbidden.com", false, "blocked by policy deny rule"},
		{"policy deny blocks wildcard subdomain", "sub.evil.com", false, "blocked by policy deny rule"},
		{"non-denied host allowed", "safe.com", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", tt.hostname, 80, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q) allowed = %v, want %v", tt.hostname, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget(%q) reason = %q, want %q", tt.hostname, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_PolicyDenies_CannotBeOverriddenByAgent(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.com"}})

	// Agent tries to allow the policy-denied host.
	s.SetAgentRules([]TargetRule{{Hostname: "blocked.com"}}, nil)

	allowed, reason := s.CheckTarget("http", "blocked.com", 80, "/")
	if allowed {
		t.Error("policy deny should not be overridden by agent allow")
	}
	if reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q", reason, "blocked by policy deny rule")
	}
}

func TestTargetScope_PolicyAllows_UpperBoundary(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(
		[]TargetRule{
			{Hostname: "*.example.com"},
			{Hostname: "api.internal.com", Ports: []int{443}},
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
		{"within policy allows (wildcard)", "http", "sub.example.com", 80, "/", true, ""},
		{"within policy allows (exact)", "https", "api.internal.com", 443, "/", true, ""},
		{"outside policy allows", "http", "other.com", 80, "/", false, "not in policy allow list"},
		{"exact port mismatch", "https", "api.internal.com", 8080, "/", false, "not in policy allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget(tt.scheme, tt.hostname, tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q, %d) allowed = %v, want %v",
					tt.scheme, tt.hostname, tt.port, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_AgentAllows_WithinPolicyScope(t *testing.T) {
	s := NewTargetScope()
	// Policy allows all of *.example.com.
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)
	// Agent restricts to only api.example.com.
	s.SetAgentRules([]TargetRule{{Hostname: "api.example.com"}}, nil)

	tests := []struct {
		name       string
		hostname   string
		wantAllow  bool
		wantReason string
	}{
		{"allowed by both layers", "api.example.com", true, ""},
		{"in policy but not agent", "www.example.com", false, "not in agent allow list"},
		{"outside both layers", "other.com", false, "not in policy allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", tt.hostname, 80, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q) allowed = %v, want %v", tt.hostname, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget(%q) reason = %q, want %q", tt.hostname, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_AgentDenies_AdditionalRestrictions(t *testing.T) {
	s := NewTargetScope()
	// Policy allows all of *.example.com.
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)
	// Agent denies admin.example.com specifically.
	s.SetAgentRules(nil, []TargetRule{{Hostname: "admin.example.com"}})

	tests := []struct {
		name       string
		hostname   string
		wantAllow  bool
		wantReason string
	}{
		{"allowed by policy, not agent-denied", "api.example.com", true, ""},
		{"allowed by policy but agent-denied", "admin.example.com", false, "blocked by agent deny rule"},
		{"outside policy", "other.com", false, "not in policy allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", tt.hostname, 80, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q) allowed = %v, want %v", tt.hostname, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget(%q) reason = %q, want %q", tt.hostname, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_NoPolicyAgentOnly_BackwardCompat(t *testing.T) {
	// With no policy rules, behavior should match the old single-layer behavior.
	s := NewTargetScope()
	s.SetAgentRules(
		[]TargetRule{{Hostname: "example.com"}},
		[]TargetRule{{Hostname: "evil.com"}},
	)

	tests := []struct {
		name       string
		hostname   string
		wantAllow  bool
		wantReason string
	}{
		{"allowed by agent", "example.com", true, ""},
		{"denied by agent", "evil.com", false, "blocked by agent deny rule"},
		{"not in agent allow list", "other.com", false, "not in agent allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", tt.hostname, 80, "/")
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q) allowed = %v, want %v", tt.hostname, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget(%q) reason = %q, want %q", tt.hostname, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_NoRules_AllAllowed(t *testing.T) {
	// With no policy and no agent rules, everything should be allowed.
	s := NewTargetScope()

	allowed, reason := s.CheckTarget("http", "anything.com", 80, "/")
	if !allowed {
		t.Errorf("no rules should allow all, got blocked with reason %q", reason)
	}
}

func TestTargetScope_PolicyDenyPrecedesAgentDeny(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.com"}})
	s.SetAgentRules(nil, []TargetRule{{Hostname: "blocked.com"}})

	// Policy deny should be the reason (checked first).
	allowed, reason := s.CheckTarget("http", "blocked.com", 80, "/")
	if allowed {
		t.Error("both layers deny, should be blocked")
	}
	if reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q (policy should take precedence)", reason, "blocked by policy deny rule")
	}
}

func TestTargetScope_FullTwoLayerEvaluation(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(
		[]TargetRule{{Hostname: "*.example.com"}},
		[]TargetRule{{Hostname: "secret.example.com"}},
	)
	s.SetAgentRules(
		[]TargetRule{{Hostname: "api.example.com"}, {Hostname: "www.example.com"}},
		[]TargetRule{{Hostname: "www.example.com", PathPrefix: "/admin/"}},
	)

	tests := []struct {
		name       string
		hostname   string
		path       string
		wantAllow  bool
		wantReason string
	}{
		{"policy deny blocks", "secret.example.com", "/", false, "blocked by policy deny rule"},
		{"allowed by both layers", "api.example.com", "/v1/data", true, ""},
		{"in policy but not agent allows", "cdn.example.com", "/", false, "not in agent allow list"},
		{"outside policy allows", "other.com", "/", false, "not in policy allow list"},
		{"agent deny on specific path", "www.example.com", "/admin/settings", false, "blocked by agent deny rule"},
		{"agent allow but not denied path", "www.example.com", "/public", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := s.CheckTarget("http", tt.hostname, 80, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget(%q, %q) allowed = %v, want %v",
					tt.hostname, tt.path, allowed, tt.wantAllow)
			}
			if reason != tt.wantReason {
				t.Errorf("CheckTarget(%q, %q) reason = %q, want %q",
					tt.hostname, tt.path, reason, tt.wantReason)
			}
		})
	}
}

func TestTargetScope_SetPolicyRules(t *testing.T) {
	s := NewTargetScope()

	allows := []TargetRule{{Hostname: "a.com", Ports: []int{80, 443}}}
	denies := []TargetRule{{Hostname: "b.com"}}
	s.SetPolicyRules(allows, denies)

	gotAllows, gotDenies := s.PolicyRules()
	if len(gotAllows) != 1 || gotAllows[0].Hostname != "a.com" {
		t.Errorf("PolicyRules allows = %v, want [{Hostname: a.com}]", gotAllows)
	}
	if len(gotDenies) != 1 || gotDenies[0].Hostname != "b.com" {
		t.Errorf("PolicyRules denies = %v, want [{Hostname: b.com}]", gotDenies)
	}

	// Verify deep copy — modify returned slice should not affect internal state.
	gotAllows[0].Hostname = "modified.com"
	allows2, _ := s.PolicyRules()
	if allows2[0].Hostname == "modified.com" {
		t.Error("PolicyRules should return a deep copy")
	}
}

func TestTargetScope_HasPolicyRules(t *testing.T) {
	s := NewTargetScope()
	if s.HasPolicyRules() {
		t.Error("new scope should not have policy rules")
	}

	s.SetPolicyRules([]TargetRule{{Hostname: "a.com"}}, nil)
	if !s.HasPolicyRules() {
		t.Error("scope with policy allows should have policy rules")
	}

	s.SetPolicyRules(nil, []TargetRule{{Hostname: "b.com"}})
	if !s.HasPolicyRules() {
		t.Error("scope with policy denies should have policy rules")
	}

	s.SetPolicyRules(nil, nil)
	if s.HasPolicyRules() {
		t.Error("scope after clearing policy should not have policy rules")
	}
}

func TestTargetScope_HasRules_BothLayers(t *testing.T) {
	s := NewTargetScope()
	if s.HasRules() {
		t.Error("new scope should have no rules")
	}

	// Only policy rules.
	s.SetPolicyRules([]TargetRule{{Hostname: "a.com"}}, nil)
	if !s.HasRules() {
		t.Error("scope with only policy rules should have rules")
	}

	// Clear policy, add agent.
	s.SetPolicyRules(nil, nil)
	s.SetAgentRules([]TargetRule{{Hostname: "b.com"}}, nil)
	if !s.HasRules() {
		t.Error("scope with only agent rules should have rules")
	}

	// Both layers.
	s.SetPolicyRules([]TargetRule{{Hostname: "a.com"}}, nil)
	if !s.HasRules() {
		t.Error("scope with both layers should have rules")
	}

	// Clear both.
	s.SetPolicyRules(nil, nil)
	s.SetAgentRules(nil, nil)
	if s.HasRules() {
		t.Error("scope with no rules in either layer should have no rules")
	}
}

func TestTargetScope_SetAgentRules_PolicyBoundaryCheck(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)

	// Agent allows within policy — should succeed.
	err := s.SetAgentRules([]TargetRule{{Hostname: "api.example.com"}}, nil)
	if err != nil {
		t.Errorf("SetAgentRules within policy: unexpected error: %v", err)
	}

	// Agent allows outside policy — should fail.
	err = s.SetAgentRules([]TargetRule{{Hostname: "other.com"}}, nil)
	if err == nil {
		t.Error("SetAgentRules outside policy: expected error, got nil")
	}

	// Verify previous valid rules remain after failed SetAgentRules.
	allows, _ := s.AgentRules()
	if len(allows) != 1 || allows[0].Hostname != "api.example.com" {
		t.Errorf("agent allows should remain unchanged after failed set, got %v", allows)
	}
}

func TestTargetScope_MergeAgentRules_PolicyBoundaryCheck(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)

	// Merge with valid allows — should succeed.
	err := s.MergeAgentRules([]TargetRule{{Hostname: "api.example.com"}}, nil, nil, nil)
	if err != nil {
		t.Errorf("MergeAgentRules within policy: unexpected error: %v", err)
	}

	// Merge with invalid allows — should fail.
	err = s.MergeAgentRules([]TargetRule{{Hostname: "evil.com"}}, nil, nil, nil)
	if err == nil {
		t.Error("MergeAgentRules outside policy: expected error, got nil")
	}

	// Verify the valid allow from first merge remains.
	allows, _ := s.AgentRules()
	if len(allows) != 1 || allows[0].Hostname != "api.example.com" {
		t.Errorf("agent allows should remain unchanged after failed merge, got %v", allows)
	}

	// Agent denies are always allowed (no policy boundary restriction on denies).
	err = s.MergeAgentRules(nil, nil, []TargetRule{{Hostname: "any.com"}}, nil)
	if err != nil {
		t.Errorf("MergeAgentRules adding denies: unexpected error: %v", err)
	}
}

func TestTargetScope_ValidateAgentAllows(t *testing.T) {
	tests := []struct {
		name         string
		policyAllows []TargetRule
		agentAllows  []TargetRule
		wantErr      bool
	}{
		{
			name:         "no policy allows — all agent allows valid",
			policyAllows: nil,
			agentAllows:  []TargetRule{{Hostname: "anything.com"}},
			wantErr:      false,
		},
		{
			name:         "agent within wildcard policy",
			policyAllows: []TargetRule{{Hostname: "*.example.com"}},
			agentAllows:  []TargetRule{{Hostname: "api.example.com"}},
			wantErr:      false,
		},
		{
			name:         "agent wildcard within wildcard policy",
			policyAllows: []TargetRule{{Hostname: "*.example.com"}},
			agentAllows:  []TargetRule{{Hostname: "*.example.com"}},
			wantErr:      false,
		},
		{
			name:         "agent outside policy",
			policyAllows: []TargetRule{{Hostname: "*.example.com"}},
			agentAllows:  []TargetRule{{Hostname: "other.com"}},
			wantErr:      true,
		},
		{
			name:         "agent wider wildcard than policy",
			policyAllows: []TargetRule{{Hostname: "*.sub.example.com"}},
			agentAllows:  []TargetRule{{Hostname: "*.example.com"}},
			wantErr:      true,
		},
		{
			name:         "agent with restricted ports within policy",
			policyAllows: []TargetRule{{Hostname: "example.com", Ports: []int{80, 443}}},
			agentAllows:  []TargetRule{{Hostname: "example.com", Ports: []int{443}}},
			wantErr:      false,
		},
		{
			name:         "agent with port outside policy ports",
			policyAllows: []TargetRule{{Hostname: "example.com", Ports: []int{80, 443}}},
			agentAllows:  []TargetRule{{Hostname: "example.com", Ports: []int{8080}}},
			wantErr:      true,
		},
		{
			name:         "agent all ports but policy restricts",
			policyAllows: []TargetRule{{Hostname: "example.com", Ports: []int{80}}},
			agentAllows:  []TargetRule{{Hostname: "example.com"}},
			wantErr:      true,
		},
		{
			name:         "agent with restricted schemes within policy",
			policyAllows: []TargetRule{{Hostname: "example.com", Schemes: []string{"http", "https"}}},
			agentAllows:  []TargetRule{{Hostname: "example.com", Schemes: []string{"https"}}},
			wantErr:      false,
		},
		{
			name:         "agent with scheme outside policy",
			policyAllows: []TargetRule{{Hostname: "example.com", Schemes: []string{"https"}}},
			agentAllows:  []TargetRule{{Hostname: "example.com", Schemes: []string{"http"}}},
			wantErr:      true,
		},
		{
			name:         "agent all schemes but policy restricts",
			policyAllows: []TargetRule{{Hostname: "example.com", Schemes: []string{"https"}}},
			agentAllows:  []TargetRule{{Hostname: "example.com"}},
			wantErr:      true,
		},
		{
			name:         "agent path more specific than policy",
			policyAllows: []TargetRule{{Hostname: "example.com", PathPrefix: "/api/"}},
			agentAllows:  []TargetRule{{Hostname: "example.com", PathPrefix: "/api/v2/"}},
			wantErr:      false,
		},
		{
			name:         "agent path less specific than policy",
			policyAllows: []TargetRule{{Hostname: "example.com", PathPrefix: "/api/v2/"}},
			agentAllows:  []TargetRule{{Hostname: "example.com", PathPrefix: "/api/"}},
			wantErr:      true,
		},
		{
			name:         "agent all paths but policy restricts",
			policyAllows: []TargetRule{{Hostname: "example.com", PathPrefix: "/api/"}},
			agentAllows:  []TargetRule{{Hostname: "example.com"}},
			wantErr:      true,
		},
		{
			name:         "empty agent allows always valid",
			policyAllows: []TargetRule{{Hostname: "example.com"}},
			agentAllows:  nil,
			wantErr:      false,
		},
		{
			name:         "multiple policy allows cover agent",
			policyAllows: []TargetRule{{Hostname: "a.com"}, {Hostname: "b.com"}},
			agentAllows:  []TargetRule{{Hostname: "a.com"}, {Hostname: "b.com"}},
			wantErr:      false,
		},
		{
			name:         "agent covered by one of multiple policy rules",
			policyAllows: []TargetRule{{Hostname: "a.com"}, {Hostname: "*.example.com"}},
			agentAllows:  []TargetRule{{Hostname: "sub.example.com"}},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.policyAllows, nil)

			err := s.ValidateAgentAllows(tt.agentAllows)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAgentAllows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTargetScope_CheckURL_TwoLayer(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(
		[]TargetRule{{Hostname: "*.example.com", Schemes: []string{"https"}}},
		[]TargetRule{{Hostname: "evil.example.com"}},
	)
	if err := s.SetAgentRules(
		[]TargetRule{{Hostname: "api.example.com", Schemes: []string{"https"}}},
		nil,
	); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}

	tests := []struct {
		name       string
		rawURL     string
		wantAllow  bool
		wantReason string
	}{
		{"allowed by all layers", "https://api.example.com/data", true, ""},
		{"blocked by policy deny", "https://evil.example.com/data", false, "blocked by policy deny rule"},
		{"blocked by wrong scheme (policy)", "http://api.example.com/data", false, "not in policy allow list"},
		{"not in agent allow list", "https://www.example.com/data", false, "not in agent allow list"},
		{"outside policy allows", "https://other.com/data", false, "not in policy allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
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

func TestTargetScope_ConcurrentAccess_TwoLayer(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(
		[]TargetRule{{Hostname: "*.example.com"}},
		[]TargetRule{{Hostname: "blocked.example.com"}},
	)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			s.CheckTarget("http", "api.example.com", 80, "/path")
		}()
		go func() {
			defer wg.Done()
			s.SetAgentRules([]TargetRule{{Hostname: "api.example.com"}}, nil)
		}()
		go func() {
			defer wg.Done()
			s.AgentRules()
		}()
		go func() {
			defer wg.Done()
			s.PolicyRules()
		}()
		go func() {
			defer wg.Done()
			s.HasRules()
		}()
	}
	wg.Wait()
}

func TestTargetScope_ConcurrentMergeAgentRules_TwoLayer(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)
	u, _ := url.Parse("http://api.example.com/path")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			s.MergeAgentRules(
				[]TargetRule{{Hostname: "api.example.com"}},
				[]TargetRule{{Hostname: "old.example.com"}},
				nil, nil,
			)
		}()
		go func() {
			defer wg.Done()
			s.CheckURL(u)
		}()
		go func() {
			defer wg.Done()
			s.AgentRules()
		}()
	}
	wg.Wait()
}

func TestTargetScope_SetAgentRules_NoPolicyAllowsNoError(t *testing.T) {
	// When no policy allows are set, any agent allows should be accepted.
	s := NewTargetScope()
	err := s.SetAgentRules([]TargetRule{{Hostname: "anything.com"}}, nil)
	if err != nil {
		t.Errorf("SetAgentRules without policy: unexpected error: %v", err)
	}
}

func TestTargetScope_MergeAgentRules_NoPolicyAllowsNoError(t *testing.T) {
	s := NewTargetScope()
	err := s.MergeAgentRules([]TargetRule{{Hostname: "anything.com"}}, nil, nil, nil)
	if err != nil {
		t.Errorf("MergeAgentRules without policy: unexpected error: %v", err)
	}
}

func TestTargetScope_AgentDenies_NoPolicyBoundary(t *testing.T) {
	// Agent denies are not subject to policy allow boundary — they can deny anything.
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.example.com"}}, nil)

	// Add denies for a hostname outside policy allows — should be fine.
	err := s.SetAgentRules(nil, []TargetRule{{Hostname: "outside.com"}})
	if err != nil {
		t.Errorf("SetAgentRules with outside deny: unexpected error: %v", err)
	}
}

func TestTargetScope_PolicyDeniesWithPorts(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(
		nil,
		[]TargetRule{{Hostname: "example.com", Ports: []int{8080}, PathPrefix: "/admin/"}},
	)

	tests := []struct {
		name      string
		port      int
		path      string
		wantAllow bool
	}{
		{"policy deny matches port and path", 8080, "/admin/settings", false},
		{"different port allowed", 80, "/admin/settings", true},
		{"different path allowed", 8080, "/api/data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := s.CheckTarget("http", "example.com", tt.port, tt.path)
			if allowed != tt.wantAllow {
				t.Errorf("CheckTarget port=%d path=%q: allowed = %v, want %v",
					tt.port, tt.path, allowed, tt.wantAllow)
			}
		})
	}
}

func TestHostnameCoveredBy(t *testing.T) {
	tests := []struct {
		name     string
		covering string
		covered  string
		want     bool
	}{
		{"exact same", "example.com", "example.com", true},
		{"exact same case insensitive", "Example.COM", "example.com", true},
		{"wildcard covers exact", "*.example.com", "sub.example.com", true},
		{"wildcard covers same wildcard", "*.example.com", "*.example.com", true},
		{"wildcard covers deeper subdomain wildcard", "*.example.com", "*.sub.example.com", true},
		{"exact does not cover wildcard", "example.com", "*.example.com", false},
		{"narrower wildcard does not cover wider", "*.sub.example.com", "*.example.com", false},
		{"different domains", "*.example.com", "other.com", false},
		{"different domain wildcards", "*.example.com", "*.other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostnameCoveredBy(tt.covering, tt.covered)
			if got != tt.want {
				t.Errorf("hostnameCoveredBy(%q, %q) = %v, want %v",
					tt.covering, tt.covered, got, tt.want)
			}
		})
	}
}

func TestRuleCoversRule(t *testing.T) {
	tests := []struct {
		name     string
		covering TargetRule
		covered  TargetRule
		want     bool
	}{
		{
			name:     "exact same rule",
			covering: TargetRule{Hostname: "a.com", Ports: []int{80}},
			covered:  TargetRule{Hostname: "a.com", Ports: []int{80}},
			want:     true,
		},
		{
			name:     "covering has no port restriction",
			covering: TargetRule{Hostname: "a.com"},
			covered:  TargetRule{Hostname: "a.com", Ports: []int{80}},
			want:     true,
		},
		{
			name:     "covered has no port restriction but covering does",
			covering: TargetRule{Hostname: "a.com", Ports: []int{80}},
			covered:  TargetRule{Hostname: "a.com"},
			want:     false,
		},
		{
			name:     "covered ports subset of covering",
			covering: TargetRule{Hostname: "a.com", Ports: []int{80, 443}},
			covered:  TargetRule{Hostname: "a.com", Ports: []int{80}},
			want:     true,
		},
		{
			name:     "covered port not in covering",
			covering: TargetRule{Hostname: "a.com", Ports: []int{80}},
			covered:  TargetRule{Hostname: "a.com", Ports: []int{443}},
			want:     false,
		},
		{
			name:     "covering has no scheme restriction",
			covering: TargetRule{Hostname: "a.com"},
			covered:  TargetRule{Hostname: "a.com", Schemes: []string{"https"}},
			want:     true,
		},
		{
			name:     "covered has no scheme restriction but covering does",
			covering: TargetRule{Hostname: "a.com", Schemes: []string{"https"}},
			covered:  TargetRule{Hostname: "a.com"},
			want:     false,
		},
		{
			name:     "covering path prefix is prefix of covered",
			covering: TargetRule{Hostname: "a.com", PathPrefix: "/api/"},
			covered:  TargetRule{Hostname: "a.com", PathPrefix: "/api/v2/"},
			want:     true,
		},
		{
			name:     "covered path less specific than covering",
			covering: TargetRule{Hostname: "a.com", PathPrefix: "/api/v2/"},
			covered:  TargetRule{Hostname: "a.com", PathPrefix: "/api/"},
			want:     false,
		},
		{
			name:     "covered has no path but covering restricts",
			covering: TargetRule{Hostname: "a.com", PathPrefix: "/api/"},
			covered:  TargetRule{Hostname: "a.com"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleCoversRule(tt.covering, tt.covered)
			if got != tt.want {
				t.Errorf("ruleCoversRule(%+v, %+v) = %v, want %v",
					tt.covering, tt.covered, got, tt.want)
			}
		})
	}
}
