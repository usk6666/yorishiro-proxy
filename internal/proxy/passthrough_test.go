package proxy

import (
	"sort"
	"sync"
	"testing"
)

func TestPassthroughList_Add(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{
			name:    "exact domain",
			pattern: "example.com",
			want:    true,
		},
		{
			name:    "wildcard domain",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "empty pattern",
			pattern: "",
			want:    false,
		},
		{
			name:    "whitespace only",
			pattern: "   ",
			want:    false,
		},
		{
			name:    "domain with spaces is trimmed",
			pattern: "  example.com  ",
			want:    true,
		},
		{
			name:    "uppercase is normalized",
			pattern: "EXAMPLE.COM",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := NewPassthroughList()
			got := pl.Add(tt.pattern)
			if got != tt.want {
				t.Errorf("Add(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestPassthroughList_Add_Duplicate(t *testing.T) {
	pl := NewPassthroughList()
	pl.Add("example.com")
	pl.Add("example.com") // duplicate

	if pl.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (duplicates should be ignored)", pl.Len())
	}
}

func TestPassthroughList_Remove(t *testing.T) {
	tests := []struct {
		name    string
		add     []string
		remove  string
		want    bool
		wantLen int
	}{
		{
			name:    "remove existing pattern",
			add:     []string{"example.com"},
			remove:  "example.com",
			want:    true,
			wantLen: 0,
		},
		{
			name:    "remove non-existing pattern",
			add:     []string{"example.com"},
			remove:  "other.com",
			want:    false,
			wantLen: 1,
		},
		{
			name:    "remove empty pattern",
			add:     []string{"example.com"},
			remove:  "",
			want:    false,
			wantLen: 1,
		},
		{
			name:    "remove with case normalization",
			add:     []string{"example.com"},
			remove:  "EXAMPLE.COM",
			want:    true,
			wantLen: 0,
		},
		{
			name:    "remove wildcard",
			add:     []string{"*.example.com"},
			remove:  "*.example.com",
			want:    true,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := NewPassthroughList()
			for _, p := range tt.add {
				pl.Add(p)
			}
			got := pl.Remove(tt.remove)
			if got != tt.want {
				t.Errorf("Remove(%q) = %v, want %v", tt.remove, got, tt.want)
			}
			if pl.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", pl.Len(), tt.wantLen)
			}
		})
	}
}

func TestPassthroughList_Contains(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		hostname string
		want     bool
	}{
		{
			name:     "exact match",
			patterns: []string{"example.com"},
			hostname: "example.com",
			want:     true,
		},
		{
			name:     "exact match case insensitive",
			patterns: []string{"example.com"},
			hostname: "EXAMPLE.COM",
			want:     true,
		},
		{
			name:     "no match",
			patterns: []string{"example.com"},
			hostname: "other.com",
			want:     false,
		},
		{
			name:     "wildcard matches subdomain",
			patterns: []string{"*.example.com"},
			hostname: "foo.example.com",
			want:     true,
		},
		{
			name:     "wildcard matches nested subdomain",
			patterns: []string{"*.example.com"},
			hostname: "bar.foo.example.com",
			want:     true,
		},
		{
			name:     "wildcard does not match exact domain",
			patterns: []string{"*.example.com"},
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "wildcard case insensitive",
			patterns: []string{"*.EXAMPLE.COM"},
			hostname: "foo.example.com",
			want:     true,
		},
		{
			name:     "empty hostname",
			patterns: []string{"example.com"},
			hostname: "",
			want:     false,
		},
		{
			name:     "empty list",
			patterns: []string{},
			hostname: "example.com",
			want:     false,
		},
		{
			name:     "multiple patterns first matches",
			patterns: []string{"foo.com", "bar.com"},
			hostname: "foo.com",
			want:     true,
		},
		{
			name:     "multiple patterns second matches",
			patterns: []string{"foo.com", "bar.com"},
			hostname: "bar.com",
			want:     true,
		},
		{
			name:     "wildcard and exact combined",
			patterns: []string{"example.com", "*.cdn.example.com"},
			hostname: "static.cdn.example.com",
			want:     true,
		},
		{
			name:     "hostname with spaces is trimmed",
			patterns: []string{"example.com"},
			hostname: "  example.com  ",
			want:     true,
		},
		{
			name:     "wildcard does not match partial domain",
			patterns: []string{"*.example.com"},
			hostname: "notexample.com",
			want:     false,
		},
		{
			name:     "wildcard does not match different suffix",
			patterns: []string{"*.example.com"},
			hostname: "foo.example.org",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := NewPassthroughList()
			for _, p := range tt.patterns {
				pl.Add(p)
			}
			got := pl.Contains(tt.hostname)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestPassthroughList_List(t *testing.T) {
	pl := NewPassthroughList()
	pl.Add("beta.com")
	pl.Add("alpha.com")
	pl.Add("*.gamma.com")

	got := pl.List()
	sort.Strings(got)

	want := []string{"*.gamma.com", "alpha.com", "beta.com"}
	if len(got) != len(want) {
		t.Fatalf("List() returned %d items, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPassthroughList_Len(t *testing.T) {
	pl := NewPassthroughList()
	if pl.Len() != 0 {
		t.Errorf("Len() = %d, want 0", pl.Len())
	}

	pl.Add("a.com")
	pl.Add("b.com")
	if pl.Len() != 2 {
		t.Errorf("Len() = %d, want 2", pl.Len())
	}

	pl.Remove("a.com")
	if pl.Len() != 1 {
		t.Errorf("Len() = %d, want 1", pl.Len())
	}
}

func TestPassthroughList_ConcurrentAccess(t *testing.T) {
	pl := NewPassthroughList()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent adds.
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			pl.Add("example.com")
		}(i)
	}

	// Concurrent contains checks.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			pl.Contains("example.com")
		}()
	}

	// Concurrent list calls.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			pl.List()
		}()
	}

	wg.Wait()

	// After all concurrent adds of the same pattern, should have exactly 1.
	if pl.Len() != 1 {
		t.Errorf("Len() = %d, want 1", pl.Len())
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		want     bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.baz.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"example.com", "foo.example.com", false}, // not a wildcard pattern
		{"*example.com", "foo.example.com", false}, // malformed: missing dot after *
		{"*.com", "example.com", true},
		{"*.com", "com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := matchWildcard(tt.pattern, tt.hostname)
			if got != tt.want {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
			}
		})
	}
}

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  Example.Com  ", "example.com"},
		{"*.EXAMPLE.COM", "*.example.com"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePattern(tt.input)
			if got != tt.want {
				t.Errorf("normalizePattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
