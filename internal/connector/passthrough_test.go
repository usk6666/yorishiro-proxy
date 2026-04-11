package connector

import "testing"

func TestMatchWildcardPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		want     bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.baz.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"example.com", "foo.example.com", false},  // not a wildcard pattern
		{"*example.com", "foo.example.com", false}, // malformed: missing dot after *
		{"*.com", "example.com", true},
		{"*.com", "com", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := matchWildcardPattern(tt.pattern, tt.hostname)
			if got != tt.want {
				t.Errorf("matchWildcardPattern(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
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
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePattern(tt.input)
			if got != tt.want {
				t.Errorf("normalizePattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPassthroughList_BasicOps(t *testing.T) {
	pl := NewPassthroughList()
	if !pl.Add("example.com") {
		t.Fatal("Add(example.com) = false")
	}
	if !pl.Add("*.test.com") {
		t.Fatal("Add(*.test.com) = false")
	}
	if pl.Len() != 2 {
		t.Errorf("Len = %d, want 2", pl.Len())
	}
	if !pl.Contains("example.com") {
		t.Error("Contains(example.com) = false")
	}
	if !pl.Contains("foo.test.com") {
		t.Error("Contains(foo.test.com) = false")
	}
	if pl.Contains("test.com") {
		t.Error("Contains(test.com) = true (bare domain should not match wildcard)")
	}

	if !pl.Remove("example.com") {
		t.Error("Remove(example.com) = false")
	}
	if pl.Contains("example.com") {
		t.Error("Contains(example.com) after Remove = true")
	}
}
