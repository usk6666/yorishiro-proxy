package connector

import "testing"

// TestPassthroughList_ContainsHostSpellings covers the USK-1263 decision:
// spellings proven to dial the same host as the pattern match it; legacy
// IPv4 spellings never fold (passthrough is allow-like: less inspection),
// so they are compared as written.
func TestPassthroughList_ContainsHostSpellings(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Trailing dot on a name, either side.
		{"pinned.example", "pinned.example.", true},
		{"pinned.example", "PINNED.Example.", true},
		{"pinned.example.", "pinned.example", true},
		{"*.example.com", "a.example.com.", true},
		{"*.example.com", "b.a.example.com.", true},
		{"*.example.com.", "a.example.com", true},
		// IPv4-mapped IPv6 <-> dotted quad.
		{"127.0.0.1", "::ffff:127.0.0.1", true},
		{"127.0.0.1", "[::ffff:127.0.0.1]", true},
		{"127.0.0.1", "::ffff:7f00:1", true},
		{"::ffff:127.0.0.1", "127.0.0.1", true},
		// IPv6 forms, brackets and zone.
		{"[::1]", "::1", true},
		{"[::1]", "0:0::1", true},
		{"::1", "[::1]", true},
		{"::1", "::1%lo", true},
		{"0:0::1", "::1", true},

		// Negative controls: legacy IPv4 spellings are compared as written.
		{"127.0.0.1", "0x7f.0.0.1", false},
		{"127.0.0.1", "127.1", false},
		{"127.0.0.1", "2130706433", false},
		{"127.0.0.1", "0177.0.0.1", false},
		{"127.0.0.1", "127.0.0.1.", false},
		{"127.0.0.1", "[127.0.0.1]", false},
		{"0x7f.0.0.1", "127.0.0.1", false},
		{"[127.0.0.1]", "127.0.0.1", false},
		// Other non-equivalents.
		{"localhost", "localhost..", false},
		{"*.example.com", "example.com.", false},
		{"*.example.com", "a.example.com..", false},
		{"127.0.0.1", "::127.0.0.1", false},
		{"::1", "::2", false},
		// Legacy spellings still match themselves (lowercased).
		{"0x7f.0.0.1", "0X7F.0.0.1", true},
		{"127.0.0.1.", "127.0.0.1.", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.host, func(t *testing.T) {
			pl := NewPassthroughList()
			if !pl.Add(tt.pattern) {
				t.Fatalf("Add(%q) = false", tt.pattern)
			}
			if got := pl.Contains(tt.host); got != tt.want {
				t.Errorf("Add(%q); Contains(%q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

// TestPassthroughList_StoredPatternVerbatim: matching folds, storage does
// not. List reports the pattern as added (lowercased), and Remove needs
// that exact pattern.
func TestPassthroughList_StoredPatternVerbatim(t *testing.T) {
	pl := NewPassthroughList()
	pl.Add("Pinned.Example.")
	pl.Add("[::1]")
	got := pl.List()
	want := map[string]bool{"pinned.example.": true, "[::1]": true}
	if len(got) != len(want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("List contains %q, want only %v", p, want)
		}
	}
	if pl.Remove("pinned.example") {
		t.Error("Remove(pinned.example) = true, want false (stored pattern is pinned.example.)")
	}
	if pl.Remove("::1") {
		t.Error("Remove(::1) = true, want false (stored pattern is [::1])")
	}
	if !pl.Contains("pinned.example") {
		t.Error("Contains(pinned.example) = false after failed Remove")
	}
	if !pl.Remove("PINNED.EXAMPLE.") {
		t.Error("Remove(PINNED.EXAMPLE.) = false, want true")
	}
	if pl.Contains("pinned.example.") {
		t.Error("Contains(pinned.example.) = true after Remove")
	}

	// Two stored spellings of one host: removing one keeps the other.
	pl.Add("a.example")
	pl.Add("a.example.")
	pl.Remove("a.example")
	if !pl.Contains("a.example") {
		t.Error("Contains(a.example) = false after removing only one of two spellings")
	}
}
