package mcptest

import (
	"errors"
	"testing"
)

// Test the unexported helpers used by Harness.ExpectError so we have
// a fast feedback loop on the substring matching contract without
// having to spin up a full MCP server.

func TestCombineErrorText(t *testing.T) {
	tests := []struct {
		name string
		in   ToolResult
		want string
	}{
		{
			name: "transport error wins",
			in:   ToolResult{Err: errors.New("network down")},
			want: "network down",
		},
		{
			name: "tool reported IsError surfaces Text",
			in:   ToolResult{IsError: true, Text: "missing required field action"},
			want: "missing required field action",
		},
		{
			name: "Err takes precedence over IsError",
			in: ToolResult{
				Err:     errors.New("rpc failed"),
				IsError: true,
				Text:    "should be ignored",
			},
			want: "rpc failed",
		},
		{
			name: "success returns empty",
			in:   ToolResult{Text: "ok"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := combineErrorText(tt.in)
			if got != tt.want {
				t.Errorf("combineErrorText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		haystack string
		needle   string
		want     bool
	}{
		{"empty needle matches anything", "abc", "", true},
		{"exact match", "abc", "abc", true},
		{"prefix match", "abc def", "abc", true},
		{"suffix match", "abc def", "def", true},
		{"middle match", "abc def ghi", "def", true},
		{"no match", "abc", "xyz", false},
		{"needle longer than haystack", "abc", "abcdef", false},
		{"case sensitive", "ABC", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.haystack, tt.needle)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.haystack, tt.needle, got, tt.want)
			}
		})
	}
}

func TestGenerateToken_FormatAndUniqueness(t *testing.T) {
	a, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	b, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}

	// 32 bytes -> 64 hex chars
	const want = 64
	if len(a) != want {
		t.Errorf("token length = %d, want %d", len(a), want)
	}
	if len(b) != want {
		t.Errorf("token length = %d, want %d", len(b), want)
	}

	// Hex alphabet only.
	for i, r := range a {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("token[%d] = %q, want hex digit", i, r)
			break
		}
	}

	// Two consecutive calls should not collide. (Cryptographic
	// uniqueness, not statistical: a real collision is astronomically
	// unlikely.)
	if a == b {
		t.Errorf("two consecutive tokens collided: %q", a)
	}
}
