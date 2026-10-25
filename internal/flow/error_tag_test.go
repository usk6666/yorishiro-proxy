package flow

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTruncateErrorTag_RespectsCap covers the cap+marker behavior so a
// runaway nested-wrap chain (or a transport-layer error that embeds
// arbitrary attacker-controlled bytes via SNI/Host) cannot blow up the
// stored row. The multibyte cases make the cap land mid-rune.
func TestTruncateErrorTag_RespectsCap(t *testing.T) {
	const marker = "...[truncated]"
	tests := []struct {
		name string
		in   string
	}{
		{name: "ascii", in: strings.Repeat("a", ErrorTagMaxLen+512)},
		{name: "multibyte", in: strings.Repeat("あ", (ErrorTagMaxLen+512)/3)},
		{name: "multibyte_offset_1", in: "x" + strings.Repeat("あ", (ErrorTagMaxLen+512)/3)},
		{name: "multibyte_offset_2", in: "xy" + strings.Repeat("あ", (ErrorTagMaxLen+512)/3)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateErrorTag(tt.in)
			if len(got) > ErrorTagMaxLen {
				t.Errorf("len(TruncateErrorTag) = %d, want <= %d", len(got), ErrorTagMaxLen)
			}
			if !strings.HasSuffix(got, marker) {
				t.Errorf("TruncateErrorTag(%s) lacks suffix %q", tt.name, marker)
			}
			if !utf8.ValidString(got) {
				t.Errorf("TruncateErrorTag(%s) output is not valid UTF-8", tt.name)
			}
			if !strings.HasPrefix(tt.in, strings.TrimSuffix(got, marker)) {
				t.Errorf("TruncateErrorTag(%s) output is not an input prefix + marker", tt.name)
			}
		})
	}
}

// TestTruncateErrorTag_UnderCapUnchanged: messages at or under the cap
// are returned verbatim.
func TestTruncateErrorTag_UnderCapUnchanged(t *testing.T) {
	for _, in := range []string{
		"",
		"dial: stream error refused: layer shutdown",
		strings.Repeat("a", ErrorTagMaxLen),
	} {
		if got := TruncateErrorTag(in); got != in {
			t.Errorf("TruncateErrorTag(len=%d) changed the input (got len=%d)", len(in), len(got))
		}
	}
}
