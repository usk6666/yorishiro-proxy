package common

import (
	"strings"
	"testing"
)

func TestCompilePattern_Valid(t *testing.T) {
	re, err := CompilePattern(`\d+`)
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("123") {
		t.Error("expected match")
	}
}

func TestCompilePattern_TooLong(t *testing.T) {
	pattern := strings.Repeat("a", MaxPatternLength+1)
	_, err := CompilePattern(pattern)
	if err == nil {
		t.Error("expected error for too-long pattern")
	}
}

func TestCompilePattern_Invalid(t *testing.T) {
	_, err := CompilePattern(`[invalid`)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestCompilePattern_AtLimit(t *testing.T) {
	pattern := strings.Repeat("a", MaxPatternLength)
	_, err := CompilePattern(pattern)
	if err != nil {
		t.Fatalf("expected success at limit, got %v", err)
	}
}

func TestCompileHeaderMatch_Valid(t *testing.T) {
	compiled, err := CompileHeaderMatch(map[string]string{
		"content-type": "application/json",
		"x-custom":     "val.*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 2 {
		t.Errorf("expected 2 entries, got %d", len(compiled))
	}
}

func TestCompileHeaderMatch_Nil(t *testing.T) {
	compiled, err := CompileHeaderMatch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if compiled != nil {
		t.Error("expected nil for nil input")
	}
}

func TestCompileHeaderMatch_InvalidPattern(t *testing.T) {
	_, err := CompileHeaderMatch(map[string]string{
		"content-type": `[invalid`,
	})
	if err == nil {
		t.Error("expected error for invalid pattern")
	}
}

func TestCompilePreset(t *testing.T) {
	preset, err := LookupPreset(PresetDestructiveSQL)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := CompilePreset(preset)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Error("expected rules from preset")
	}
	for _, r := range rules {
		if r.Pattern == nil {
			t.Errorf("rule %s has nil pattern", r.ID)
		}
		if r.Category != PresetDestructiveSQL {
			t.Errorf("rule %s category = %q, want %q", r.ID, r.Category, PresetDestructiveSQL)
		}
	}
}

func TestLookupPreset_Unknown(t *testing.T) {
	_, err := LookupPreset("nonexistent")
	if err == nil {
		t.Error("expected error for unknown preset")
	}
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	if len(names) < 2 {
		t.Errorf("expected at least 2 presets, got %d", len(names))
	}
	// Verify sorted.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("not sorted: %v", names)
			break
		}
	}
}
