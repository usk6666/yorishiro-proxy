package config

import (
	"slices"
	"strings"
	"testing"
)

func TestParseMCPTools(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "unset", in: "", want: nil},
		{name: "single", in: "query", want: []string{"query"}},
		{name: "trimmed", in: " query , docs ", want: []string{"query", "docs"}},
		{name: "empty element kept for Validate", in: "a,,b", want: []string{"a", "", "b"}},
		{name: "only separators", in: " , ", want: []string{"", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMCPTools(tt.in)
			if !slices.Equal(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("ParseMCPTools(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestConfigValidate_MCPTools(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "unset", raw: ""},
		{name: "trimmed names", raw: " query , docs "},
		{name: "duplicates tolerated", raw: "query,query"},
		{name: "empty middle element", raw: "a,,b", wantErr: true},
		{name: "only separators", raw: " , ", wantErr: true},
		{name: "trailing comma", raw: "query,", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.MCPTools = ParseMCPTools(tt.raw)
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "mcp_tools") {
					t.Errorf("Validate() with mcp tools %q = %v, want an mcp_tools error", tt.raw, err)
				}
				return
			}
			if err != nil {
				t.Errorf("Validate() with mcp tools %q = %v, want nil", tt.raw, err)
			}
		})
	}
}

// TestConfigValidate_MCPToolsEmptyElement covers the field directly, so the
// shape check does not depend on ParseMCPTools.
func TestConfigValidate_MCPToolsEmptyElement(t *testing.T) {
	cfg := Default()
	cfg.MCPTools = []string{"query", ""}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() accepted an empty mcp_tools element")
	}
}
