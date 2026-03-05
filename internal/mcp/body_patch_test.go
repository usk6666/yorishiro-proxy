package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyBodyPatches_JSONPath(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		patches []BodyPatch
		want    map[string]any
		wantErr bool
	}{
		{
			name: "simple top-level key",
			body: `{"name":"old","age":30}`,
			patches: []BodyPatch{
				{JSONPath: "$.name", Value: "new"},
			},
			want: map[string]any{"name": "new", "age": float64(30)},
		},
		{
			name: "nested key",
			body: `{"user":{"name":"old","role":"viewer"}}`,
			patches: []BodyPatch{
				{JSONPath: "$.user.name", Value: "injected"},
			},
			want: map[string]any{
				"user": map[string]any{"name": "injected", "role": "viewer"},
			},
		},
		{
			name: "replace with number",
			body: `{"count":1}`,
			patches: []BodyPatch{
				{JSONPath: "$.count", Value: float64(42)},
			},
			want: map[string]any{"count": float64(42)},
		},
		{
			name: "replace with null",
			body: `{"key":"value"}`,
			patches: []BodyPatch{
				{JSONPath: "$.key", Value: nil},
			},
			want: map[string]any{"key": nil},
		},
		{
			name: "multiple patches applied in order",
			body: `{"a":"1","b":"2"}`,
			patches: []BodyPatch{
				{JSONPath: "$.a", Value: "x"},
				{JSONPath: "$.b", Value: "y"},
			},
			want: map[string]any{"a": "x", "b": "y"},
		},
		{
			name:    "nonexistent key returns error",
			body:    `{"name":"old"}`,
			patches: []BodyPatch{{JSONPath: "$.missing", Value: "val"}},
			wantErr: true,
		},
		{
			name:    "invalid JSON body returns error",
			body:    `not json`,
			patches: []BodyPatch{{JSONPath: "$.key", Value: "val"}},
			wantErr: true,
		},
		{
			name:    "empty json_path returns error",
			body:    `{"key":"val"}`,
			patches: []BodyPatch{{JSONPath: "", Value: "val"}},
			wantErr: true,
		},
		{
			name:    "json_path with nil value sets null",
			body:    `{"key":"val"}`,
			patches: []BodyPatch{{JSONPath: "$.key", Value: nil}},
			want:    map[string]any{"key": nil},
		},
		{
			name:    "path with empty segment returns error",
			body:    `{"key":"val"}`,
			patches: []BodyPatch{{JSONPath: "$.key..name", Value: "val"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyBodyPatches([]byte(tt.body), tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyBodyPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var gotMap map[string]any
			if err := json.Unmarshal(got, &gotMap); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}

			wantJSON, _ := json.Marshal(tt.want)
			gotJSON, _ := json.Marshal(gotMap)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("got %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestApplyBodyPatches_Regex(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		patches []BodyPatch
		want    string
		wantErr bool
	}{
		{
			name: "simple replacement",
			body: "csrf_token=abc123&name=test",
			patches: []BodyPatch{
				{Regex: "csrf_token=[^&]+", Replace: "csrf_token=newvalue"},
			},
			want: "csrf_token=newvalue&name=test",
		},
		{
			name: "capture group replacement",
			body: "Hello World 123",
			patches: []BodyPatch{
				{Regex: `(\w+) (\w+)`, Replace: "$2 $1"},
			},
			want: "World Hello 123",
		},
		{
			name: "delete by replacing with empty",
			body: "remove-this-part and keep this",
			patches: []BodyPatch{
				{Regex: "remove-this-part ", Replace: ""},
			},
			want: "and keep this",
		},
		{
			name: "multiple regex patches in order",
			body: "foo=bar&baz=qux",
			patches: []BodyPatch{
				{Regex: "foo=bar", Replace: "foo=replaced"},
				{Regex: "baz=qux", Replace: "baz=also-replaced"},
			},
			want: "foo=replaced&baz=also-replaced",
		},
		{
			name:    "invalid regex returns error",
			body:    "test",
			patches: []BodyPatch{{Regex: "[invalid", Replace: "x"}},
			wantErr: true,
		},
		{
			name:    "regex pattern at max length succeeds",
			body:    "test",
			patches: []BodyPatch{{Regex: strings.Repeat("a", maxRegexPatternLen), Replace: "x"}},
			want:    "test",
		},
		{
			name:    "regex pattern too long returns error",
			body:    "test",
			patches: []BodyPatch{{Regex: strings.Repeat("a", maxRegexPatternLen+1), Replace: "x"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyBodyPatches([]byte(tt.body), tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyBodyPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestApplyBodyPatches_MixedPatches(t *testing.T) {
	body := `{"user":{"name":"old","csrf":"token123"}}`

	patches := []BodyPatch{
		{JSONPath: "$.user.name", Value: "new"},
		{Regex: `token\d+`, Replace: "newtoken"},
	}

	got, err := applyBodyPatches([]byte(body), patches)
	if err != nil {
		t.Fatalf("applyBodyPatches() error = %v", err)
	}

	// After JSON path patch, name becomes "new".
	// After regex patch, token123 -> newtoken.
	if want := `"name":"new"`; !containsStr(string(got), want) {
		t.Errorf("result %q should contain %q", string(got), want)
	}
	if want := `newtoken`; !containsStr(string(got), want) {
		t.Errorf("result %q should contain %q", string(got), want)
	}
}

func TestValidateBodyPatch_Errors(t *testing.T) {
	tests := []struct {
		name    string
		patch   BodyPatch
		wantErr bool
	}{
		{
			name:    "both json_path and regex",
			patch:   BodyPatch{JSONPath: "$.key", Value: "v", Regex: "pat", Replace: "r"},
			wantErr: true,
		},
		{
			name:    "neither json_path nor regex",
			patch:   BodyPatch{},
			wantErr: true,
		},
		{
			name:  "json_path with nil value (valid JSON null)",
			patch: BodyPatch{JSONPath: "$.key", Value: nil},
		},
		{
			name:  "valid json_path",
			patch: BodyPatch{JSONPath: "$.key", Value: "v"},
		},
		{
			name:  "valid regex",
			patch: BodyPatch{Regex: "pat", Replace: "r"},
		},
		{
			name:  "regex with empty replace is ok",
			patch: BodyPatch{Regex: "pat", Replace: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBodyPatch(tt.patch)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBodyPatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []string
		wantErr bool
	}{
		{name: "dollar prefix", path: "$.foo.bar", want: []string{"foo", "bar"}},
		{name: "no prefix", path: "foo.bar", want: []string{"foo", "bar"}},
		{name: "single key", path: "$.key", want: []string{"key"}},
		{name: "just dollar", path: "$", wantErr: true},
		{name: "empty", path: "", wantErr: true},
		{name: "trailing dot", path: "$.foo.", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJSONPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJSONPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("parseJSONPath(%q) = %v, want %v", tt.path, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseJSONPath(%q)[%d] = %q, want %q", tt.path, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// containsStr is a helper for substring checks.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
