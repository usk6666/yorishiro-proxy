package plugin

import (
	"testing"

	"go.starlark.net/starlark"
)

func TestGoToStarlark_And_Back(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]any
	}{
		{
			name:  "empty map",
			input: map[string]any{},
		},
		{
			name: "string values",
			input: map[string]any{
				"key": "value",
				"foo": "bar",
			},
		},
		{
			name: "mixed types",
			input: map[string]any{
				"str":   "hello",
				"num":   42,
				"float": 3.14,
				"bool":  true,
				"nil":   nil,
			},
		},
		{
			name: "nested map",
			input: map[string]any{
				"outer": map[string]any{
					"inner": "value",
				},
			},
		},
		{
			name: "list",
			input: map[string]any{
				"items": []any{"a", "b", "c"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dict, err := goToStarlark(tt.input)
			if err != nil {
				t.Fatalf("goToStarlark() error = %v", err)
			}
			if dict == nil {
				t.Fatal("goToStarlark() returned nil")
			}

			goVal, err := starlarkToGo(dict)
			if err != nil {
				t.Fatalf("starlarkToGo() error = %v", err)
			}

			// Basic type check - the round-trip should produce a map.
			if _, ok := goVal.(map[string]any); !ok {
				t.Errorf("starlarkToGo() returned %T, want map[string]any", goVal)
			}
		})
	}
}

func TestGoValueToStarlark_Types(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		wantType string
	}{
		{name: "nil", input: nil, wantType: "NoneType"},
		{name: "bool true", input: true, wantType: "bool"},
		{name: "bool false", input: false, wantType: "bool"},
		{name: "int", input: 42, wantType: "int"},
		{name: "int64", input: int64(100), wantType: "int"},
		{name: "float64", input: 3.14, wantType: "float"},
		{name: "string", input: "hello", wantType: "string"},
		{name: "bytes", input: []byte("data"), wantType: "bytes"},
		{name: "string slice", input: []string{"a", "b"}, wantType: "list"},
		{name: "any slice", input: []any{1, "two"}, wantType: "list"},
		{name: "map string any", input: map[string]any{"k": "v"}, wantType: "dict"},
		{name: "map string string", input: map[string]string{"k": "v"}, wantType: "dict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := goValueToStarlark(tt.input)
			if err != nil {
				t.Fatalf("goValueToStarlark() error = %v", err)
			}
			if val.Type() != tt.wantType {
				t.Errorf("goValueToStarlark() type = %q, want %q", val.Type(), tt.wantType)
			}
		})
	}
}

func TestStarlarkToGo_Types(t *testing.T) {
	tests := []struct {
		name  string
		input starlark.Value
		check func(t *testing.T, val any)
	}{
		{
			name:  "None",
			input: starlark.None,
			check: func(t *testing.T, val any) {
				if val != nil {
					t.Errorf("expected nil, got %v", val)
				}
			},
		},
		{
			name:  "Bool",
			input: starlark.True,
			check: func(t *testing.T, val any) {
				if v, ok := val.(bool); !ok || !v {
					t.Errorf("expected true, got %v", val)
				}
			},
		},
		{
			name:  "Int",
			input: starlark.MakeInt(42),
			check: func(t *testing.T, val any) {
				if v, ok := val.(int64); !ok || v != 42 {
					t.Errorf("expected 42, got %v", val)
				}
			},
		},
		{
			name:  "Float",
			input: starlark.Float(3.14),
			check: func(t *testing.T, val any) {
				if v, ok := val.(float64); !ok || v != 3.14 {
					t.Errorf("expected 3.14, got %v", val)
				}
			},
		},
		{
			name:  "String",
			input: starlark.String("hello"),
			check: func(t *testing.T, val any) {
				if v, ok := val.(string); !ok || v != "hello" {
					t.Errorf("expected hello, got %v", val)
				}
			},
		},
		{
			name:  "Bytes",
			input: starlark.Bytes("data"),
			check: func(t *testing.T, val any) {
				if v, ok := val.([]byte); !ok || string(v) != "data" {
					t.Errorf("expected data, got %v", val)
				}
			},
		},
		{
			name:  "Tuple",
			input: starlark.Tuple{starlark.MakeInt(1), starlark.String("two")},
			check: func(t *testing.T, val any) {
				arr, ok := val.([]any)
				if !ok || len(arr) != 2 {
					t.Errorf("expected []any of length 2, got %v", val)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := starlarkToGo(tt.input)
			if err != nil {
				t.Fatalf("starlarkToGo() error = %v", err)
			}
			tt.check(t, val)
		})
	}
}

func TestStarlarkToGo_DictNonStringKey(t *testing.T) {
	dict := starlark.NewDict(1)
	if err := dict.SetKey(starlark.MakeInt(1), starlark.String("val")); err != nil {
		t.Fatal(err)
	}
	_, err := starlarkToGo(dict)
	if err == nil {
		t.Fatal("expected error for non-string dict key")
	}
}
