package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestApplyBodyPatches_JSONPath_ByteExact pins that a json_path patch
// rewrites only the bytes of the target value; every other byte of the
// body (key order, whitespace, escapes, number spelling, duplicate keys,
// invalid UTF-8) is left exactly as the wire carried it.
func TestApplyBodyPatches_JSONPath_ByteExact(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		patches []BodyPatch
		want    string
	}{
		{
			// Issue body, verified live against httpbin.org/anything.
			name:    "issue_repro",
			body:    `{"zeta":1,"alpha":{"y":2,"b":3},"url":"a/b<c>&d","big":12345678901234567890}`,
			patches: []BodyPatch{{JSONPath: "$.zeta", Value: float64(2)}},
			want:    `{"zeta":2,"alpha":{"y":2,"b":3},"url":"a/b<c>&d","big":12345678901234567890}`,
		},
		{
			name:    "nested_indented",
			body:    "{\n  \"zeta\": 1,\n  \"alpha\": {\n    \"y\": 2,\n    \"b\": 3\n  }\n}\n",
			patches: []BodyPatch{{JSONPath: "$.alpha.b", Value: "x<y>&"}},
			want:    "{\n  \"zeta\": 1,\n  \"alpha\": {\n    \"y\": 2,\n    \"b\": \"x<y>&\"\n  }\n}\n",
		},
		{
			name:    "duplicate_last_wins",
			body:    `{"a":1,"b":0,"a":2}`,
			patches: []BodyPatch{{JSONPath: "$.a", Value: float64(9)}},
			want:    `{"a":1,"b":0,"a":9}`,
		},
		{
			name:    "duplicate_intermediate_last_wins",
			body:    `{"o":{"k":1},"o":{"k":2}}`,
			patches: []BodyPatch{{JSONPath: "$.o.k", Value: float64(9)}},
			want:    `{"o":{"k":1},"o":{"k":9}}`,
		},
		{
			name:    "escaped_key",
			body:    `{"zeta":1, "other":"é"}`,
			patches: []BodyPatch{{JSONPath: "$.zeta", Value: "v"}},
			want:    `{"zeta":"v", "other":"é"}`,
		},
		{
			name: "sequential_length_change",
			body: `{"b":2,"a":1}`,
			patches: []BodyPatch{
				{JSONPath: "$.a", Value: float64(10)},
				{JSONPath: "$.b", Value: float64(20)},
			},
			want: `{"b":20,"a":10}`,
		},
		{
			name:    "invalid_utf8_elsewhere",
			body:    "{\"a\":1,\"b\":\"\xff\"}",
			patches: []BodyPatch{{JSONPath: "$.a", Value: float64(2)}},
			want:    "{\"a\":2,\"b\":\"\xff\"}",
		},
		{
			name:    "container_value_replaced_whole",
			body:    `{"a" : {"x":[1,{"y":"}\"]"}]} , "b":true}`,
			patches: []BodyPatch{{JSONPath: "$.a", Value: "s"}},
			want:    `{"a" : "s" , "b":true}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []byte(tt.body)
			orig := append([]byte(nil), in...)
			got, err := applyBodyPatches(in, tt.patches)
			if err != nil {
				t.Fatalf("applyBodyPatches() error = %v", err)
			}
			if !bytes.Equal(got, []byte(tt.want)) {
				t.Errorf("applyBodyPatches() =\n  %q\nwant\n  %q", got, tt.want)
			}
			if !bytes.Equal(in, orig) {
				t.Errorf("input body mutated in place: %q", in)
			}
		})
	}
}

// TestApplyBodyPatches_JSONPath_ValueEncoding pins the encoding of the
// value types go-sdk hands the handler (string/float64/bool/nil/[]any/
// map[string]any): compact, HTML escaping off.
func TestApplyBodyPatches_JSONPath_ValueEncoding(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"null", nil, `{"x":null}`},
		{"bool", true, `{"x":true}`},
		{"array", []any{"<", float64(1)}, `{"x":["<",1]}`},
		{"object", map[string]any{"k": "&"}, `{"x":{"k":"&"}}`},
		{"string_html", "<a&b>", `{"x":"<a&b>"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyBodyPatches([]byte(`{"x":0}`), []BodyPatch{{JSONPath: "$.x", Value: tt.value}})
			if err != nil {
				t.Fatalf("applyBodyPatches() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("applyBodyPatches() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestApplyBodyPatches_ValueJSON_ByteExact pins that value_json is spliced
// verbatim (big integers, key order, inner whitespace and escapes preserved).
func TestApplyBodyPatches_ValueJSON_ByteExact(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		path      string
		valueJSON string
		want      string
	}{
		{"big_int", `{"big":1,"x":0}`, "$.big", `12345678901234567890`, `{"big":12345678901234567890,"x":0}`},
		{"object_key_order", `{"big":1,"x":0}`, "$.big", `{"z":1,"a":2}`, `{"big":{"z":1,"a":2},"x":0}`},
		{"whitespace_kept", `{"a":1}`, "$.a", ` [ 1 , 2 ] `, `{"a": [ 1 , 2 ] }`},
		{"string_escapes_kept", `{"a":1}`, "$.a", `"<"`, `{"a":"<"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyBodyPatches([]byte(tt.body), []BodyPatch{{JSONPath: tt.path, ValueJSON: tt.valueJSON}})
			if err != nil {
				t.Fatalf("applyBodyPatches() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("applyBodyPatches() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestValidateBodyPatch_ValueJSON pins the value_json validation rules.
func TestValidateBodyPatch_ValueJSON(t *testing.T) {
	tests := []struct {
		name    string
		patch   BodyPatch
		wantErr string
	}{
		{"valid", BodyPatch{JSONPath: "$.a", ValueJSON: `1`}, ""},
		{"with_regex", BodyPatch{Regex: "a", Replace: "b", ValueJSON: `1`}, "value_json"},
		{"with_value", BodyPatch{JSONPath: "$.a", Value: "v", ValueJSON: `1`}, "value_json"},
		{"with_encoding", BodyPatch{JSONPath: "$.a", ValueJSON: `"v"`, Encoding: []string{"base64"}}, "value_json"},
		{"invalid_json", BodyPatch{JSONPath: "$.a", ValueJSON: `{"a":`}, "value_json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBodyPatch(tt.patch)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateBodyPatch() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateBodyPatch() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestApplyBodyPatches_JSONPath_Errors pins the error paths (message shapes
// kept from the decode/re-encode implementation) and that malformed,
// attacker-controlled bodies produce errors rather than panics.
func TestApplyBodyPatches_JSONPath_Errors(t *testing.T) {
	deep := strings.Repeat("[", 10001) + strings.Repeat("]", 10001)
	tests := []struct {
		name    string
		body    string
		path    string
		wantErr string
	}{
		{"missing_final_key", `{"a":{"b":1}}`, "$.a.c", `json_path key "c" not found`},
		{"missing_intermediate", `{"a":{"b":1}}`, "$.x.b", `json_path key "x" not found`},
		{"non_object_intermediate", `{"a":[1]}`, "$.a.b", `json_path key "b": expected object, got array`},
		{"top_level_array", `[1]`, "$.a", `json_path key "a": expected object, got array`},
		{"top_level_string", ` "s" `, "$.a", `json_path key "a": expected object, got string`},
		{"empty_object", `{}`, "$.a", `json_path key "a" not found`},
		{"truncated", `{"a":1`, "$.a", "body is not valid JSON"},
		{"trailing_garbage", `{"a":1} x`, "$.a", "body is not valid JSON"},
		{"empty_body", ``, "$.a", "body is not valid JSON"},
		{"too_deep", deep, "$.a", "body is not valid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyBodyPatches([]byte(tt.body), []BodyPatch{{JSONPath: tt.path, Value: float64(1)}})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("applyBodyPatches() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// FuzzApplyJSONPathPatch checks the scanner never panics on arbitrary
// bodies and, whenever it succeeds, yields valid JSON.
func FuzzApplyJSONPathPatch(f *testing.F) {
	f.Add([]byte(`{"zeta":1,"alpha":{"y":2,"b":3}}`), "$.alpha.b")
	f.Add([]byte(`{"a":1,"a":{"b":"\"}"}}`), "$.a.b")
	f.Add([]byte(`[{"a":1}]`), "$.a")
	f.Fuzz(func(t *testing.T, body []byte, path string) {
		got, err := applyBodyPatches(body, []BodyPatch{{JSONPath: path, ValueJSON: `"X"`}})
		if err != nil {
			return
		}
		if !json.Valid(got) {
			t.Fatalf("patched body is not valid JSON: %q -> %q", body, got)
		}
	})
}
