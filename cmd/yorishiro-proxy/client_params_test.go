package main

import (
	"bytes"
	"strings"
	"testing"
)

// --- parseArrayValue tests ---

func TestParseArrayValue_SimpleCSV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single element",
			input: "a",
			want:  []string{"a"},
		},
		{
			name:  "three elements",
			input: "a,b,c",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "quoted element with comma",
			input: "'a,b','c,d'",
			want:  []string{"a,b", "c,d"},
		},
		{
			name:  "mixed quoted and unquoted",
			input: "a,'b,c',d",
			want:  []string{"a", "b,c", "d"},
		},
		{
			name:  "spaces preserved",
			input: "a, b, c",
			want:  []string{"a", " b", " c"},
		},
		{
			name:  "empty elements",
			input: "a,,b",
			want:  []string{"a", "", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseArrayValue(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseArrayValue(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("parseArrayValue(%q)[%d] = %q, want %q", tt.input, i, got[i], w)
				}
			}
		})
	}
}

// --- parseToolSchema tests ---

func TestParseToolSchema_NilInput(t *testing.T) {
	got := parseToolSchema(nil)
	if got != nil {
		t.Errorf("parseToolSchema(nil) = %v, want nil", got)
	}
}

func TestParseToolSchema_NotMap(t *testing.T) {
	got := parseToolSchema("not a map")
	if got != nil {
		t.Errorf("parseToolSchema(string) = %v, want nil", got)
	}
}

func TestParseToolSchema_EmptyObject(t *testing.T) {
	got := parseToolSchema(map[string]any{})
	if got == nil {
		t.Fatal("parseToolSchema({}) = nil, want non-nil")
	}
	if len(got.properties) != 0 {
		t.Errorf("properties should be empty, got %v", got.properties)
	}
	if len(got.required) != 0 {
		t.Errorf("required should be empty, got %v", got.required)
	}
}

func TestParseToolSchema_WithProperties(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit":    map[string]any{"type": "integer"},
			"resource": map[string]any{"type": "string"},
			"enabled":  map[string]any{"type": "boolean"},
			"tags":     map[string]any{"type": "array"},
		},
		"required": []any{"resource"},
	}

	got := parseToolSchema(schema)
	if got == nil {
		t.Fatal("parseToolSchema returned nil")
	}

	wantTypes := map[string]string{
		"limit":    "integer",
		"resource": "string",
		"enabled":  "boolean",
		"tags":     "array",
	}
	for key, wantType := range wantTypes {
		if got.properties[key] != wantType {
			t.Errorf("properties[%q] = %q, want %q", key, got.properties[key], wantType)
		}
	}

	if !got.required["resource"] {
		t.Error("resource should be required")
	}
	if got.required["limit"] {
		t.Error("limit should not be required")
	}
}

func TestParseToolSchema_WithEnums(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"protocol": map[string]any{
				"type": "string",
				"enum": []any{"http", "https", "h2"},
			},
		},
	}

	got := parseToolSchema(schema)
	if got == nil {
		t.Fatal("parseToolSchema returned nil")
	}
	enums, ok := got.enums["protocol"]
	if !ok {
		t.Fatal("enum for 'protocol' not found")
	}
	if len(enums) != 3 {
		t.Errorf("expected 3 enum values, got %d: %v", len(enums), enums)
	}
}

// --- coerceValue tests ---

func TestCoerceValue_NilSchema(t *testing.T) {
	got := coerceValue("limit", "10", nil)
	if got != "10" {
		t.Errorf("coerceValue with nil schema = %v, want string '10'", got)
	}
}

func TestCoerceValue_UnknownKey(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"resource": "string"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}
	got := coerceValue("unknown", "foo", schema)
	if got != "foo" {
		t.Errorf("coerceValue unknown key = %v, want 'foo'", got)
	}
}

func TestCoerceValue_IntegerType(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"limit": "integer"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	tests := []struct {
		input string
		want  any
	}{
		{"10", int64(10)},
		{"0", int64(0)},
		{"-5", int64(-5)},
		{"3.14", float64(3.14)},
		{"abc", "abc"},
	}
	for _, tt := range tests {
		got := coerceValue("limit", tt.input, schema)
		if got != tt.want {
			t.Errorf("coerceValue('limit', %q) = %v (%T), want %v (%T)", tt.input, got, got, tt.want, tt.want)
		}
	}
}

func TestCoerceValue_NumberType(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"rate": "number"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	got := coerceValue("rate", "3.14", schema)
	if got != float64(3.14) {
		t.Errorf("coerceValue number = %v (%T), want float64(3.14)", got, got)
	}
}

func TestCoerceValue_BooleanType(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"enabled": "boolean"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	tests := []struct {
		input string
		want  any
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"False", false},
		{"FALSE", false},
		{"0", false},
		{"no", false},
		{"maybe", "maybe"},
	}
	for _, tt := range tests {
		got := coerceValue("enabled", tt.input, schema)
		if got != tt.want {
			t.Errorf("coerceValue('enabled', %q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestCoerceValue_ArrayType(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"payloads": "array"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	got := coerceValue("payloads", "a,b,c", schema)
	arr, ok := got.([]string)
	if !ok {
		t.Fatalf("coerceValue array type: got %T, want []string", got)
	}
	if len(arr) != 3 || arr[0] != "a" || arr[1] != "b" || arr[2] != "c" {
		t.Errorf("coerceValue array = %v, want [a b c]", arr)
	}
}

// --- buildToolParams tests ---

func TestBuildToolParams_EmptyArgs(t *testing.T) {
	params, err := buildToolParams("query", []string{}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("expected empty params, got %v", params)
	}
}

func TestBuildToolParams_KeyValuePairs(t *testing.T) {
	params, err := buildToolParams("query", []string{"resource=flows", "limit=10"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["resource"] != "flows" {
		t.Errorf("resource = %v, want 'flows'", params["resource"])
	}
	if params["limit"] != "10" {
		t.Errorf("limit = %v, want '10' (no schema = string)", params["limit"])
	}
}

func TestBuildToolParams_FlagStyleArgs(t *testing.T) {
	params, err := buildToolParams("query", []string{"--resource=flows", "--limit=10"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["resource"] != "flows" {
		t.Errorf("resource = %v, want 'flows'", params["resource"])
	}
}

func TestBuildToolParams_DotNotation(t *testing.T) {
	params, err := buildToolParams("query", []string{"--filter.method=POST", "--filter.url_pattern=/api"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	// Dot-notation must produce nested map, not flat key.
	filterVal, ok := params["filter"]
	if !ok {
		t.Fatalf("expected params[\"filter\"] to exist, got %v", params)
	}
	filter, ok := filterVal.(map[string]any)
	if !ok {
		t.Fatalf("params[\"filter\"] = %T, want map[string]any", filterVal)
	}
	if filter["method"] != "POST" {
		t.Errorf("filter[\"method\"] = %v, want 'POST'", filter["method"])
	}
	if filter["url_pattern"] != "/api" {
		t.Errorf("filter[\"url_pattern\"] = %v, want '/api'", filter["url_pattern"])
	}
	// Flat keys must not exist.
	if _, found := params["filter.method"]; found {
		t.Error("flat key 'filter.method' should not exist in params")
	}
	if _, found := params["filter.url_pattern"]; found {
		t.Error("flat key 'filter.url_pattern' should not exist in params")
	}
}

func TestBuildToolParams_DotNotation_MergesSameParent(t *testing.T) {
	// Multiple dot-notation flags with same parent key must be merged into a single nested map.
	params, err := buildToolParams("query", []string{"--filter.method=POST", "--filter.status=200", "--filter.url_pattern=/api"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	filter, ok := params["filter"].(map[string]any)
	if !ok {
		t.Fatalf("params[\"filter\"] = %T, want map[string]any", params["filter"])
	}
	if filter["method"] != "POST" {
		t.Errorf("filter[\"method\"] = %v, want 'POST'", filter["method"])
	}
	if filter["status"] != "200" {
		t.Errorf("filter[\"status\"] = %v, want '200'", filter["status"])
	}
	if filter["url_pattern"] != "/api" {
		t.Errorf("filter[\"url_pattern\"] = %v, want '/api'", filter["url_pattern"])
	}
}

func TestBuildToolParams_DotNotation_MixedWithPositionalAndFlat(t *testing.T) {
	// Positional + flat + dot-notation all together.
	schema := &toolSchema{
		properties: map[string]string{
			"resource": "string",
			"limit":    "integer",
		},
		required: map[string]bool{},
		enums:    map[string][]string{},
	}
	params, err := buildToolParams("query", []string{"flows", "--limit=5", "--filter.method=GET"}, schema, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["resource"] != "flows" {
		t.Errorf("resource = %v, want 'flows'", params["resource"])
	}
	if params["limit"] != int64(5) {
		t.Errorf("limit = %v, want int64(5)", params["limit"])
	}
	filter, ok := params["filter"].(map[string]any)
	if !ok {
		t.Fatalf("params[\"filter\"] = %T, want map[string]any", params["filter"])
	}
	if filter["method"] != "GET" {
		t.Errorf("filter[\"method\"] = %v, want 'GET'", filter["method"])
	}
}

func TestBuildToolParams_PositionalArgs_Query(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		wantR  string // resource
		wantID string // id (empty if not expected)
	}{
		{
			name:   "single positional maps to resource",
			args:   []string{"flows"},
			wantR:  "flows",
			wantID: "",
		},
		{
			name:   "two positionals map to resource and id",
			args:   []string{"flow", "abc123"},
			wantR:  "flow",
			wantID: "abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := buildToolParams("query", tt.args, nil, nil)
			if err != nil {
				t.Fatalf("buildToolParams: %v", err)
			}
			if params["resource"] != tt.wantR {
				t.Errorf("resource = %v, want %q", params["resource"], tt.wantR)
			}
			if tt.wantID != "" {
				if params["id"] != tt.wantID {
					t.Errorf("id = %v, want %q", params["id"], tt.wantID)
				}
			}
		})
	}
}

func TestBuildToolParams_PositionalArgs_Execute(t *testing.T) {
	params, err := buildToolParams("execute", []string{"resend", "--flow_id=abc"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["action"] != "resend" {
		t.Errorf("action = %v, want 'resend'", params["action"])
	}
	if params["flow_id"] != "abc" {
		t.Errorf("flow_id = %v, want 'abc'", params["flow_id"])
	}
}

func TestBuildToolParams_PositionalArgs_ExtraPositionalWarned(t *testing.T) {
	var buf bytes.Buffer
	params, err := buildToolParams("query", []string{"flows", "id1", "extra"}, nil, &buf)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	_ = params
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning for extra positional arg, got: %q", buf.String())
	}
}

func TestBuildToolParams_PositionalArgs_UnknownToolNoPositional(t *testing.T) {
	var buf bytes.Buffer
	// Unknown tool — no positional mapping; bare words should warn.
	params, err := buildToolParams("unknown_tool", []string{"bare_arg"}, nil, &buf)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	_ = params
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning for bare positional arg in unknown tool, got: %q", buf.String())
	}
}

func TestBuildToolParams_TypeInference(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{
			"resource": "string",
			"limit":    "integer",
			"enabled":  "boolean",
			"tags":     "array",
		},
		required: map[string]bool{},
		enums:    map[string][]string{},
	}

	params, err := buildToolParams("query", []string{
		"resource=flows",
		"limit=10",
		"enabled=true",
		"tags=a,b,c",
	}, schema, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}

	if params["resource"] != "flows" {
		t.Errorf("resource = %v, want 'flows'", params["resource"])
	}
	if params["limit"] != int64(10) {
		t.Errorf("limit = %v (%T), want int64(10)", params["limit"], params["limit"])
	}
	if params["enabled"] != true {
		t.Errorf("enabled = %v, want true", params["enabled"])
	}
	arr, ok := params["tags"].([]string)
	if !ok || len(arr) != 3 {
		t.Errorf("tags = %v, want [a b c]", params["tags"])
	}
}

func TestBuildToolParams_ArrayParam_CommaSeparated(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"payloads": "array"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	params, err := buildToolParams("fuzz", []string{"--payloads=a,b,c"}, schema, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	arr, ok := params["payloads"].([]string)
	if !ok {
		t.Fatalf("payloads type = %T, want []string", params["payloads"])
	}
	if len(arr) != 3 || arr[0] != "a" || arr[1] != "b" || arr[2] != "c" {
		t.Errorf("payloads = %v, want [a b c]", arr)
	}
}

func TestBuildToolParams_MissingRequired_Error(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"resource": "string"},
		required:   map[string]bool{"resource": true},
		enums:      map[string][]string{},
	}

	_, err := buildToolParams("query", []string{}, schema, nil)
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "resource") {
		t.Errorf("error %q should mention 'resource'", err.Error())
	}
}

func TestBuildToolParams_MissingRequired_WithEnum_ShowsCandidates(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"protocol": "string"},
		required:   map[string]bool{"protocol": true},
		enums:      map[string][]string{"protocol": {"http", "https", "h2"}},
	}

	_, err := buildToolParams("query", []string{}, schema, nil)
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("error should show enum candidates: %v", err)
	}
}

func TestBuildToolParams_UnknownFlag_WarnedToStderr(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{"resource": "string"},
		required:   map[string]bool{},
		enums:      map[string][]string{},
	}

	var buf bytes.Buffer
	params, err := buildToolParams("query", []string{"unknown_param=foo"}, schema, &buf)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	_ = params
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning for unknown param, got: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "unknown_param") {
		t.Errorf("warning should mention 'unknown_param', got: %q", buf.String())
	}
}

func TestBuildToolParams_BareFlag_BecomesTrue(t *testing.T) {
	params, err := buildToolParams("query", []string{"--verbose"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["verbose"] != true {
		t.Errorf("verbose = %v, want true", params["verbose"])
	}
}

func TestBuildToolParams_BareDoubleDash_Skipped(t *testing.T) {
	params, err := buildToolParams("query", []string{"--"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("expected empty params, got %v", params)
	}
}

func TestBuildToolParams_ValueWithEqualsSign(t *testing.T) {
	params, err := buildToolParams("query", []string{"url=http://example.com?a=1&b=2"}, nil, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["url"] != "http://example.com?a=1&b=2" {
		t.Errorf("url = %v, want 'http://example.com?a=1&b=2'", params["url"])
	}
}

func TestBuildToolParams_MixedPositionalAndFlags(t *testing.T) {
	schema := &toolSchema{
		properties: map[string]string{
			"resource": "string",
			"id":       "string",
			"limit":    "integer",
		},
		required: map[string]bool{},
		enums:    map[string][]string{},
	}

	params, err := buildToolParams("query", []string{"flow", "abc123", "--limit=5"}, schema, nil)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if params["resource"] != "flow" {
		t.Errorf("resource = %v, want 'flow'", params["resource"])
	}
	if params["id"] != "abc123" {
		t.Errorf("id = %v, want 'abc123'", params["id"])
	}
	if params["limit"] != int64(5) {
		t.Errorf("limit = %v, want int64(5)", params["limit"])
	}
}

func TestBuildToolParams_ProxyStartNoPositional(t *testing.T) {
	// proxy_start has no positional args; bare word should warn.
	var buf bytes.Buffer
	_, err := buildToolParams("proxy_start", []string{"myarg"}, nil, &buf)
	if err != nil {
		t.Fatalf("buildToolParams: %v", err)
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning for bare positional arg in proxy_start, got: %q", buf.String())
	}
}
