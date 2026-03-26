package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- helpers ---

func makeTextResult(text string, isError bool) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{
			&gomcp.TextContent{Text: text},
		},
		IsError: isError,
	}
}

// --- resolveFormat tests ---

func TestResolveFormat_ExplicitFlag(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "table")
	// Explicit flag beats env var.
	got := resolveFormat("json")
	if got != "json" {
		t.Errorf("resolveFormat(\"json\") = %q, want \"json\"", got)
	}
}

func TestResolveFormat_ExplicitFlagTable(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "")
	got := resolveFormat("table")
	if got != "table" {
		t.Errorf("resolveFormat(\"table\") = %q, want \"table\"", got)
	}
}

func TestResolveFormat_EnvVar(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "table")
	// Swap isTTYFunc to return true so env var is not overridden by TTY detection.
	orig := isTTYFunc
	isTTYFunc = func(*os.File) bool { return true }
	t.Cleanup(func() { isTTYFunc = orig })

	got := resolveFormat("")
	if got != "table" {
		t.Errorf("resolveFormat(\"\") with env=table = %q, want \"table\"", got)
	}
}

func TestResolveFormat_NoTTY_DefaultsToRaw(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "")
	orig := isTTYFunc
	isTTYFunc = func(*os.File) bool { return false }
	t.Cleanup(func() { isTTYFunc = orig })

	got := resolveFormat("")
	if got != "raw" {
		t.Errorf("resolveFormat with no TTY = %q, want \"raw\"", got)
	}
}

func TestResolveFormat_TTY_DefaultsToJSON(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "")
	orig := isTTYFunc
	isTTYFunc = func(*os.File) bool { return true }
	t.Cleanup(func() { isTTYFunc = orig })

	got := resolveFormat("")
	if got != "json" {
		t.Errorf("resolveFormat with TTY and no env = %q, want \"json\"", got)
	}
}

// --- extractTextContent tests ---

func TestExtractTextContent_HasText(t *testing.T) {
	result := makeTextResult("hello world", false)
	got := extractTextContent(result)
	if got != "hello world" {
		t.Errorf("extractTextContent = %q, want \"hello world\"", got)
	}
}

func TestExtractTextContent_Empty(t *testing.T) {
	result := &gomcp.CallToolResult{Content: []gomcp.Content{}}
	got := extractTextContent(result)
	if got != "" {
		t.Errorf("extractTextContent empty = %q, want \"\"", got)
	}
}

// --- printToolResult tests ---

func TestPrintToolResult_JSON(t *testing.T) {
	result := makeTextResult(`{"key":"value"}`, false)
	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "json", false, false)
	if err != nil {
		t.Fatalf("printToolResult: %v", err)
	}
	// Output should be parseable as JSON.
	var out any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Errorf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	// Should be indented (contain newlines).
	if !strings.Contains(buf.String(), "\n") {
		t.Errorf("JSON output should be indented (contain newlines): %q", buf.String())
	}
}

func TestPrintToolResult_Raw(t *testing.T) {
	result := makeTextResult(`{"key":"value"}`, false)
	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "json", false, true)
	if err != nil {
		t.Fatalf("printToolResult raw: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	// Compact JSON has no indentation (no "  ").
	if strings.Contains(out, "  ") {
		t.Errorf("raw output should be compact (no indentation): %q", out)
	}
	// Should still be valid JSON.
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Errorf("raw output is not valid JSON: %v\noutput: %q", err, out)
	}
}

func TestPrintToolResult_RawFormat(t *testing.T) {
	result := makeTextResult(`{"key":"value"}`, false)
	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "raw", false, false)
	if err != nil {
		t.Fatalf("printToolResult format=raw: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if strings.Contains(out, "  ") {
		t.Errorf("raw format output should be compact: %q", out)
	}
}

func TestPrintToolResult_Quiet_SuccessSuppressed(t *testing.T) {
	result := makeTextResult(`{"key":"value"}`, false)
	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "json", true, false)
	if err != nil {
		t.Fatalf("printToolResult quiet: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("quiet mode should suppress successful output, got: %q", buf.String())
	}
}

func TestPrintToolResult_Quiet_ErrorPrinted(t *testing.T) {
	result := makeTextResult("tool error occurred", true)
	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "json", true, false)
	if err != nil {
		t.Fatalf("printToolResult quiet error: %v", err)
	}
	// Error should be printed even in quiet mode.
	if buf.Len() == 0 {
		t.Error("quiet mode should still print error results")
	}
}

func TestPrintToolResult_Table_FlowsList(t *testing.T) {
	flows := []any{
		map[string]any{
			"id":       "abc123",
			"protocol": "http",
			"method":   "GET",
			"url":      "http://example.com/",
			"status":   "200",
			"state":    "complete",
		},
	}
	b, _ := json.Marshal(flows)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table flows: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"ID", "PROTOCOL", "METHOD", "URL", "STATUS", "STATE", "abc123", "http", "GET"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintToolResult_Table_FlowsWrapped(t *testing.T) {
	// Response wrapped in {"flows": [...]} object.
	flows := map[string]any{
		"flows": []any{
			map[string]any{
				"id":       "def456",
				"protocol": "https",
				"method":   "POST",
				"url":      "https://example.com/api",
				"status":   "201",
				"state":    "complete",
			},
		},
	}
	b, _ := json.Marshal(flows)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table flows wrapped: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "def456") {
		t.Errorf("table output missing flow id 'def456':\n%s", out)
	}
}

func TestPrintToolResult_Table_Messages(t *testing.T) {
	msgs := map[string]any{
		"messages": []any{
			map[string]any{
				"direction":    "request",
				"content_type": "application/json",
				"size":         "256",
			},
		},
	}
	b, _ := json.Marshal(msgs)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table messages: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"DIRECTION", "CONTENT-TYPE", "SIZE", "request"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintToolResult_Table_FlowDetail(t *testing.T) {
	flow := map[string]any{
		"id":         "abc123",
		"protocol":   "http",
		"method":     "GET",
		"url":        "http://example.com/",
		"status":     "200",
		"state":      "complete",
		"started_at": "2026-01-01T00:00:00Z",
	}
	b, _ := json.Marshal(flow)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table flow detail: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "abc123") {
		t.Errorf("table output missing flow id:\n%s", out)
	}
}

func TestPrintToolResult_Table_Status(t *testing.T) {
	status := map[string]any{
		"proxy_state": "running",
		"uptime":      "1h30m",
	}
	b, _ := json.Marshal(status)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table status: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "proxy_state") {
		t.Errorf("table output missing proxy_state key:\n%s", out)
	}
}

func TestPrintToolResult_Table_OtherTool_KeyValue(t *testing.T) {
	data := map[string]any{
		"status":  "ok",
		"message": "proxy started",
	}
	b, _ := json.Marshal(data)
	result := makeTextResult(string(b), false)

	var buf bytes.Buffer
	err := printToolResult(&buf, "proxy_start", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table key-value: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "status") || !strings.Contains(out, "ok") {
		t.Errorf("key-value table missing expected content:\n%s", out)
	}
}

func TestPrintToolResult_Table_InvalidJSON_Fallback(t *testing.T) {
	result := makeTextResult("not valid json {{", false)

	var buf bytes.Buffer
	// Should not return an error; falls back to printing the raw text.
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table invalid JSON: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "not valid json") {
		t.Errorf("fallback output should contain original text:\n%s", out)
	}
}

func TestPrintToolResult_Table_ErrorResult_PlainText(t *testing.T) {
	result := makeTextResult("something went wrong", true)

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table error result: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "something went wrong") {
		t.Errorf("error text should appear in output:\n%s", out)
	}
}

func TestPrintToolResult_Table_EmptyContent_FallbackJSON(t *testing.T) {
	result := &gomcp.CallToolResult{Content: []gomcp.Content{}}

	var buf bytes.Buffer
	err := printToolResult(&buf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("printToolResult table empty content: %v", err)
	}
	// Should produce some output (indented JSON fallback).
	if buf.Len() == 0 {
		t.Error("expected fallback JSON output for empty content")
	}
}

// --- strVal tests ---

func TestStrVal(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{"string value", map[string]any{"k": "v"}, "k", "v"},
		{"missing key", map[string]any{}, "k", "-"},
		{"nil value", map[string]any{"k": nil}, "k", "-"},
		{"empty string", map[string]any{"k": ""}, "k", "-"},
		{"float64 value", map[string]any{"k": float64(200)}, "k", "200"},
		{"bool value", map[string]any{"k": true}, "k", "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strVal(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("strVal(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// --- printResultJSON / printResultRaw direct tests ---

func TestPrintResultJSON_Indented(t *testing.T) {
	result := makeTextResult("hello", false)
	var buf bytes.Buffer
	if err := printResultJSON(&buf, result); err != nil {
		t.Fatalf("printResultJSON: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\n") {
		t.Errorf("indented JSON should contain newlines: %q", out)
	}
}

func TestPrintResultRaw_Compact(t *testing.T) {
	result := makeTextResult("hello", false)
	var buf bytes.Buffer
	if err := printResultRaw(&buf, result); err != nil {
		t.Fatalf("printResultRaw: %v", err)
	}
	// Compact JSON — the content line should be single-line.
	out := strings.TrimSpace(buf.String())
	if strings.Contains(out, "\n") {
		t.Errorf("compact JSON should not contain newlines: %q", out)
	}
}

// --- printKeyValueTable with non-map input ---

func TestPrintKeyValueTable_NonMap(t *testing.T) {
	var buf bytes.Buffer
	err := printKeyValueTable(&buf, "scalar value")
	if err != nil {
		t.Fatalf("printKeyValueTable non-map: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "scalar value") {
		t.Errorf("output should contain scalar value: %q", out)
	}
}

// --- printFlowsTable with non-map items (defensive) ---

func TestPrintFlowsTable_NonMapItem(t *testing.T) {
	var buf bytes.Buffer
	// Mix of valid and invalid items.
	flows := []any{
		"not a map",
		map[string]any{"id": "x1", "protocol": "http", "method": "GET", "url": "/", "status": "200", "state": "complete"},
	}
	err := printFlowsTable(&buf, flows)
	if err != nil {
		t.Fatalf("printFlowsTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "x1") {
		t.Errorf("should render valid item: %q", out)
	}
}

// --- writeHTTPPart with nested map values ---

func TestWriteHTTPPart_NestedMapValues(t *testing.T) {
	flow := map[string]any{
		"request": map[string]any{
			"headers": map[string]any{
				"content-type": "application/json",
				"x-custom":     map[string]any{"nested": "value"},
			},
			"body": map[string]any{"key": "val"},
		},
	}

	var buf bytes.Buffer
	tw := &buf
	_ = tw

	// Use tabwriter via printFlowDetailTable to exercise writeHTTPPart fully.
	// Add required "id" and "protocol" keys so the flow detail path is taken.
	flow["id"] = "nest-test"
	flow["protocol"] = "http"

	b, _ := json.Marshal(flow)
	result := makeTextResult(string(b), false)

	var out bytes.Buffer
	err := printToolResult(&out, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("writeHTTPPart nested: %v", err)
	}

	outStr := out.String()
	// Top-level fields should appear.
	if !strings.Contains(outStr, "nest-test") {
		t.Errorf("output missing flow id 'nest-test':\n%s", outStr)
	}
	// Request headers section should appear.
	if !strings.Contains(outStr, "request headers") {
		t.Errorf("output missing 'request headers' section:\n%s", outStr)
	}
	// Nested map value should be rendered as compact JSON.
	if !strings.Contains(outStr, "nested") {
		t.Errorf("output missing nested map value:\n%s", outStr)
	}
	// Request body (nested map) should appear.
	if !strings.Contains(outStr, "request body") {
		t.Errorf("output missing 'request body':\n%s", outStr)
	}
}

// --- resolveFormat with YP_CLIENT_FORMAT set and non-TTY stdout ---

func TestResolveFormat_EnvVar_NonTTY_ReturnsEnvValue(t *testing.T) {
	t.Setenv("YP_CLIENT_FORMAT", "table")
	orig := isTTYFunc
	// Simulate non-TTY stdout.
	isTTYFunc = func(*os.File) bool { return false }
	t.Cleanup(func() { isTTYFunc = orig })

	got := resolveFormat("")
	// When YP_CLIENT_FORMAT is set it takes priority over TTY detection.
	if got != "table" {
		t.Errorf("resolveFormat with YP_CLIENT_FORMAT=table and non-TTY = %q, want \"table\"", got)
	}
}

// --- printResultTable stderr warning is captured via errWriter ---

func TestPrintResultTable_InvalidJSON_WritesWarningToErrWriter(t *testing.T) {
	result := makeTextResult("not valid json {{", false)

	var mainBuf, warnBuf bytes.Buffer

	// Inject custom errWriter to capture the warning.
	origErrWriter := errWriter
	errWriter = &warnBuf
	t.Cleanup(func() { errWriter = origErrWriter })

	err := printToolResult(&mainBuf, "query", result, "table", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Main output should contain the original text.
	if !strings.Contains(mainBuf.String(), "not valid json") {
		t.Errorf("main output missing original text: %q", mainBuf.String())
	}
	// Warning should have been written to errWriter.
	if !strings.Contains(warnBuf.String(), "warning") {
		t.Errorf("errWriter should contain warning message, got: %q", warnBuf.String())
	}
}
