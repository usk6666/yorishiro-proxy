package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// isTTYFunc is the function used to detect whether an *os.File is a TTY.
// Replaceable in tests.
var isTTYFunc = defaultIsTTY

// defaultIsTTY returns true when f is connected to an interactive terminal.
func defaultIsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	// os.ModeCharDevice is set for TTY file descriptors on Unix.
	return fi.Mode()&os.ModeCharDevice != 0
}

// resolveFormat determines the effective output format.
// Priority: explicit --format flag > YP_CLIENT_FORMAT env var > TTY detection.
// When stdout is not a TTY (piped), falls back to raw JSON regardless of env var.
func resolveFormat(flagFormat string) string {
	if flagFormat != "" {
		return flagFormat
	}
	if env := os.Getenv("YP_CLIENT_FORMAT"); env != "" {
		return env
	}
	// When stdout is not a TTY, default to raw JSON (pipe-friendly).
	if !isTTYFunc(os.Stdout) {
		return "raw"
	}
	return "json"
}

// extractTextContent returns the text from the first TextContent block in the result.
// Returns an empty string when no TextContent is found.
func extractTextContent(result *gomcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// printToolResult writes the formatted tool result to w.
// format must be one of "json", "table", or "raw".
// When quiet is true, output is suppressed on success (IsError=false).
// When raw is true, compact JSON is used regardless of format.
func printToolResult(w io.Writer, toolName string, result *gomcp.CallToolResult, format string, quiet, raw bool) error {
	// Quiet mode: suppress successful output.
	if quiet && !result.IsError {
		return nil
	}

	// Raw flag overrides format.
	if raw {
		return printResultRaw(w, result)
	}

	switch format {
	case "table":
		return printResultTable(w, toolName, result)
	case "raw":
		return printResultRaw(w, result)
	default:
		// "json" and anything else defaults to indented JSON.
		return printResultJSON(w, result)
	}
}

// printResultJSON writes result as indented JSON.
func printResultJSON(w io.Writer, result *gomcp.CallToolResult) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Fprintln(w, string(b))
	return nil
}

// printResultRaw writes result as compact (non-indented) JSON.
func printResultRaw(w io.Writer, result *gomcp.CallToolResult) error {
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Fprintln(w, string(b))
	return nil
}

// printResultTable writes a human-readable table for the given tool.
// The JSON text from the MCP response is parsed and rendered per-tool.
// Falls back to compact JSON with a stderr warning when parsing fails.
func printResultTable(w io.Writer, toolName string, result *gomcp.CallToolResult) error {
	text := extractTextContent(result)

	// If the tool returned an error, print it as-is (no table rendering needed).
	if result.IsError {
		if text != "" {
			fmt.Fprintln(w, text)
			return nil
		}
		return printResultJSON(w, result)
	}

	if text == "" {
		// No text content; fall back to indented JSON.
		return printResultJSON(w, result)
	}

	// Parse the JSON text block to determine what to render.
	var data any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse tool response as JSON; falling back to compact output\n")
		fmt.Fprintln(w, text)
		return nil
	}

	switch toolName {
	case "query":
		return printQueryTable(w, data)
	default:
		return printKeyValueTable(w, data)
	}
}

// printQueryTable selects the right renderer based on the response shape.
func printQueryTable(w io.Writer, data any) error {
	// Detect response shape to pick the right renderer:
	// - []any → flows list
	// - map with "flows" key → flows list
	// - map with "messages" key → messages list
	// - map with "proxy_state" or "listening" key → status
	// - map with "id" and "protocol" key → single flow detail
	// - everything else → key-value pairs

	switch v := data.(type) {
	case []any:
		// Array: assume flows list.
		return printFlowsTable(w, v)
	case map[string]any:
		if flows, ok := v["flows"]; ok {
			if arr, ok := flows.([]any); ok {
				return printFlowsTable(w, arr)
			}
		}
		if msgs, ok := v["messages"]; ok {
			if arr, ok := msgs.([]any); ok {
				return printMessagesTable(w, arr)
			}
		}
		// Status detection: has "proxy_state" or "listening" or "uptime" key.
		if _, hasState := v["proxy_state"]; hasState {
			return printKeyValueTable(w, data)
		}
		if _, hasListening := v["listening"]; hasListening {
			return printKeyValueTable(w, data)
		}
		// Single flow detail: has "id" and "protocol".
		if _, hasID := v["id"]; hasID {
			if _, hasProto := v["protocol"]; hasProto {
				return printFlowDetailTable(w, v)
			}
		}
		return printKeyValueTable(w, data)
	default:
		// Scalar or unexpected type: just print as JSON.
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal data: %w", err)
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
}

// printFlowsTable renders a flows list as a table with columns:
// ID, Protocol, Method, URL, Status, State.
func printFlowsTable(w io.Writer, flows []any) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROTOCOL\tMETHOD\tURL\tSTATUS\tSTATE")
	for _, item := range flows {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			strVal(m, "id"),
			strVal(m, "protocol"),
			strVal(m, "method"),
			strVal(m, "url"),
			strVal(m, "status"),
			strVal(m, "state"),
		)
	}
	return tw.Flush()
}

// printMessagesTable renders a messages list as a table.
func printMessagesTable(w io.Writer, messages []any) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DIRECTION\tCONTENT-TYPE\tSIZE")
	for _, item := range messages {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n",
			strVal(m, "direction"),
			strVal(m, "content_type"),
			strVal(m, "size"),
		)
	}
	return tw.Flush()
}

// printFlowDetailTable renders a single flow's top-level fields, request headers/body,
// and response headers/body.
func printFlowDetailTable(w io.Writer, flow map[string]any) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Top-level fields first.
	topFields := []string{"id", "protocol", "method", "url", "status", "state", "started_at", "ended_at"}
	for _, key := range topFields {
		if val, ok := flow[key]; ok && val != nil {
			fmt.Fprintf(tw, "%s\t%v\n", key, val)
		}
	}

	writeHTTPPart(tw, flow, "request")
	writeHTTPPart(tw, flow, "response")

	return tw.Flush()
}

// writeHTTPPart writes headers and body for a request or response sub-object.
func writeHTTPPart(tw io.Writer, flow map[string]any, part string) {
	sub, ok := flow[part].(map[string]any)
	if !ok {
		return
	}
	if headers, ok := sub["headers"].(map[string]any); ok && len(headers) > 0 {
		fmt.Fprintf(tw, "\n")
		fmt.Fprintf(tw, "--- %s headers ---\t\n", part)
		for k, v := range headers {
			fmt.Fprintf(tw, "  %s\t%v\n", k, v)
		}
	}
	if body, ok := sub["body"]; ok && body != nil {
		fmt.Fprintf(tw, "%s body\t%v\n", part, body)
	}
}

// printKeyValueTable renders arbitrary map data as aligned key-value pairs.
func printKeyValueTable(w io.Writer, data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		// Not a map — fall back to indented JSON.
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal data: %w", err)
		}
		fmt.Fprintln(w, string(b))
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for k, v := range m {
		// Render nested objects as compact JSON.
		var valStr string
		switch vv := v.(type) {
		case string:
			valStr = vv
		case nil:
			valStr = ""
		default:
			b, err := json.Marshal(v)
			if err != nil {
				valStr = fmt.Sprintf("%v", v)
			} else {
				valStr = string(b)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\n", k, valStr)
	}
	return tw.Flush()
}

// strVal safely extracts a string value from a map, returning "-" when missing or non-string.
func strVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return "-"
	}
	switch vv := v.(type) {
	case string:
		if vv == "" {
			return "-"
		}
		return vv
	case float64:
		return fmt.Sprintf("%.0f", vv)
	default:
		return fmt.Sprintf("%v", v)
	}
}
