package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// interceptHTTPPayloadProperties returns the property map of the intercept
// tool's top-level "http" payload, exactly as an MCP client receives it from
// tools/list.
func interceptHTTPPayloadProperties(t *testing.T) map[string]any {
	t.Helper()

	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var tool *gomcp.Tool
	for _, tl := range result.Tools {
		if tl.Name == "intercept" {
			tool = tl
			break
		}
	}
	if tool == nil || tool.InputSchema == nil {
		t.Fatal("intercept tool (with InputSchema) not found in tools/list")
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("marshal InputSchema: %v", err)
	}
	var schema struct {
		Properties map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal InputSchema: %v", err)
	}
	httpProps := schema.Properties["http"].Properties
	// Non-vacuity: the payload must still expose its real fields.
	if _, ok := httpProps["body"]; !ok {
		t.Fatalf("intercept http payload has no body property; schema shape changed: %s", raw)
	}
	return httpProps
}

// TestInterceptToolSchema_NoAutoContentLength: http.auto_content_length was
// accepted but read by nothing (USK-1258), so it is removed from the schema;
// the go-sdk's additionalProperties:false then rejects callers still sending it.
func TestInterceptToolSchema_NoAutoContentLength(t *testing.T) {
	props := interceptHTTPPayloadProperties(t)
	if _, ok := props["auto_content_length"]; ok {
		t.Error("intercept http payload still advertises auto_content_length")
	}
}

// TestApplyHTTPModify_KeepsLayerOpaque: the producing Layer's Opaque must
// survive an intercept modify. The HTTP/1.x Layer only re-frames a changed
// body (drop Transfer-Encoding, re-stamp Content-Length) and only patches a
// header-only change onto the held wire bytes when Opaque is present;
// without it the request goes out through the synthetic path with the held
// framing headers and the decoded body, which desyncs the upstream
// (USK-1258).
func TestApplyHTTPModify_KeepsLayerOpaque(t *testing.T) {
	type layerState struct{ id int }
	opaque := &layerState{id: 1}
	body := "changed"

	tests := []struct {
		name   string
		params *httpMessageModify
	}{
		{"nil_params", nil},
		{"body_change", &httpMessageModify{Body: &body}},
		{"header_only_change", &httpMessageModify{Headers: []headerKV{{Name: "X-A", Value: "1"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Raw:       []byte("POST / HTTP/1.1\r\n\r\n"),
				Opaque:    opaque,
				Message:   &envelope.HTTPMessage{Method: "POST", Path: "/", Body: []byte("orig")},
			}
			out, err := applyHTTPModify(env, env.Message.(*envelope.HTTPMessage), tc.params)
			if err != nil {
				t.Fatalf("applyHTTPModify: %v", err)
			}
			if out.Opaque != any(opaque) {
				t.Errorf("modified Opaque = %v, want the held envelope's Opaque %v", out.Opaque, opaque)
			}
		})
	}
}

// TestHelpInterceptResource_NoAutoContentLength: the help document must not
// describe the removed field, and must point CL/TE testing at the paths that
// actually control those headers.
func TestHelpInterceptResource_NoAutoContentLength(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://help/intercept",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("help/intercept has no contents")
	}
	text := result.Contents[0].Text
	if strings.Contains(text, "auto_content_length") {
		t.Error("help/intercept still mentions auto_content_length")
	}
	for _, want := range []string{`msg["raw"]`, "resend_raw", "fuzz_raw"} {
		if !strings.Contains(text, want) {
			t.Errorf("help/intercept does not point CL/TE testing at %s", want)
		}
	}
}
