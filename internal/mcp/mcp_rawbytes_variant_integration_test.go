//go:build e2e

package mcp

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// =============================================================================
// MCP Raw Bytes and Variant Record Query Integration Tests (USK-531)
//
// These tests verify that AI agents can access raw bytes and variant records
// via the MCP query tool — the "last mile" between storage and agent consumption.
// Raw bytes access is essential for protocol-level anomaly detection (smuggling,
// frame injection). Variant records are essential for forensic reports ("what
// was modified").
// =============================================================================

// --- Raw Bytes MCP Access Tests ---

func TestMCPQuery_RawBytes_HTTP1x(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://example.com/test")
	rawReqBytes := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n")
	rawRespBytes := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 10 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}, "X-Custom": {"value"}},
				RawBytes:  rawReqBytes,
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       []byte("hello"),
				RawBytes:   rawRespBytes,
			},
		},
	})

	// Query via MCP query tool (flow resource).
	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// Verify raw_request is returned as base64-encoded string.
	if detail.RawRequest == "" {
		t.Fatal("raw_request is empty; AI agent cannot access raw bytes via MCP")
	}
	decoded, err := base64.StdEncoding.DecodeString(detail.RawRequest)
	if err != nil {
		t.Fatalf("raw_request base64 decode: %v", err)
	}
	if string(decoded) != string(rawReqBytes) {
		t.Errorf("raw_request decoded = %q, want %q", decoded, rawReqBytes)
	}

	// Verify raw_response is returned as base64-encoded string.
	if detail.RawResponse == "" {
		t.Fatal("raw_response is empty; AI agent cannot access raw bytes via MCP")
	}
	decoded, err = base64.StdEncoding.DecodeString(detail.RawResponse)
	if err != nil {
		t.Fatalf("raw_response base64 decode: %v", err)
	}
	if string(decoded) != string(rawRespBytes) {
		t.Errorf("raw_response decoded = %q, want %q", decoded, rawRespBytes)
	}
}

func TestMCPQuery_RawBytes_HTTP2(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://api.example.com/v2/resource")
	// Simulate HTTP/2 frame raw bytes (HEADERS frame prefix + pseudo-headers).
	rawReqBytes := []byte{0x00, 0x00, 0x1a, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x82, 0x86, 0x84, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc,
		0x78, 0x0f, 0x03}
	rawRespBytes := []byte{0x00, 0x00, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x88, 0x5c, 0x01, 0x35}

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/2",
		FlowType: "unary",
		Duration: 15 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "192.168.1.10:12345",
			ServerAddr: "93.184.216.34:443",
			TLSVersion: "TLS 1.3",
			TLSALPN:    "h2",
		},
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{":method": {"GET"}, ":path": {"/v2/resource"}},
				RawBytes:  rawReqBytes,
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{":status": {"200"}, "content-type": {"application/json"}},
				Body:       []byte(`{"ok":true}`),
				RawBytes:   rawRespBytes,
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	if detail.RawRequest == "" {
		t.Fatal("raw_request is empty for HTTP/2 flow")
	}
	decoded, err := base64.StdEncoding.DecodeString(detail.RawRequest)
	if err != nil {
		t.Fatalf("raw_request base64 decode: %v", err)
	}
	if len(decoded) != len(rawReqBytes) {
		t.Errorf("raw_request length = %d, want %d", len(decoded), len(rawReqBytes))
	}
	// Verify binary content round-trips faithfully.
	for i := range rawReqBytes {
		if decoded[i] != rawReqBytes[i] {
			t.Errorf("raw_request byte[%d] = 0x%02x, want 0x%02x", i, decoded[i], rawReqBytes[i])
			break
		}
	}

	if detail.RawResponse == "" {
		t.Fatal("raw_response is empty for HTTP/2 flow")
	}
	decoded, err = base64.StdEncoding.DecodeString(detail.RawResponse)
	if err != nil {
		t.Fatalf("raw_response base64 decode: %v", err)
	}
	if len(decoded) != len(rawRespBytes) {
		t.Errorf("raw_response length = %d, want %d", len(decoded), len(rawRespBytes))
	}
}

func TestMCPQuery_RawBytes_gRPC(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://grpc.example.com/myservice.MyService/MyMethod")
	// gRPC request: length-prefixed protobuf (compressed=0, length=5, data=5 bytes).
	rawReqBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 0x66, 0x6f, 0x6f}
	rawRespBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x01, 0x62}

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "gRPC",
		FlowType: "unary",
		Duration: 8 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			TLSALPN: "h2",
		},
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       reqURL,
				Headers: map[string][]string{
					":method":      {"POST"},
					"content-type": {"application/grpc"},
				},
				RawBytes: rawReqBytes,
				Metadata: map[string]string{
					"grpc_service": "myservice.MyService",
					"grpc_method":  "MyMethod",
				},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers: map[string][]string{
					":status":      {"200"},
					"content-type": {"application/grpc"},
				},
				RawBytes: rawRespBytes,
				Metadata: map[string]string{
					"grpc_status": "0",
				},
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	if detail.RawRequest == "" {
		t.Fatal("raw_request is empty for gRPC flow")
	}
	decoded, err := base64.StdEncoding.DecodeString(detail.RawRequest)
	if err != nil {
		t.Fatalf("raw_request base64 decode: %v", err)
	}
	// Verify gRPC length-prefixed frame structure.
	if decoded[0] != 0x00 {
		t.Errorf("gRPC compressed flag = 0x%02x, want 0x00", decoded[0])
	}
	if len(decoded) != len(rawReqBytes) {
		t.Errorf("raw_request length = %d, want %d", len(decoded), len(rawReqBytes))
	}

	if detail.RawResponse == "" {
		t.Fatal("raw_response is empty for gRPC flow")
	}
}

func TestMCPQuery_RawBytes_RawTCP(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Raw TCP has no L7 structured view — raw bytes are the primary data.
	// Use invalid UTF-8 sequences (0xfe, 0xff) to ensure base64 encoding is triggered.
	rawSendBytes := []byte{0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0xfe, 0xff, 0x01, 0x02, 0x03, 0x70, 0x61, 0x79}
	rawRecvBytes := []byte{0x52, 0x45, 0x53, 0x50, 0xfe, 0xff, 0x00, 0x04, 0x72, 0x65, 0x73, 0x70}

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "TCP",
		FlowType: "bidirectional",
		Duration: 20 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				RawBytes:  rawSendBytes,
			},
			{
				Sequence:  1,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				RawBytes:  rawRecvBytes,
			},
		},
	})

	// For TCP bidirectional flows, query messages resource to verify raw bytes.
	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// TCP flows use message_preview for bidirectional flows.
	if detail.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want bidirectional", detail.FlowType)
	}

	// Query individual messages to verify raw bytes are accessible.
	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})

	if msgResult.Count < 2 {
		t.Fatalf("messages count = %d, want >= 2", msgResult.Count)
	}

	// For Raw TCP, body falls back to RawBytes in convertMessagesToEntries.
	sendMsg := msgResult.Messages[0]
	if sendMsg.Direction != "send" {
		t.Errorf("first message direction = %q, want send", sendMsg.Direction)
	}
	if sendMsg.Body == "" {
		t.Fatal("send message body is empty; raw bytes not accessible via messages resource")
	}
	// Body should be base64-encoded since raw TCP data contains non-UTF8 bytes.
	if sendMsg.BodyEncoding != "base64" {
		t.Errorf("send body_encoding = %q, want base64", sendMsg.BodyEncoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(sendMsg.Body)
	if err != nil {
		t.Fatalf("send body base64 decode: %v", err)
	}
	if len(decoded) != len(rawSendBytes) {
		t.Errorf("send body decoded length = %d, want %d", len(decoded), len(rawSendBytes))
	} else {
		for i := range rawSendBytes {
			if decoded[i] != rawSendBytes[i] {
				t.Errorf("send body byte[%d] = 0x%02x, want 0x%02x", i, decoded[i], rawSendBytes[i])
				break
			}
		}
	}

	recvMsg := msgResult.Messages[1]
	if recvMsg.Direction != "receive" {
		t.Errorf("second message direction = %q, want receive", recvMsg.Direction)
	}
	if recvMsg.Body == "" {
		t.Fatal("receive message body is empty; raw bytes not accessible via messages resource")
	}
}

func TestMCPQuery_RawBytes_WireFormatIntegrity(t *testing.T) {
	// Verify that raw bytes content matches the expected wire format,
	// not just that it's non-empty. This is critical for smuggling analysis.
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://target.example.com/path")
	// Intentionally craft a request with unusual whitespace and header casing
	// that would be normalized by standard HTTP libraries.
	rawReq := "GET /path HTTP/1.1\r\n" +
		"host: target.example.com\r\n" +
		"X-CUSTOM:  value-with-leading-space\r\n" +
		"transfer-encoding: chunked\r\n" +
		"Transfer-Encoding: identity\r\n" +
		"\r\n"
	rawReqBytes := []byte(rawReq)

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 5 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers: map[string][]string{
					"host":              {"target.example.com"},
					"X-CUSTOM":          {"value-with-leading-space"},
					"transfer-encoding": {"chunked"},
					"Transfer-Encoding": {"identity"},
				},
				RawBytes: rawReqBytes,
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Body:       []byte("ok"),
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	if detail.RawRequest == "" {
		t.Fatal("raw_request is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(detail.RawRequest)
	if err != nil {
		t.Fatalf("raw_request base64 decode: %v", err)
	}

	decodedStr := string(decoded)

	// Verify wire-level details are preserved (not normalized).
	tests := []struct {
		name    string
		contain string
	}{
		{"lowercase host header", "host: target.example.com"},
		{"uppercase custom header", "X-CUSTOM:"},
		{"leading whitespace in value", "X-CUSTOM:  value-with-leading-space"},
		{"duplicate transfer-encoding (chunked)", "transfer-encoding: chunked"},
		{"duplicate Transfer-Encoding (identity)", "Transfer-Encoding: identity"},
		{"request line", "GET /path HTTP/1.1"},
	}

	for _, tt := range tests {
		if !containsStr(decodedStr, tt.contain) {
			t.Errorf("raw bytes missing %s (%q), got:\n%s", tt.name, tt.contain, decodedStr)
		}
	}
}

// --- Variant Record MCP Access Tests ---

func TestMCPQuery_Variant_RequestModification(t *testing.T) {
	// Verify that when intercept/transform modifies a request, both original
	// and modified variants are returned via MCP query tool.
	env := setupIntegrationEnv(t)

	originalURL, _ := url.Parse("http://example.com/original-path")
	modifiedURL, _ := url.Parse("http://example.com/modified-path")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 12 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       originalURL,
				Headers:   map[string][]string{"Host": {"example.com"}, "X-Original": {"true"}},
				Body:      []byte("original-body"),
				RawBytes:  []byte("GET /original-path HTTP/1.1\r\nHost: example.com\r\nX-Original: true\r\n\r\noriginal-body"),
				Metadata:  map[string]string{"variant": "original"},
			},
			{
				Sequence:  1,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       modifiedURL,
				Headers:   map[string][]string{"Host": {"example.com"}, "X-Injected": {"payload"}},
				Body:      []byte("modified-body"),
				Metadata:  map[string]string{"variant": "modified"},
			},
			{
				Sequence:   2,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       []byte("response-ok"),
			},
		},
	})

	// Query flow detail via MCP.
	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// The effective (displayed) request should be the modified variant.
	if detail.Method != "POST" {
		t.Errorf("effective method = %q, want POST (modified variant)", detail.Method)
	}
	if detail.URL != "http://example.com/modified-path" {
		t.Errorf("effective URL = %q, want modified path", detail.URL)
	}
	if detail.RequestBody != "modified-body" {
		t.Errorf("effective request_body = %q, want modified-body", detail.RequestBody)
	}

	// The original_request field should contain the pre-modification data.
	if detail.OriginalRequest == nil {
		t.Fatal("original_request is nil; AI agent cannot distinguish original from modified")
	}
	if detail.OriginalRequest.Method != "GET" {
		t.Errorf("original_request.method = %q, want GET", detail.OriginalRequest.Method)
	}
	if detail.OriginalRequest.URL != "http://example.com/original-path" {
		t.Errorf("original_request.url = %q, want original path", detail.OriginalRequest.URL)
	}
	if detail.OriginalRequest.Body != "original-body" {
		t.Errorf("original_request.body = %q, want original-body", detail.OriginalRequest.Body)
	}

	// Verify raw bytes are on the original (raw_request comes from the effective/modified message).
	// The modified message has no RawBytes, so raw_request should be empty.
	// The original's raw bytes are preserved in original_request for forensic analysis.
	if detail.MessageCount != 3 {
		t.Errorf("message_count = %d, want 3 (original + modified + response)", detail.MessageCount)
	}
}

func TestMCPQuery_Variant_ResponseModification(t *testing.T) {
	// Verify that when intercept modifies a response, both original and
	// modified response variants are returned via MCP query.
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://example.com/api/data")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 10 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
				Body:       []byte(`{"secret":"redacted"}`),
				Metadata:   map[string]string{"variant": "original"},
			},
			{
				Sequence:   2,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"application/json"}, "X-Modified": {"true"}},
				Body:       []byte(`{"secret":"exposed","injected":true}`),
				Metadata:   map[string]string{"variant": "modified"},
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// The effective response should be the modified variant.
	if detail.ResponseStatusCode != 200 {
		t.Errorf("effective response status = %d, want 200", detail.ResponseStatusCode)
	}
	if detail.ResponseBody != `{"secret":"exposed","injected":true}` {
		t.Errorf("effective response_body = %q, want modified body", detail.ResponseBody)
	}

	// The original_response field should contain the pre-modification data.
	if detail.OriginalResponse == nil {
		t.Fatal("original_response is nil; AI agent cannot access pre-modification response")
	}
	if detail.OriginalResponse.StatusCode != 200 {
		t.Errorf("original_response.status_code = %d, want 200", detail.OriginalResponse.StatusCode)
	}
	if detail.OriginalResponse.Body != `{"secret":"redacted"}` {
		t.Errorf("original_response.body = %q, want original body", detail.OriginalResponse.Body)
	}
}

func TestMCPQuery_Variant_MessagesResourceDistinguishable(t *testing.T) {
	// Verify that querying the messages resource returns variant metadata
	// so AI agents can distinguish original from modified messages.
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://example.com/intercept-target")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 8 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}},
				Body:      []byte("original-request"),
				RawBytes:  []byte("GET /intercept-target HTTP/1.1\r\nHost: example.com\r\n\r\noriginal-request"),
				Metadata:  map[string]string{"variant": "original"},
			},
			{
				Sequence:  1,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}, "X-Attack": {"payload"}},
				Body:      []byte("modified-request"),
				Metadata:  map[string]string{"variant": "modified"},
			},
			{
				Sequence:   2,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       []byte("response"),
			},
		},
	})

	// Query messages resource.
	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})

	if msgResult.Count != 3 {
		t.Fatalf("messages count = %d, want 3", msgResult.Count)
	}

	// Find original and modified send messages.
	var originalSend, modifiedSend *queryMessageEntry
	for i := range msgResult.Messages {
		msg := &msgResult.Messages[i]
		if msg.Direction != "send" {
			continue
		}
		if msg.Metadata != nil && msg.Metadata["variant"] == "original" {
			originalSend = msg
		}
		if msg.Metadata != nil && msg.Metadata["variant"] == "modified" {
			modifiedSend = msg
		}
	}

	if originalSend == nil {
		t.Fatal("original send message not found in messages resource")
	}
	if modifiedSend == nil {
		t.Fatal("modified send message not found in messages resource")
	}

	// Verify original has lower sequence than modified.
	if originalSend.Sequence >= modifiedSend.Sequence {
		t.Errorf("original sequence (%d) should be < modified sequence (%d)",
			originalSend.Sequence, modifiedSend.Sequence)
	}

	// Verify variant metadata is distinguishable.
	if originalSend.Metadata["variant"] != "original" {
		t.Errorf("original send variant = %q, want original", originalSend.Metadata["variant"])
	}
	if modifiedSend.Metadata["variant"] != "modified" {
		t.Errorf("modified send variant = %q, want modified", modifiedSend.Metadata["variant"])
	}

	// Verify the original send message's body content differs from modified.
	if originalSend.Body == modifiedSend.Body {
		t.Error("original and modified send messages have identical bodies; variant distinction fails")
	}
}

func TestMCPQuery_Variant_NoModification_NoOriginalFields(t *testing.T) {
	// When no modification occurs, original_request and original_response
	// should be nil/absent.
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://example.com/normal")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 5 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}},
				RawBytes:  []byte("GET /normal HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Body:       []byte("ok"),
				RawBytes:   []byte("HTTP/1.1 200 OK\r\n\r\nok"),
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	if detail.OriginalRequest != nil {
		t.Error("original_request should be nil when no modification occurred")
	}
	if detail.OriginalResponse != nil {
		t.Error("original_response should be nil when no modification occurred")
	}

	// Raw bytes should still be accessible even without modification.
	if detail.RawRequest == "" {
		t.Error("raw_request should be present even without modification")
	}
	if detail.RawResponse == "" {
		t.Error("raw_response should be present even without modification")
	}
}

func TestMCPQuery_Variant_RawInterceptMode(t *testing.T) {
	// Verify that raw intercept mode (byte-level modification) variant records
	// are accessible via MCP. In raw mode, the modified message may have different
	// raw bytes but variant metadata should still be present.
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://example.com/raw-intercept")
	originalRawBytes := []byte("GET /raw-intercept HTTP/1.1\r\nHost: example.com\r\n\r\n")

	flowID := seedMultiProtoSession(t, env.store, multiProtoSessionOpts{
		Protocol: "HTTP/1.x",
		FlowType: "unary",
		Duration: 10 * time.Millisecond,
		Messages: []*flow.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}},
				RawBytes:  originalRawBytes,
				Metadata:  map[string]string{"variant": "original"},
			},
			{
				Sequence:  1,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Host": {"example.com"}, "X-Injected": {"raw-payload"}},
				RawBytes:  []byte("GET /raw-intercept HTTP/1.1\r\nHost: example.com\r\nX-Injected: raw-payload\r\n\r\n"),
				Metadata:  map[string]string{"variant": "modified"},
			},
			{
				Sequence:   2,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Body:       []byte("ok"),
			},
		},
	})

	detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// The effective raw_request should come from the modified variant.
	if detail.RawRequest == "" {
		t.Fatal("raw_request is empty for raw intercept mode")
	}
	decoded, err := base64.StdEncoding.DecodeString(detail.RawRequest)
	if err != nil {
		t.Fatalf("raw_request base64 decode: %v", err)
	}
	if !containsStr(string(decoded), "X-Injected: raw-payload") {
		t.Error("raw_request should contain modified raw bytes with injected header")
	}

	// The original_request should still be present for forensic comparison.
	if detail.OriginalRequest == nil {
		t.Fatal("original_request is nil for raw intercept mode")
	}

	// Verify messages resource also exposes both variants.
	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})

	variantCount := 0
	for _, msg := range msgResult.Messages {
		if msg.Metadata != nil && (msg.Metadata["variant"] == "original" || msg.Metadata["variant"] == "modified") {
			variantCount++
		}
	}
	if variantCount != 2 {
		t.Errorf("variant message count = %d, want 2 (original + modified)", variantCount)
	}
}

