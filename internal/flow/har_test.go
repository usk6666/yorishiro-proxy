package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

// mockFlowReader is a test double for FlowReader.
type mockFlowReader struct {
	flows    []*Flow
	messages map[string][]*Message
}

func (m *mockFlowReader) GetFlow(_ context.Context, id string) (*Flow, error) {
	for _, f := range m.flows {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, nil
}

func (m *mockFlowReader) ListFlows(_ context.Context, _ ListOptions) ([]*Flow, error) {
	return m.flows, nil
}

func (m *mockFlowReader) CountFlows(_ context.Context, _ ListOptions) (int, error) {
	return len(m.flows), nil
}

func (m *mockFlowReader) GetMessages(_ context.Context, flowID string, _ MessageListOptions) ([]*Message, error) {
	return m.messages[flowID], nil
}

func (m *mockFlowReader) CountMessages(_ context.Context, flowID string) (int, error) {
	return len(m.messages[flowID]), nil
}

func TestExportHAR_BasicHTTP(t *testing.T) {
	t.Helper()
	now := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	sendMs := int64(5)
	waitMs := int64(100)
	receiveMs := int64(20)

	store := &mockFlowReader{
		flows: []*Flow{
			{
				ID:        "flow-1",
				ConnID:    "conn-1",
				Protocol:  "HTTPS",
				FlowType:  "unary",
				State:     "complete",
				Timestamp: now,
				Duration:  125 * time.Millisecond,
				SendMs:    &sendMs,
				WaitMs:    &waitMs,
				ReceiveMs: &receiveMs,
				ConnInfo: &ConnectionInfo{
					ServerAddr: "93.184.216.34:443",
				},
			},
		},
		messages: map[string][]*Message{
			"flow-1": {
				{
					ID:        "msg-1",
					FlowID:    "flow-1",
					Sequence:  0,
					Direction: "send",
					Timestamp: now,
					Method:    "GET",
					URL:       mustParseURL("https://example.com/api?key=value&foo=bar"),
					Headers: map[string][]string{
						"Host":       {"example.com"},
						"User-Agent": {"test-agent"},
					},
				},
				{
					ID:         "msg-2",
					FlowID:     "flow-1",
					Sequence:   1,
					Direction:  "receive",
					Timestamp:  now.Add(125 * time.Millisecond),
					StatusCode: 200,
					Headers: map[string][]string{
						"Content-Type": {"application/json"},
					},
					Body: []byte(`{"status":"ok"}`),
				},
			},
		},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{
		IncludeBodies: true,
	}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 1 {
		t.Fatalf("exported = %d, want 1", n)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	// Validate top-level structure.
	if har.Log.Version != "1.2" {
		t.Errorf("version = %q, want 1.2", har.Log.Version)
	}
	if har.Log.Creator.Name != "yorishiro-proxy" {
		t.Errorf("creator.name = %q, want yorishiro-proxy", har.Log.Creator.Name)
	}
	if har.Log.Creator.Version != "1.0.0" {
		t.Errorf("creator.version = %q, want 1.0.0", har.Log.Creator.Version)
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(har.Log.Entries))
	}

	entry := har.Log.Entries[0]

	// Validate request.
	if entry.Request.Method != "GET" {
		t.Errorf("request.method = %q, want GET", entry.Request.Method)
	}
	if entry.Request.URL != "https://example.com/api?key=value&foo=bar" {
		t.Errorf("request.url = %q", entry.Request.URL)
	}
	if len(entry.Request.QueryString) != 2 {
		t.Errorf("queryString count = %d, want 2", len(entry.Request.QueryString))
	}

	// Validate response.
	if entry.Response.Status != 200 {
		t.Errorf("response.status = %d, want 200", entry.Response.Status)
	}
	if entry.Response.StatusText != "OK" {
		t.Errorf("response.statusText = %q, want OK", entry.Response.StatusText)
	}
	if entry.Response.Content.Text != `{"status":"ok"}` {
		t.Errorf("response.content.text = %q", entry.Response.Content.Text)
	}
	if entry.Response.Content.MimeType != "application/json" {
		t.Errorf("response.content.mimeType = %q", entry.Response.Content.MimeType)
	}
	if entry.Response.Content.Encoding != "" {
		t.Errorf("response.content.encoding should be empty for text, got %q", entry.Response.Content.Encoding)
	}

	// Validate timings.
	if entry.Timings.Send != 5 {
		t.Errorf("timings.send = %f, want 5", entry.Timings.Send)
	}
	if entry.Timings.Wait != 100 {
		t.Errorf("timings.wait = %f, want 100", entry.Timings.Wait)
	}
	if entry.Timings.Receive != 20 {
		t.Errorf("timings.receive = %f, want 20", entry.Timings.Receive)
	}

	// Validate server IP.
	if entry.ServerIPAddress != "93.184.216.34" {
		t.Errorf("serverIPAddress = %q, want 93.184.216.34", entry.ServerIPAddress)
	}
}

func TestExportHAR_BinaryBody(t *testing.T) {
	now := time.Now().UTC()
	binaryBody := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG header

	store := &mockFlowReader{
		flows: []*Flow{
			{
				ID:        "flow-bin",
				Protocol:  "HTTPS",
				FlowType:  "unary",
				State:     "complete",
				Timestamp: now,
				Duration:  50 * time.Millisecond,
			},
		},
		messages: map[string][]*Message{
			"flow-bin": {
				{
					ID:        "msg-req",
					FlowID:    "flow-bin",
					Sequence:  0,
					Direction: "send",
					Timestamp: now,
					Method:    "GET",
					URL:       mustParseURL("https://example.com/image.png"),
				},
				{
					ID:         "msg-resp",
					FlowID:     "flow-bin",
					Sequence:   1,
					Direction:  "receive",
					Timestamp:  now.Add(50 * time.Millisecond),
					StatusCode: 200,
					Headers: map[string][]string{
						"Content-Type": {"image/png"},
					},
					Body: binaryBody,
				},
			},
		},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{
		IncludeBodies: true,
	}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 1 {
		t.Fatalf("exported = %d, want 1", n)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Response.Content.Encoding != "base64" {
		t.Errorf("encoding = %q, want base64", entry.Response.Content.Encoding)
	}
	if entry.Response.Content.Text == "" {
		t.Error("content.text should not be empty for binary body")
	}
}

func TestExportHAR_WebSocket(t *testing.T) {
	now := time.Now().UTC()

	store := &mockFlowReader{
		flows: []*Flow{
			{
				ID:        "flow-ws",
				Protocol:  "WebSocket",
				FlowType:  "bidirectional",
				State:     "complete",
				Timestamp: now,
				Duration:  5 * time.Second,
			},
		},
		messages: map[string][]*Message{
			"flow-ws": {
				// Upgrade request.
				{
					ID:        "msg-upgrade-req",
					FlowID:    "flow-ws",
					Sequence:  0,
					Direction: "send",
					Timestamp: now,
					Method:    "GET",
					URL:       mustParseURL("wss://example.com/ws"),
					Headers: map[string][]string{
						"Upgrade":    {"websocket"},
						"Connection": {"Upgrade"},
					},
				},
				// Upgrade response.
				{
					ID:         "msg-upgrade-resp",
					FlowID:     "flow-ws",
					Sequence:   1,
					Direction:  "receive",
					Timestamp:  now.Add(50 * time.Millisecond),
					StatusCode: 101,
					Headers: map[string][]string{
						"Upgrade":    {"websocket"},
						"Connection": {"Upgrade"},
					},
				},
				// WebSocket message: send.
				{
					ID:        "msg-ws-1",
					FlowID:    "flow-ws",
					Sequence:  2,
					Direction: "send",
					Timestamp: now.Add(100 * time.Millisecond),
					Body:      []byte("hello"),
					Metadata:  map[string]string{"opcode": "1"},
				},
				// WebSocket message: receive.
				{
					ID:        "msg-ws-2",
					FlowID:    "flow-ws",
					Sequence:  3,
					Direction: "receive",
					Timestamp: now.Add(200 * time.Millisecond),
					Body:      []byte("world"),
					Metadata:  map[string]string{"opcode": "1"},
				},
			},
		},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{
		IncludeBodies: true,
	}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 1 {
		t.Fatalf("exported = %d, want 1", n)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if len(entry.WebSocketMessages) != 2 {
		t.Fatalf("_webSocketMessages = %d, want 2", len(entry.WebSocketMessages))
	}

	ws0 := entry.WebSocketMessages[0]
	if ws0.Type != "send" {
		t.Errorf("ws[0].type = %q, want send", ws0.Type)
	}
	if ws0.Opcode != 1 {
		t.Errorf("ws[0].opcode = %d, want 1", ws0.Opcode)
	}
	if ws0.Data != "hello" {
		t.Errorf("ws[0].data = %q, want hello", ws0.Data)
	}

	ws1 := entry.WebSocketMessages[1]
	if ws1.Type != "receive" {
		t.Errorf("ws[1].type = %q, want receive", ws1.Type)
	}
	if ws1.Data != "world" {
		t.Errorf("ws[1].data = %q, want world", ws1.Data)
	}

	// Verify upgrade request is used as the entry request.
	if entry.Request.Method != "GET" {
		t.Errorf("request.method = %q, want GET", entry.Request.Method)
	}
	if entry.Response.Status != 101 {
		t.Errorf("response.status = %d, want 101", entry.Response.Status)
	}
}

func TestExportHAR_SkipsTCPAndGRPC(t *testing.T) {
	now := time.Now().UTC()
	store := &mockFlowReader{
		flows: []*Flow{
			{ID: "flow-tcp", Protocol: "TCP", FlowType: "stream", State: "complete", Timestamp: now, Duration: time.Second},
			{ID: "flow-grpc", Protocol: "gRPC", FlowType: "unary", State: "complete", Timestamp: now, Duration: time.Second},
			{ID: "flow-http", Protocol: "HTTP/1.x", FlowType: "unary", State: "complete", Timestamp: now, Duration: time.Second},
		},
		messages: map[string][]*Message{
			"flow-tcp":  {},
			"flow-grpc": {},
			"flow-http": {
				{ID: "msg-1", FlowID: "flow-http", Sequence: 0, Direction: "send", Timestamp: now, Method: "GET", URL: mustParseURL("http://example.com/")},
				{ID: "msg-2", FlowID: "flow-http", Sequence: 1, Direction: "receive", Timestamp: now, StatusCode: 200},
			},
		},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 1 {
		t.Errorf("exported = %d, want 1 (TCP and gRPC should be skipped)", n)
	}
}

func TestExportHAR_NilTimings(t *testing.T) {
	now := time.Now().UTC()
	store := &mockFlowReader{
		flows: []*Flow{
			{
				ID:        "flow-no-timing",
				Protocol:  "HTTPS",
				FlowType:  "unary",
				State:     "complete",
				Timestamp: now,
				Duration:  50 * time.Millisecond,
				// SendMs, WaitMs, ReceiveMs are all nil.
			},
		},
		messages: map[string][]*Message{
			"flow-no-timing": {
				{ID: "msg-1", FlowID: "flow-no-timing", Sequence: 0, Direction: "send", Timestamp: now, Method: "GET", URL: mustParseURL("https://example.com/")},
				{ID: "msg-2", FlowID: "flow-no-timing", Sequence: 1, Direction: "receive", Timestamp: now, StatusCode: 200},
			},
		},
	}

	var buf bytes.Buffer
	_, err := ExportHAR(context.Background(), store, &buf, ExportOptions{}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	timings := har.Log.Entries[0].Timings
	if timings.Send != -1 {
		t.Errorf("timings.send = %f, want -1", timings.Send)
	}
	if timings.Wait != -1 {
		t.Errorf("timings.wait = %f, want -1", timings.Wait)
	}
	if timings.Receive != -1 {
		t.Errorf("timings.receive = %f, want -1", timings.Receive)
	}
}

func TestExportHAR_TimeFilter(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	after := base.Add(30 * time.Minute)
	before := base.Add(90 * time.Minute)

	store := &mockFlowReader{
		flows: []*Flow{
			{ID: "f1", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: base, Duration: time.Millisecond},
			{ID: "f2", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: base.Add(time.Hour), Duration: time.Millisecond},
			{ID: "f3", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: base.Add(2 * time.Hour), Duration: time.Millisecond},
		},
		messages: map[string][]*Message{
			"f1": {{ID: "m1", FlowID: "f1", Sequence: 0, Direction: "send", Timestamp: base, Method: "GET", URL: mustParseURL("https://a.com/")}},
			"f2": {{ID: "m2", FlowID: "f2", Sequence: 0, Direction: "send", Timestamp: base.Add(time.Hour), Method: "GET", URL: mustParseURL("https://b.com/")}},
			"f3": {{ID: "m3", FlowID: "f3", Sequence: 0, Direction: "send", Timestamp: base.Add(2 * time.Hour), Method: "GET", URL: mustParseURL("https://c.com/")}},
		},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{
		Filter: ExportFilter{
			TimeAfter:  &after,
			TimeBefore: &before,
		},
	}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 1 {
		t.Errorf("exported = %d, want 1", n)
	}
}

func TestExportHAR_MaxFlows(t *testing.T) {
	now := time.Now().UTC()
	var flows []*Flow
	msgs := map[string][]*Message{}
	for i := 0; i < 10; i++ {
		id := "flow-" + string(rune('a'+i))
		flows = append(flows, &Flow{
			ID: id, Protocol: "HTTPS", FlowType: "unary", State: "complete",
			Timestamp: now.Add(time.Duration(i) * time.Minute), Duration: time.Millisecond,
		})
		msgs[id] = []*Message{
			{ID: "m-" + id, FlowID: id, Sequence: 0, Direction: "send", Timestamp: now, Method: "GET", URL: mustParseURL("https://example.com/")},
		}
	}

	store := &mockFlowReader{flows: flows, messages: msgs}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{MaxFlows: 3}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 3 {
		t.Errorf("exported = %d, want 3", n)
	}
}

func TestExportHAR_LargeFlowCount(t *testing.T) {
	now := time.Now().UTC()
	count := 1100
	var flows []*Flow
	msgs := map[string][]*Message{}
	for i := 0; i < count; i++ {
		id := "flow-" + time.Now().Format("20060102") + "-" + string(rune(i))
		flows = append(flows, &Flow{
			ID: id, Protocol: "HTTPS", FlowType: "unary", State: "complete",
			Timestamp: now.Add(time.Duration(i) * time.Millisecond), Duration: time.Millisecond,
		})
		msgs[id] = []*Message{
			{ID: "m-" + id, FlowID: id, Sequence: 0, Direction: "send", Timestamp: now, Method: "GET", URL: mustParseURL("https://example.com/")},
			{ID: "r-" + id, FlowID: id, Sequence: 1, Direction: "receive", Timestamp: now, StatusCode: 200, Body: []byte("ok")},
		}
	}

	store := &mockFlowReader{flows: flows, messages: msgs}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{IncludeBodies: true}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != count {
		t.Errorf("exported = %d, want %d", n, count)
	}

	// Verify it's valid JSON.
	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}
	if len(har.Log.Entries) != count {
		t.Errorf("entries = %d, want %d", len(har.Log.Entries), count)
	}
}

func TestExportHAR_ContextCancellation(t *testing.T) {
	now := time.Now().UTC()
	store := &mockFlowReader{
		flows: []*Flow{
			{ID: "f1", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: now, Duration: time.Millisecond},
		},
		messages: map[string][]*Message{
			"f1": {{ID: "m1", FlowID: "f1", Sequence: 0, Direction: "send", Timestamp: now, Method: "GET", URL: mustParseURL("https://example.com/")}},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	var buf bytes.Buffer
	_, err := ExportHAR(ctx, store, &buf, ExportOptions{}, "1.0.0")
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestExportHAR_EmptyFlows(t *testing.T) {
	store := &mockFlowReader{
		flows:    []*Flow{},
		messages: map[string][]*Message{},
	}

	var buf bytes.Buffer
	n, err := ExportHAR(context.Background(), store, &buf, ExportOptions{}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if n != 0 {
		t.Errorf("exported = %d, want 0", n)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}
	if har.Log.Entries == nil {
		t.Error("entries should not be nil (should be empty array for valid JSON)")
	}
}

func TestExportHAR_NoBodiesOption(t *testing.T) {
	now := time.Now().UTC()
	store := &mockFlowReader{
		flows: []*Flow{
			{ID: "f1", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: now, Duration: time.Millisecond},
		},
		messages: map[string][]*Message{
			"f1": {
				{ID: "m1", FlowID: "f1", Sequence: 0, Direction: "send", Timestamp: now, Method: "POST", URL: mustParseURL("https://example.com/"), Body: []byte("request body"), Headers: map[string][]string{"Content-Type": {"text/plain"}}},
				{ID: "m2", FlowID: "f1", Sequence: 1, Direction: "receive", Timestamp: now, StatusCode: 200, Body: []byte("response body"), Headers: map[string][]string{"Content-Type": {"text/plain"}}},
			},
		},
	}

	var buf bytes.Buffer
	_, err := ExportHAR(context.Background(), store, &buf, ExportOptions{IncludeBodies: false}, "1.0.0")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}

	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Request.PostData != nil {
		t.Error("postData should be nil when includeBodies is false")
	}
	if entry.Response.Content.Text != "" {
		t.Error("content.text should be empty when includeBodies is false")
	}
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		body     []byte
		want     bool
	}{
		{"text/html", "text/html", []byte("<h1>Hello</h1>"), false},
		{"application/json", "application/json", []byte(`{"key":"value"}`), false},
		{"application/xml", "application/xml", []byte("<root/>"), false},
		{"image/png", "image/png", []byte{0x89, 0x50, 0x4E, 0x47}, true},
		{"application/octet-stream binary", "application/octet-stream", []byte{0x80, 0x81, 0xFE, 0xFF}, true},
		{"text with charset", "text/html; charset=utf-8", []byte("hello"), false},
		{"custom+json", "application/vnd.api+json", []byte(`{}`), false},
		{"custom+xml", "application/atom+xml", []byte("<feed/>"), false},
		{"valid utf8 unknown type", "application/octet-stream", []byte("plain text"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isBinaryContent(tc.mimeType, tc.body)
			if got != tc.want {
				t.Errorf("isBinaryContent(%q, ...) = %v, want %v", tc.mimeType, got, tc.want)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"93.184.216.34:443", "93.184.216.34"},
		{"[::1]:8080", "::1"},
		{"localhost:80", "localhost"},
		{"", ""},
		{"no-port", "no-port"},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got := extractIP(tc.addr)
			if got != tc.want {
				t.Errorf("extractIP(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestProtocolToHTTPVersion(t *testing.T) {
	tests := []struct {
		protocol string
		want     string
	}{
		{"HTTP/1.x", "HTTP/1.1"},
		{"HTTPS", "HTTP/1.1"},
		{"HTTP/2", "h2"},
		{"WebSocket", "HTTP/1.1"},
		{"SOCKS5+HTTPS", "HTTP/1.1"},
		{"SOCKS5+HTTP", "HTTP/1.1"},
		{"unknown", "HTTP/1.1"},
	}

	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			got := protocolToHTTPVersion(tc.protocol)
			if got != tc.want {
				t.Errorf("protocolToHTTPVersion(%q) = %q, want %q", tc.protocol, got, tc.want)
			}
		})
	}
}

func TestHeadersToHAR_Sorted(t *testing.T) {
	headers := map[string][]string{
		"Zebra":   {"z-val"},
		"Alpha":   {"a-val"},
		"Content": {"c-val1", "c-val2"},
	}

	result := headersToHAR(headers)
	if len(result) != 4 {
		t.Fatalf("headersToHAR: got %d entries, want 4", len(result))
	}

	// Verify sorted order.
	if result[0].Name != "Alpha" {
		t.Errorf("result[0].name = %q, want Alpha", result[0].Name)
	}
	if result[1].Name != "Content" || result[1].Value != "c-val1" {
		t.Errorf("result[1] = %+v", result[1])
	}
	if result[2].Name != "Content" || result[2].Value != "c-val2" {
		t.Errorf("result[2] = %+v", result[2])
	}
	if result[3].Name != "Zebra" {
		t.Errorf("result[3].name = %q, want Zebra", result[3].Name)
	}
}

func TestHARSchemaValidation(t *testing.T) {
	// Validates that the HAR output matches the expected JSON structure.
	now := time.Now().UTC()
	store := &mockFlowReader{
		flows: []*Flow{
			{ID: "f1", Protocol: "HTTPS", FlowType: "unary", State: "complete", Timestamp: now, Duration: 100 * time.Millisecond},
		},
		messages: map[string][]*Message{
			"f1": {
				{ID: "m1", FlowID: "f1", Sequence: 0, Direction: "send", Timestamp: now, Method: "POST", URL: mustParseURL("https://example.com/submit"), Body: []byte("data"), Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}},
				{ID: "m2", FlowID: "f1", Sequence: 1, Direction: "receive", Timestamp: now, StatusCode: 201, Body: []byte("created"), Headers: map[string][]string{"Content-Type": {"text/plain"}}},
			},
		},
	}

	var buf bytes.Buffer
	_, err := ExportHAR(context.Background(), store, &buf, ExportOptions{IncludeBodies: true}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}

	// Verify it's valid JSON and re-marshal to check required fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	// Must have "log" key.
	if _, ok := raw["log"]; !ok {
		t.Error("missing 'log' key in HAR")
	}

	// Parse the full HAR and check required fields.
	var har HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}

	entry := har.Log.Entries[0]

	// Verify postData for POST request.
	if entry.Request.PostData == nil {
		t.Fatal("postData should not be nil for POST with body")
	}
	if entry.Request.PostData.MimeType != "application/x-www-form-urlencoded" {
		t.Errorf("postData.mimeType = %q", entry.Request.PostData.MimeType)
	}
	if entry.Request.PostData.Text != "data" {
		t.Errorf("postData.text = %q, want data", entry.Request.PostData.Text)
	}
}

// mustParseURL is defined in sqlite_test.go.
