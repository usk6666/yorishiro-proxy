package grpcweb

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// mockFlowWriter records calls to SaveFlow and AppendMessage for test verification.
type mockFlowWriter struct {
	flows     []*flow.Stream
	messages  []*flow.Flow
	updates   []mockFlowUpdate
	saveErr   error
	appendErr error
}

type mockFlowUpdate struct {
	id     string
	update flow.StreamUpdate
}

func (m *mockFlowWriter) SaveStream(_ context.Context, f *flow.Stream) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	f.ID = "test-flow-id"
	m.flows = append(m.flows, f)
	return nil
}

func (m *mockFlowWriter) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	m.updates = append(m.updates, mockFlowUpdate{id: id, update: update})
	return nil
}

func (m *mockFlowWriter) SaveFlow(_ context.Context, msg *flow.Flow) error {
	if m.appendErr != nil {
		return m.appendErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

func testURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("invalid test URL %q: %v", rawURL, err)
	}
	return u
}

func TestRecordSession_Unary(t *testing.T) {
	store := &mockFlowWriter{}
	logger := slog.Default()
	h := NewHandler(store, logger)

	// Build a single-frame request and response.
	reqPayload := []byte("request-data")
	respPayload := []byte("response-data")
	trailerData := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")

	reqBody := EncodeFrame(false, false, reqPayload)
	respBody := append(EncodeFrame(false, false, respPayload), EncodeFrame(true, false, trailerData)...)

	info := &StreamInfo{
		ConnID:     "conn-1",
		ClientAddr: "127.0.0.1:1234",
		ServerAddr: "example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web+proto"},
			{Name: "grpc-encoding", Value: "identity"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web+proto"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Method:       "POST",
		URL:          testURL(t, "https://example.com/test.Service/GetItem"),
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     100 * time.Millisecond,
	}

	err := h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Verify flow.
	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}
	fl := store.flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("Protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.State != "complete" {
		t.Errorf("State = %q, want %q", fl.State, "complete")
	}
	if fl.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", fl.Scheme, "https")
	}

	// Verify messages: 1 send + 1 receive = 2.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}

	send := store.messages[0]
	if send.Direction != "send" {
		t.Errorf("message[0].Direction = %q, want %q", send.Direction, "send")
	}
	if send.Sequence != 0 {
		t.Errorf("message[0].Sequence = %d, want 0", send.Sequence)
	}
	if string(send.Body) != "request-data" {
		t.Errorf("message[0].Body = %q, want %q", send.Body, "request-data")
	}
	if send.Method != "POST" {
		t.Errorf("message[0].Method = %q, want %q", send.Method, "POST")
	}
	if send.Metadata["service"] != "test.Service" {
		t.Errorf("message[0].Metadata[service] = %q, want %q", send.Metadata["service"], "test.Service")
	}
	if send.Metadata["method"] != "GetItem" {
		t.Errorf("message[0].Metadata[method] = %q, want %q", send.Metadata["method"], "GetItem")
	}
	if send.Metadata["grpc_encoding"] != "identity" {
		t.Errorf("message[0].Metadata[grpc_encoding] = %q, want %q", send.Metadata["grpc_encoding"], "identity")
	}
	// RawBytes should contain the original request body.
	if send.RawBytes == nil {
		t.Error("message[0].RawBytes is nil, expected original request body")
	}

	recv := store.messages[1]
	if recv.Direction != "receive" {
		t.Errorf("message[1].Direction = %q, want %q", recv.Direction, "receive")
	}
	if recv.Sequence != 1 {
		t.Errorf("message[1].Sequence = %d, want 1", recv.Sequence)
	}
	if string(recv.Body) != "response-data" {
		t.Errorf("message[1].Body = %q, want %q", recv.Body, "response-data")
	}
	if recv.StatusCode != 200 {
		t.Errorf("message[1].StatusCode = %d, want 200", recv.StatusCode)
	}
	if recv.Metadata["grpc_status"] != "0" {
		t.Errorf("message[1].Metadata[grpc_status] = %q, want %q", recv.Metadata["grpc_status"], "0")
	}
	if recv.Metadata["grpc_message"] != "OK" {
		t.Errorf("message[1].Metadata[grpc_message] = %q, want %q", recv.Metadata["grpc_message"], "OK")
	}
	// RawBytes should contain the original response body (including embedded trailer).
	if recv.RawBytes == nil {
		t.Error("message[1].RawBytes is nil, expected original response body")
	}
	// Embedded trailers should be merged into headers.
	if recv.Headers["grpc-status"] == nil {
		t.Error("message[1].Headers missing grpc-status from embedded trailers")
	}
}

func TestRecordSession_Base64(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	reqPayload := []byte("hello")
	respPayload := []byte("world")
	trailerData := []byte("grpc-status: 0\r\n")

	reqBinary := EncodeFrame(false, false, reqPayload)
	respBinary := append(EncodeFrame(false, false, respPayload), EncodeFrame(true, false, trailerData)...)

	reqBody := EncodeBase64Body(reqBinary)
	respBody := EncodeBase64Body(respBinary)

	info := &StreamInfo{
		ConnID:     "conn-2",
		ClientAddr: "127.0.0.1:5678",
		ServerAddr: "example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web-text+proto"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web-text+proto"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Method:       "POST",
		URL:          testURL(t, "https://example.com/test.Svc/Echo"),
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     50 * time.Millisecond,
	}

	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}

	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}
	if string(store.messages[0].Body) != "hello" {
		t.Errorf("send body = %q, want %q", store.messages[0].Body, "hello")
	}
	if string(store.messages[1].Body) != "world" {
		t.Errorf("receive body = %q, want %q", store.messages[1].Body, "world")
	}
}

func TestRecordSession_ServerStreaming(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	// 1 request frame, 3 response frames → "stream".
	reqBody := EncodeFrame(false, false, []byte("req"))
	respBody := EncodeFrame(false, false, []byte("r1"))
	respBody = append(respBody, EncodeFrame(false, false, []byte("r2"))...)
	respBody = append(respBody, EncodeFrame(false, false, []byte("r3"))...)
	respBody = append(respBody, EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))...)

	info := &StreamInfo{
		ConnID:     "conn-3",
		ClientAddr: "127.0.0.1:9999",
		ServerAddr: "example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Method:       "POST",
		URL:          testURL(t, "https://example.com/test.Svc/ListItems"),
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     200 * time.Millisecond,
	}

	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// 1 send + 3 receive = 4 messages.
	if len(store.messages) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(store.messages))
	}

	// Verify sequences.
	for i, msg := range store.messages {
		if msg.Sequence != i {
			t.Errorf("message[%d].Sequence = %d, want %d", i, msg.Sequence, i)
		}
	}

	// Only last receive should have grpc_status metadata.
	lastRecv := store.messages[3]
	if lastRecv.Metadata["grpc_status"] != "0" {
		t.Errorf("last receive grpc_status = %q, want %q", lastRecv.Metadata["grpc_status"], "0")
	}

	// Non-last receives should not have grpc_status.
	midRecv := store.messages[2]
	if midRecv.Metadata["grpc_status"] != "" {
		t.Errorf("mid receive grpc_status = %q, want empty", midRecv.Metadata["grpc_status"])
	}
}

func TestRecordSession_TrailersOnly(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	// No request body, no response body → trailers-only with headers fallback.
	info := &StreamInfo{
		ConnID:     "conn-4",
		ClientAddr: "127.0.0.1:1111",
		ServerAddr: "example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
			{Name: "grpc-status", Value: "12"},
			{Name: "grpc-message", Value: "UNIMPLEMENTED"},
		},
		RequestBody:  nil,
		ResponseBody: nil,
		StatusCode:   200,
		Method:       "POST",
		URL:          testURL(t, "https://example.com/test.Svc/NoOp"),
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     10 * time.Millisecond,
	}

	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// 1 send (no frames) + 1 receive (no frames) = 2 messages.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}

	recv := store.messages[1]
	if recv.Metadata["grpc_trailers_only"] != "true" {
		t.Errorf("Metadata[grpc_trailers_only] = %q, want %q", recv.Metadata["grpc_trailers_only"], "true")
	}
	if recv.Metadata["grpc_status"] != "12" {
		t.Errorf("Metadata[grpc_status] = %q, want %q", recv.Metadata["grpc_status"], "12")
	}
	if recv.Metadata["grpc_message"] != "UNIMPLEMENTED" {
		t.Errorf("Metadata[grpc_message] = %q, want %q", recv.Metadata["grpc_message"], "UNIMPLEMENTED")
	}
}

func TestRecordSession_NilStore(t *testing.T) {
	h := NewHandler(nil, slog.Default())
	info := &StreamInfo{
		URL: testURL(t, "https://example.com/test.Svc/Noop"),
	}
	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() with nil store should return nil, got %v", err)
	}
}

func TestRecordSession_SaveFlowError(t *testing.T) {
	store := &mockFlowWriter{saveErr: errTest}
	h := NewHandler(store, slog.Default())

	info := &StreamInfo{
		ConnID: "conn-err",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{},
		Method:          "POST",
		URL:             testURL(t, "https://example.com/test.Svc/Fail"),
		Scheme:          "https",
		Start:           time.Now(),
		Duration:        10 * time.Millisecond,
	}

	err := h.RecordSession(context.Background(), info)
	if err == nil {
		t.Fatal("expected error from SaveFlow, got nil")
	}
}

func TestRecordSession_InvalidPath(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	info := &StreamInfo{
		ConnID: "conn-bad-path",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{},
		Method:          "POST",
		URL:             testURL(t, "https://example.com/invalid-path"),
		Scheme:          "https",
		Start:           time.Now(),
		Duration:        10 * time.Millisecond,
	}

	// Should not error — falls back to "unknown" service/method.
	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.messages) == 0 {
		t.Fatal("expected at least one message")
	}
	if store.messages[0].Metadata["service"] != "unknown" {
		t.Errorf("service = %q, want %q", store.messages[0].Metadata["service"], "unknown")
	}
}

func TestRecordSession_BidirectionalStreaming(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	// 2 request frames, 2 response frames → "bidirectional".
	reqBody := EncodeFrame(false, false, []byte("req1"))
	reqBody = append(reqBody, EncodeFrame(false, false, []byte("req2"))...)

	respBody := EncodeFrame(false, false, []byte("resp1"))
	respBody = append(respBody, EncodeFrame(false, false, []byte("resp2"))...)
	respBody = append(respBody, EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))...)

	info := &StreamInfo{
		ConnID:     "conn-bidi",
		ClientAddr: "127.0.0.1:2222",
		ServerAddr: "example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Method:       "POST",
		URL:          testURL(t, "https://example.com/test.Chat/Stream"),
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     300 * time.Millisecond,
	}

	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// 2 send + 2 receive = 4 messages.
	if len(store.messages) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(store.messages))
	}

	// Only first send should carry HTTP metadata.
	if store.messages[0].Method != "POST" {
		t.Errorf("first send Method = %q, want POST", store.messages[0].Method)
	}
	if store.messages[1].Method != "" {
		t.Errorf("second send Method = %q, want empty", store.messages[1].Method)
	}
}

func TestRecordSession_ConnInfoFromTLS(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, slog.Default())

	info := &StreamInfo{
		ConnID:     "conn-tls",
		ClientAddr: "10.0.0.1:3333",
		ServerAddr: "secure.example.com:443",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ResponseHeaders: parser.RawHeaders{},
		Method:          "POST",
		URL:             testURL(t, "https://secure.example.com/test.Svc/Secure"),
		Scheme:          "https",
		Start:           time.Now(),
		Duration:        10 * time.Millisecond,
	}

	if err := h.RecordSession(context.Background(), info); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	fl := store.flows[0]
	if fl.ConnInfo == nil {
		t.Fatal("ConnInfo is nil")
	}
	if fl.ConnInfo.ClientAddr != "10.0.0.1:3333" {
		t.Errorf("ClientAddr = %q, want %q", fl.ConnInfo.ClientAddr, "10.0.0.1:3333")
	}
	if fl.ConnInfo.ServerAddr != "secure.example.com:443" {
		t.Errorf("ServerAddr = %q, want %q", fl.ConnInfo.ServerAddr, "secure.example.com:443")
	}
}

func TestExtractGRPCWebStatus(t *testing.T) {
	tests := []struct {
		name     string
		trailers map[string]string
		headers  parser.RawHeaders
		want     string
	}{
		{
			name:     "from embedded trailers",
			trailers: map[string]string{"grpc-status": "0"},
			headers:  nil,
			want:     "0",
		},
		{
			name:     "from response headers",
			trailers: nil,
			headers:  parser.RawHeaders{{Name: "grpc-status", Value: "14"}},
			want:     "14",
		},
		{
			name:     "trailers take precedence",
			trailers: map[string]string{"grpc-status": "0"},
			headers:  parser.RawHeaders{{Name: "grpc-status", Value: "14"}},
			want:     "0",
		},
		{
			name:     "not found",
			trailers: nil,
			headers:  nil,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGRPCWebStatus(tt.trailers, tt.headers)
			if got != tt.want {
				t.Errorf("extractGRPCWebStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFlattenRawHeaders(t *testing.T) {
	headers := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/grpc-web"},
		{Name: "X-Multi", Value: "a"},
		{Name: "X-Multi", Value: "b"},
	}

	result := flattenRawHeaders(headers)
	if result["Content-Type"] != "application/grpc-web" {
		t.Errorf("Content-Type = %v, want %q", result["Content-Type"], "application/grpc-web")
	}
	if result["X-Multi"] != "a, b" {
		t.Errorf("X-Multi = %v, want %q", result["X-Multi"], "a, b")
	}
}

func TestFlattenRawHeaders_Nil(t *testing.T) {
	result := flattenRawHeaders(nil)
	if result == nil {
		t.Error("expected non-nil empty map")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestRawHeadersToMap(t *testing.T) {
	headers := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/grpc-web"},
		{Name: "X-Dup", Value: "a"},
		{Name: "X-Dup", Value: "b"},
	}

	m := rawHeadersToMap(headers)
	if len(m["Content-Type"]) != 1 || m["Content-Type"][0] != "application/grpc-web" {
		t.Errorf("Content-Type = %v", m["Content-Type"])
	}
	if len(m["X-Dup"]) != 2 || m["X-Dup"][0] != "a" || m["X-Dup"][1] != "b" {
		t.Errorf("X-Dup = %v", m["X-Dup"])
	}
}

func TestRawHeadersToMap_Nil(t *testing.T) {
	m := rawHeadersToMap(nil)
	if m == nil {
		t.Error("expected non-nil empty map")
	}
}

func TestMergeHeaders(t *testing.T) {
	a := map[string][]string{"A": {"1"}}
	b := map[string][]string{"A": {"2"}, "B": {"3"}}

	result := mergeHeaders(a, b)
	if len(result["A"]) != 2 {
		t.Errorf("A = %v, want 2 values", result["A"])
	}
	if len(result["B"]) != 1 || result["B"][0] != "3" {
		t.Errorf("B = %v, want [3]", result["B"])
	}
}

func TestMergeHeaders_NilBoth(t *testing.T) {
	if result := mergeHeaders(nil, nil); result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

var errTest = fmt.Errorf("test error")
