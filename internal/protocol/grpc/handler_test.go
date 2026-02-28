package grpc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// --- test helpers ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mockStore is a thread-safe minimal in-memory session store for testing.
type mockStore struct {
	sessions []*session.Session
	messages []*session.Message
}

func (m *mockStore) SaveSession(_ context.Context, s *session.Session) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	m.sessions = append(m.sessions, s)
	return nil
}

func (m *mockStore) UpdateSession(_ context.Context, id string, update session.SessionUpdate) error {
	for _, s := range m.sessions {
		if s.ID == id {
			if update.State != "" {
				s.State = update.State
			}
			if update.Duration != 0 {
				s.Duration = update.Duration
			}
			if update.Tags != nil {
				s.Tags = update.Tags
			}
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) GetSession(_ context.Context, id string) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockStore) ListSessions(_ context.Context, _ session.ListOptions) ([]*session.Session, error) {
	return m.sessions, nil
}

func (m *mockStore) CountSessions(_ context.Context, _ session.ListOptions) (int, error) {
	return len(m.sessions), nil
}

func (m *mockStore) DeleteSession(_ context.Context, _ string) error { return nil }
func (m *mockStore) DeleteAllSessions(_ context.Context) (int64, error) {
	return 0, nil
}
func (m *mockStore) DeleteSessionsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (m *mockStore) DeleteSessionsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *mockStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) {
	return 0, nil
}

func (m *mockStore) AppendMessage(_ context.Context, msg *session.Message) error {
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetMessages(_ context.Context, sessionID string, opts session.MessageListOptions) ([]*session.Message, error) {
	var result []*session.Message
	for _, msg := range m.messages {
		if msg.SessionID == sessionID {
			if opts.Direction != "" && msg.Direction != opts.Direction {
				continue
			}
			result = append(result, msg)
		}
	}
	return result, nil
}

func (m *mockStore) CountMessages(_ context.Context, sessionID string) (int, error) {
	count := 0
	for _, msg := range m.messages {
		if msg.SessionID == sessionID {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) GetMacro(_ context.Context, _ string) (*session.MacroRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListMacros(_ context.Context) ([]*session.MacroRecord, error) { return nil, nil }
func (m *mockStore) DeleteMacro(_ context.Context, _ string) error                { return nil }

// messagesForSession returns messages for a given session ID.
func (m *mockStore) messagesForSession(sessionID string) []*session.Message {
	var result []*session.Message
	for _, msg := range m.messages {
		if msg.SessionID == sessionID {
			result = append(result, msg)
		}
	}
	return result
}

// --- IsGRPC tests ---

func TestIsGRPC(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/grpc",
			contentType: "application/grpc",
			want:        true,
		},
		{
			name:        "application/grpc+proto",
			contentType: "application/grpc+proto",
			want:        true,
		},
		{
			name:        "application/grpc+json",
			contentType: "application/grpc+json",
			want:        true,
		},
		{
			name:        "with parameters",
			contentType: "application/grpc; charset=utf-8",
			want:        true,
		},
		{
			name:        "with leading whitespace",
			contentType: "  application/grpc",
			want:        true,
		},
		{
			name:        "application/json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "text/plain",
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "empty string",
			contentType: "",
			want:        false,
		},
		{
			name:        "application/grpc-web (not gRPC over HTTP/2)",
			contentType: "application/grpc-web",
			want:        false,
		},
		{
			name:        "application/grpc-web+proto",
			contentType: "application/grpc-web+proto",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGRPC(tt.contentType)
			if got != tt.want {
				t.Errorf("IsGRPC(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

// --- ParseServiceMethod tests ---

func TestParseServiceMethod(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantService string
		wantMethod  string
		wantErr     bool
	}{
		{
			name:        "simple service and method",
			path:        "/UserService/GetUser",
			wantService: "UserService",
			wantMethod:  "GetUser",
		},
		{
			name:        "package-qualified service",
			path:        "/com.example.UserService/ListUsers",
			wantService: "com.example.UserService",
			wantMethod:  "ListUsers",
		},
		{
			name:        "nested package",
			path:        "/grpc.health.v1.Health/Check",
			wantService: "grpc.health.v1.Health",
			wantMethod:  "Check",
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "root only",
			path:    "/",
			wantErr: true,
		},
		{
			name:    "no method",
			path:    "/Service/",
			wantErr: true,
		},
		{
			name:    "no service (leading slash only)",
			path:    "//Method",
			wantErr: true,
		},
		{
			name:    "no slash separator",
			path:    "/ServiceMethod",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, method, err := ParseServiceMethod(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseServiceMethod(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if service != tt.wantService {
					t.Errorf("service = %q, want %q", service, tt.wantService)
				}
				if method != tt.wantMethod {
					t.Errorf("method = %q, want %q", method, tt.wantMethod)
				}
			}
		})
	}
}

// --- classifySessionType tests ---

func TestClassifySessionType(t *testing.T) {
	tests := []struct {
		name       string
		reqFrames  int
		respFrames int
		want       string
	}{
		{name: "unary (1 req, 1 resp)", reqFrames: 1, respFrames: 1, want: "unary"},
		{name: "unary (0 req, 0 resp)", reqFrames: 0, respFrames: 0, want: "unary"},
		{name: "unary (0 req, 1 resp)", reqFrames: 0, respFrames: 1, want: "unary"},
		{name: "unary (1 req, 0 resp)", reqFrames: 1, respFrames: 0, want: "unary"},
		{name: "server streaming", reqFrames: 1, respFrames: 3, want: "stream"},
		{name: "client streaming", reqFrames: 3, respFrames: 1, want: "stream"},
		{name: "bidirectional", reqFrames: 3, respFrames: 3, want: "bidirectional"},
		{name: "bidirectional (many)", reqFrames: 10, respFrames: 5, want: "bidirectional"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySessionType(tt.reqFrames, tt.respFrames)
			if got != tt.want {
				t.Errorf("classifySessionType(%d, %d) = %q, want %q", tt.reqFrames, tt.respFrames, got, tt.want)
			}
		})
	}
}

// --- RecordSession tests ---

func TestRecordSession_UnaryRPC(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	reqPayload := []byte{0x0A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F} // protobuf bytes
	respPayload := []byte{0x0A, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73}

	reqBody := EncodeFrame(false, reqPayload)
	respBody := EncodeFrame(false, respPayload)

	info := &StreamInfo{
		ConnID:     "test-conn-1",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/com.example.UserService/GetUser",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
			"Grpc-Timeout": {"5S"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status":  {"0"},
			"grpc-message": {""},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     50 * time.Millisecond,
		TLSVersion:   "TLS 1.3",
		TLSCipher:    "TLS_AES_128_GCM_SHA256",
		TLSALPN:      "h2",
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Verify session.
	if len(store.sessions) != 1 {
		t.Fatalf("sessions count = %d, want 1", len(store.sessions))
	}
	sess := store.sessions[0]
	if sess.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", sess.Protocol, "gRPC")
	}
	if sess.SessionType != "unary" {
		t.Errorf("session_type = %q, want %q", sess.SessionType, "unary")
	}
	if sess.State != "complete" {
		t.Errorf("state = %q, want %q", sess.State, "complete")
	}
	if sess.ConnID != "test-conn-1" {
		t.Errorf("conn_id = %q, want %q", sess.ConnID, "test-conn-1")
	}
	if sess.ConnInfo == nil {
		t.Fatal("conn_info is nil")
	}
	if sess.ConnInfo.ClientAddr != "127.0.0.1:12345" {
		t.Errorf("client_addr = %q, want %q", sess.ConnInfo.ClientAddr, "127.0.0.1:12345")
	}
	if sess.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("tls_version = %q, want %q", sess.ConnInfo.TLSVersion, "TLS 1.3")
	}

	// Verify messages.
	msgs := store.messagesForSession(sess.ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}

	// Send message (seq=0).
	send := msgs[0]
	if send.Direction != "send" {
		t.Errorf("send direction = %q, want %q", send.Direction, "send")
	}
	if send.Sequence != 0 {
		t.Errorf("send sequence = %d, want 0", send.Sequence)
	}
	if send.Method != "POST" {
		t.Errorf("send method = %q, want %q", send.Method, "POST")
	}
	if send.URL.Path != "/com.example.UserService/GetUser" {
		t.Errorf("send URL path = %q, want %q", send.URL.Path, "/com.example.UserService/GetUser")
	}
	if send.Metadata["service"] != "com.example.UserService" {
		t.Errorf("send metadata service = %q, want %q", send.Metadata["service"], "com.example.UserService")
	}
	if send.Metadata["method"] != "GetUser" {
		t.Errorf("send metadata method = %q, want %q", send.Metadata["method"], "GetUser")
	}
	if len(send.Body) != len(reqPayload) {
		t.Errorf("send body length = %d, want %d", len(send.Body), len(reqPayload))
	}

	// Receive message (seq=1).
	recv := msgs[1]
	if recv.Direction != "receive" {
		t.Errorf("receive direction = %q, want %q", recv.Direction, "receive")
	}
	if recv.Sequence != 1 {
		t.Errorf("receive sequence = %d, want 1", recv.Sequence)
	}
	if recv.Metadata["grpc_status"] != "0" {
		t.Errorf("receive metadata grpc_status = %q, want %q", recv.Metadata["grpc_status"], "0")
	}
	if recv.StatusCode != 200 {
		t.Errorf("receive status_code = %d, want 200", recv.StatusCode)
	}
	if len(recv.Body) != len(respPayload) {
		t.Errorf("receive body length = %d, want %d", len(recv.Body), len(respPayload))
	}
}

func TestRecordSession_ServerStreaming(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	reqPayload := []byte{0x01, 0x02}
	respPayload1 := []byte{0x10, 0x11}
	respPayload2 := []byte{0x20, 0x21}
	respPayload3 := []byte{0x30, 0x31}

	reqBody := EncodeFrame(false, reqPayload)
	var respBody []byte
	respBody = append(respBody, EncodeFrame(false, respPayload1)...)
	respBody = append(respBody, EncodeFrame(false, respPayload2)...)
	respBody = append(respBody, EncodeFrame(false, respPayload3)...)

	info := &StreamInfo{
		ConnID:     "test-conn-stream",
		ClientAddr: "127.0.0.1:11111",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/com.example.UserService/ListUsers",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     100 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.sessions) != 1 {
		t.Fatalf("sessions count = %d, want 1", len(store.sessions))
	}
	sess := store.sessions[0]
	if sess.SessionType != "stream" {
		t.Errorf("session_type = %q, want %q", sess.SessionType, "stream")
	}

	// 1 send + 3 receive = 4 messages.
	msgs := store.messagesForSession(sess.ID)
	if len(msgs) != 4 {
		t.Fatalf("messages count = %d, want 4", len(msgs))
	}

	// Verify send message.
	if msgs[0].Direction != "send" || msgs[0].Sequence != 0 {
		t.Errorf("msg[0]: direction=%q seq=%d, want send/0", msgs[0].Direction, msgs[0].Sequence)
	}
	if msgs[0].Metadata["service"] != "com.example.UserService" {
		t.Errorf("msg[0] metadata service = %q", msgs[0].Metadata["service"])
	}

	// Verify receive messages.
	for i := 1; i <= 3; i++ {
		if msgs[i].Direction != "receive" || msgs[i].Sequence != i {
			t.Errorf("msg[%d]: direction=%q seq=%d, want receive/%d", i, msgs[i].Direction, msgs[i].Sequence, i)
		}
	}

	// Last receive should have grpc_status in metadata.
	lastMsg := msgs[3]
	if lastMsg.Metadata["grpc_status"] != "0" {
		t.Errorf("last msg grpc_status = %q, want %q", lastMsg.Metadata["grpc_status"], "0")
	}

	// Middle receive messages should not have grpc_status.
	for i := 1; i < 3; i++ {
		if msgs[i].Metadata["grpc_status"] != "" {
			t.Errorf("msg[%d] should not have grpc_status, got %q", i, msgs[i].Metadata["grpc_status"])
		}
	}
}

func TestRecordSession_BidirectionalStreaming(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	// Multiple request frames.
	var reqBody []byte
	reqBody = append(reqBody, EncodeFrame(false, []byte{0x01})...)
	reqBody = append(reqBody, EncodeFrame(false, []byte{0x02})...)
	reqBody = append(reqBody, EncodeFrame(false, []byte{0x03})...)

	// Multiple response frames.
	var respBody []byte
	respBody = append(respBody, EncodeFrame(false, []byte{0x11})...)
	respBody = append(respBody, EncodeFrame(false, []byte{0x12})...)

	info := &StreamInfo{
		ConnID:     "test-conn-bidi",
		ClientAddr: "127.0.0.1:22222",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/chat.ChatService/BidiChat",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     200 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	sess := store.sessions[0]
	if sess.SessionType != "bidirectional" {
		t.Errorf("session_type = %q, want %q", sess.SessionType, "bidirectional")
	}

	// 3 send + 2 receive = 5 messages.
	msgs := store.messagesForSession(sess.ID)
	if len(msgs) != 5 {
		t.Fatalf("messages count = %d, want 5", len(msgs))
	}

	// Verify directions and sequences.
	for i := 0; i < 3; i++ {
		if msgs[i].Direction != "send" || msgs[i].Sequence != i {
			t.Errorf("msg[%d]: direction=%q seq=%d, want send/%d", i, msgs[i].Direction, msgs[i].Sequence, i)
		}
	}
	for i := 3; i < 5; i++ {
		if msgs[i].Direction != "receive" || msgs[i].Sequence != i {
			t.Errorf("msg[%d]: direction=%q seq=%d, want receive/%d", i, msgs[i].Direction, msgs[i].Sequence, i)
		}
	}
}

func TestRecordSession_NilStore(t *testing.T) {
	handler := NewHandler(nil, testLogger())
	ctx := context.Background()

	info := &StreamInfo{
		Method: "POST",
		URL: &url.URL{
			Path: "/pkg.Service/Method",
		},
		Start: time.Now(),
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() with nil store should not error, got: %v", err)
	}
}

func TestRecordSession_ErrorResponse(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	// gRPC error with no response body (Trailers-Only).
	info := &StreamInfo{
		ConnID:     "test-conn-err",
		ClientAddr: "127.0.0.1:33333",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/com.example.UserService/GetUser",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
			"grpc-status":  {"5"},
			"grpc-message": {"user not found"},
		},
		RequestBody:  EncodeFrame(false, []byte{0x0A, 0x01, 0x42}),
		ResponseBody: nil,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     10 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	sess := store.sessions[0]
	if sess.SessionType != "unary" {
		t.Errorf("session_type = %q, want %q", sess.SessionType, "unary")
	}

	msgs := store.messagesForSession(sess.ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}

	recv := msgs[1]
	if recv.Metadata["grpc_status"] != "5" {
		t.Errorf("grpc_status = %q, want %q", recv.Metadata["grpc_status"], "5")
	}
	if recv.Metadata["grpc_message"] != "user not found" {
		t.Errorf("grpc_message = %q, want %q", recv.Metadata["grpc_message"], "user not found")
	}
}

func TestRecordSession_InvalidPath(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	info := &StreamInfo{
		ConnID:     "test-conn-badpath",
		ClientAddr: "127.0.0.1:44444",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/invalid-path",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  EncodeFrame(false, []byte{0x01}),
		ResponseBody: EncodeFrame(false, []byte{0x02}),
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     5 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Should still record with "unknown" service/method.
	msgs := store.messagesForSession(store.sessions[0].ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}
	if msgs[0].Metadata["service"] != "unknown" {
		t.Errorf("service = %q, want %q", msgs[0].Metadata["service"], "unknown")
	}
	if msgs[0].Metadata["method"] != "unknown" {
		t.Errorf("method = %q, want %q", msgs[0].Metadata["method"], "unknown")
	}
}

func TestRecordSession_CompressedFrames(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	reqBody := EncodeFrame(true, []byte{0x1F, 0x8B, 0x08}) // compressed
	respBody := EncodeFrame(true, []byte{0x1F, 0x8B, 0x09})

	info := &StreamInfo{
		ConnID:     "test-conn-compressed",
		ClientAddr: "127.0.0.1:55555",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type":  {"application/grpc"},
			"grpc-encoding": {"gzip"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     15 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	msgs := store.messagesForSession(store.sessions[0].ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}

	// Check compressed metadata.
	if msgs[0].Metadata["compressed"] != "true" {
		t.Errorf("send compressed = %q, want %q", msgs[0].Metadata["compressed"], "true")
	}
	if msgs[0].Metadata["grpc_encoding"] != "gzip" {
		t.Errorf("send grpc_encoding = %q, want %q", msgs[0].Metadata["grpc_encoding"], "gzip")
	}
	if msgs[1].Metadata["compressed"] != "true" {
		t.Errorf("receive compressed = %q, want %q", msgs[1].Metadata["compressed"], "true")
	}
}

func TestRecordSession_EmptyBodies(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testLogger())
	ctx := context.Background()

	info := &StreamInfo{
		ConnID:     "test-conn-empty",
		ClientAddr: "127.0.0.1:66666",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Ping",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  nil,
		ResponseBody: nil,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     1 * time.Millisecond,
	}

	err := handler.RecordSession(ctx, info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	msgs := store.messagesForSession(store.sessions[0].ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}

	// Even with no body, metadata should be present.
	if msgs[0].Metadata["service"] != "pkg.Svc" {
		t.Errorf("service = %q, want %q", msgs[0].Metadata["service"], "pkg.Svc")
	}
}

// --- extractHeader tests ---

func TestExtractHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		key     string
		want    string
	}{
		{
			name:    "exact match",
			headers: map[string][]string{"grpc-status": {"0"}},
			key:     "grpc-status",
			want:    "0",
		},
		{
			name:    "case-insensitive match",
			headers: map[string][]string{"Grpc-Status": {"13"}},
			key:     "grpc-status",
			want:    "13",
		},
		{
			name:    "not found",
			headers: map[string][]string{"content-type": {"application/grpc"}},
			key:     "grpc-status",
			want:    "",
		},
		{
			name:    "nil headers",
			headers: nil,
			key:     "grpc-status",
			want:    "",
		},
		{
			name:    "empty values",
			headers: map[string][]string{"grpc-status": {}},
			key:     "grpc-status",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHeader(tt.headers, tt.key)
			if got != tt.want {
				t.Errorf("extractHeader(%v, %q) = %q, want %q", tt.headers, tt.key, got, tt.want)
			}
		})
	}
}

// --- mergeHeaders tests ---

func TestMergeHeaders(t *testing.T) {
	tests := []struct {
		name string
		a    map[string][]string
		b    map[string][]string
		want map[string][]string
	}{
		{
			name: "merge two maps",
			a:    map[string][]string{"Content-Type": {"application/grpc"}},
			b:    map[string][]string{"grpc-status": {"0"}},
			want: map[string][]string{
				"Content-Type": {"application/grpc"},
				"grpc-status":  {"0"},
			},
		},
		{
			name: "overlapping keys",
			a:    map[string][]string{"Key": {"val1"}},
			b:    map[string][]string{"Key": {"val2"}},
			want: map[string][]string{"Key": {"val1", "val2"}},
		},
		{
			name: "nil a",
			a:    nil,
			b:    map[string][]string{"Key": {"val"}},
			want: map[string][]string{"Key": {"val"}},
		},
		{
			name: "nil b",
			a:    map[string][]string{"Key": {"val"}},
			b:    nil,
			want: map[string][]string{"Key": {"val"}},
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeHeaders(tt.a, tt.b)
			if tt.want == nil {
				if got != nil {
					t.Errorf("mergeHeaders() = %v, want nil", got)
				}
				return
			}
			for k, wantVals := range tt.want {
				gotVals, ok := got[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if len(gotVals) != len(wantVals) {
					t.Errorf("key %q: len = %d, want %d", k, len(gotVals), len(wantVals))
					continue
				}
				for i, v := range wantVals {
					if gotVals[i] != v {
						t.Errorf("key %q[%d] = %q, want %q", k, i, gotVals[i], v)
					}
				}
			}
		})
	}
}

// --- GRPCStatusName tests ---

func TestGRPCStatusName(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "OK"},
		{1, "CANCELLED"},
		{2, "UNKNOWN"},
		{3, "INVALID_ARGUMENT"},
		{4, "DEADLINE_EXCEEDED"},
		{5, "NOT_FOUND"},
		{6, "ALREADY_EXISTS"},
		{7, "PERMISSION_DENIED"},
		{8, "RESOURCE_EXHAUSTED"},
		{9, "FAILED_PRECONDITION"},
		{10, "ABORTED"},
		{11, "OUT_OF_RANGE"},
		{12, "UNIMPLEMENTED"},
		{13, "INTERNAL"},
		{14, "UNAVAILABLE"},
		{15, "DATA_LOSS"},
		{16, "UNAUTHENTICATED"},
		{99, "99"},
		{-1, "-1"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GRPCStatusName(tt.code)
			if got != tt.want {
				t.Errorf("GRPCStatusName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// --- extractGRPCStatus tests ---

func TestExtractGRPCStatus(t *testing.T) {
	tests := []struct {
		name     string
		trailers map[string][]string
		headers  map[string][]string
		want     string
	}{
		{
			name:     "from trailers",
			trailers: map[string][]string{"grpc-status": {"0"}},
			headers:  map[string][]string{},
			want:     "0",
		},
		{
			name:     "from headers (Trailers-Only)",
			trailers: nil,
			headers:  map[string][]string{"grpc-status": {"5"}},
			want:     "5",
		},
		{
			name:     "trailers take precedence",
			trailers: map[string][]string{"grpc-status": {"0"}},
			headers:  map[string][]string{"grpc-status": {"5"}},
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
			got := extractGRPCStatus(tt.trailers, tt.headers)
			if got != tt.want {
				t.Errorf("extractGRPCStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}
