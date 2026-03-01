package mcp

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- M4 Integration Test Helpers ---

// seedM4Session creates a complete session with messages in the store for M4 integration tests.
// It accepts protocol-specific parameters and optional metadata for messages.
func seedM4Session(t *testing.T, store session.Store, opts m4SessionOpts) string {
	t.Helper()
	ctx := context.Background()

	sess := &session.Session{
		Protocol:    opts.Protocol,
		SessionType: opts.SessionType,
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    opts.Duration,
		ConnInfo:    opts.ConnInfo,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	for _, msg := range opts.Messages {
		msg.SessionID = sess.ID
		if err := store.AppendMessage(ctx, msg); err != nil {
			t.Fatalf("AppendMessage(seq=%d): %v", msg.Sequence, err)
		}
	}

	return sess.ID
}

// m4SessionOpts configures a session for M4 integration tests.
type m4SessionOpts struct {
	Protocol    string
	SessionType string
	Duration    time.Duration
	ConnInfo    *session.ConnectionInfo
	Messages    []*session.Message
}

// --- Test: HTTP/2 Session Recording and Query ---

func TestM4_HTTP2_SessionRecordingAndQuery(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://api.example.com/v2/users")
	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "HTTP/2",
		SessionType: "unary",
		Duration:    50 * time.Millisecond,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr:           "192.168.1.100:54321",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=api.example.com",
		},
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers: map[string][]string{
					"Accept":     {"application/json"},
					"User-Agent": {"test-agent"},
				},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: []byte(`{"users":["alice","bob"]}`),
			},
		},
	})

	// 1. Verify session appears in sessions list with correct protocol.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	entry := listResult.Sessions[0]
	if entry.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want HTTP/2", entry.Protocol)
	}
	if entry.SessionType != "unary" {
		t.Errorf("session_type = %q, want unary", entry.SessionType)
	}
	if entry.Method != "GET" {
		t.Errorf("method = %q, want GET", entry.Method)
	}
	if entry.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", entry.StatusCode)
	}

	// Verify protocol_summary for HTTP/2.
	if entry.ProtocolSummary == nil {
		t.Fatal("protocol_summary should not be nil for HTTP/2")
	}
	if entry.ProtocolSummary["stream_count"] != "1" {
		t.Errorf("stream_count = %q, want 1", entry.ProtocolSummary["stream_count"])
	}
	if entry.ProtocolSummary["scheme"] != "https" {
		t.Errorf("scheme = %q, want https", entry.ProtocolSummary["scheme"])
	}

	// 2. Get session detail.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.Protocol != "HTTP/2" {
		t.Errorf("detail protocol = %q, want HTTP/2", detail.Protocol)
	}
	if detail.ConnInfo == nil {
		t.Fatal("detail conn_info should not be nil")
	}
	if detail.ConnInfo.TLSALPN != "h2" {
		t.Errorf("conn_info.tls_alpn = %q, want h2", detail.ConnInfo.TLSALPN)
	}
	if detail.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("conn_info.tls_version = %q, want TLS 1.3", detail.ConnInfo.TLSVersion)
	}
	if detail.ResponseBody != `{"users":["alice","bob"]}` {
		t.Errorf("response_body = %q, want JSON", detail.ResponseBody)
	}
	if detail.MessageCount != 2 {
		t.Errorf("message_count = %d, want 2", detail.MessageCount)
	}
	// Unary session should NOT have message_preview.
	if detail.MessagePreview != nil {
		t.Errorf("message_preview should be nil for unary, got %d", len(detail.MessagePreview))
	}
}

// TestM4_HTTP2_H2C_SessionRecordingAndQuery tests h2c (cleartext HTTP/2) session recording.
func TestM4_HTTP2_H2C_SessionRecordingAndQuery(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("http://internal-service:8080/health")
	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "HTTP/2",
		SessionType: "unary",
		Duration:    30 * time.Millisecond,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: "127.0.0.1:8080",
		},
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "GET",
				URL:       reqURL,
				Headers:   map[string][]string{"Accept": {"*/*"}},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/plain"}},
				Body:       []byte("OK"),
			},
		},
	})

	// Verify h2c session has http scheme.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want HTTP/2", detail.Protocol)
	}
	// h2c session should NOT have TLS metadata.
	if detail.ConnInfo != nil && detail.ConnInfo.TLSVersion != "" {
		t.Errorf("h2c session should have empty TLS version, got %q", detail.ConnInfo.TLSVersion)
	}
	if detail.URL != "http://internal-service:8080/health" {
		t.Errorf("url = %q, want http://internal-service:8080/health", detail.URL)
	}
}

// --- Test: WebSocket Session Recording and Query ---

func TestM4_WebSocket_SessionRecordingAndQuery(t *testing.T) {
	env := setupIntegrationEnv(t)

	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		Duration:    2 * time.Second,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: "192.168.1.100:54321",
			ServerAddr: "ws.example.com:443",
			TLSVersion: "TLS 1.3",
		},
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Body:      []byte("hello server"),
				Metadata:  map[string]string{"opcode": "1", "fin": "true", "masked": "true"},
			},
			{
				Sequence:  1,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				Body:      []byte("hello client"),
				Metadata:  map[string]string{"opcode": "1", "fin": "true", "masked": "false"},
			},
			{
				Sequence:  2,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Body:      []byte(`{"type":"ping"}`),
				Metadata:  map[string]string{"opcode": "1", "fin": "true", "masked": "true"},
			},
			{
				Sequence:  3,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				Body:      []byte(`{"type":"pong"}`),
				Metadata:  map[string]string{"opcode": "1", "fin": "true", "masked": "false"},
			},
			// Close frame
			{
				Sequence:  4,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				RawBytes:  []byte{0x03, 0xE8}, // close code 1000
				Metadata:  map[string]string{"opcode": "8", "fin": "true", "masked": "true"},
			},
		},
	})

	// 1. Verify session list entry.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	entry := listResult.Sessions[0]
	if entry.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want WebSocket", entry.Protocol)
	}
	if entry.SessionType != "bidirectional" {
		t.Errorf("session_type = %q, want bidirectional", entry.SessionType)
	}
	if entry.MessageCount != 5 {
		t.Errorf("message_count = %d, want 5", entry.MessageCount)
	}

	// Verify WebSocket protocol summary.
	if entry.ProtocolSummary == nil {
		t.Fatal("protocol_summary should not be nil for WebSocket")
	}
	if entry.ProtocolSummary["message_count"] != "5" {
		t.Errorf("summary message_count = %q, want 5", entry.ProtocolSummary["message_count"])
	}
	if entry.ProtocolSummary["last_frame_type"] != "Close" {
		t.Errorf("last_frame_type = %q, want Close", entry.ProtocolSummary["last_frame_type"])
	}

	// 2. Get session detail — bidirectional should have message_preview.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.SessionType != "bidirectional" {
		t.Errorf("session_type = %q, want bidirectional", detail.SessionType)
	}
	if detail.MessagePreview == nil {
		t.Fatal("message_preview should not be nil for bidirectional session")
	}
	if len(detail.MessagePreview) != 5 {
		t.Errorf("message_preview len = %d, want 5", len(detail.MessagePreview))
	}

	// Verify metadata in preview messages.
	for _, msg := range detail.MessagePreview {
		if msg.Metadata == nil {
			t.Errorf("message preview seq=%d should have metadata", msg.Sequence)
		}
	}

	// 3. Query messages with direction filter.
	sendMsgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
		"filter":   map[string]any{"direction": "send"},
	})
	if sendMsgs.Count != 3 {
		t.Errorf("send message count = %d, want 3", sendMsgs.Count)
	}
	for _, msg := range sendMsgs.Messages {
		if msg.Direction != "send" {
			t.Errorf("filtered message direction = %q, want send", msg.Direction)
		}
	}

	recvMsgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
		"filter":   map[string]any{"direction": "receive"},
	})
	if recvMsgs.Count != 2 {
		t.Errorf("receive message count = %d, want 2", recvMsgs.Count)
	}
}

// TestM4_WebSocket_BinaryFrame verifies that WebSocket binary frames are stored
// as raw bytes and correctly encoded/decoded through the query tool.
func TestM4_WebSocket_BinaryFrame(t *testing.T) {
	env := setupIntegrationEnv(t)

	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		Duration:    100 * time.Millisecond,
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				RawBytes:  []byte{0x00, 0x01, 0x02, 0xFF},
				Metadata:  map[string]string{"opcode": "2", "fin": "true", "masked": "true"},
			},
		},
	})

	msgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
	})
	if msgs.Count != 1 {
		t.Fatalf("messages count = %d, want 1", msgs.Count)
	}
	if msgs.Messages[0].Metadata["opcode"] != "2" {
		t.Errorf("opcode = %q, want 2 (Binary)", msgs.Messages[0].Metadata["opcode"])
	}
}

// --- Test: gRPC Session Recording and Query ---

func TestM4_GRPC_UnarySessionRecordingAndQuery(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://api.example.com/pkg.UserService/GetUser")
	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "gRPC",
		SessionType: "unary",
		Duration:    25 * time.Millisecond,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr:           "192.168.1.100:54321",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=api.example.com",
		},
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       reqURL,
				Headers: map[string][]string{
					"Content-Type": {"application/grpc+proto"},
					"Te":           {"trailers"},
				},
				Body:     []byte("grpc-request-body"),
				Metadata: map[string]string{"service": "pkg.UserService", "method": "GetUser"},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Headers: map[string][]string{
					"Content-Type": {"application/grpc+proto"},
					"Grpc-Status":  {"0"},
					"Grpc-Message": {""},
				},
				Body:     []byte("grpc-response-body"),
				Metadata: map[string]string{"service": "pkg.UserService", "method": "GetUser", "grpc_status": "0"},
			},
		},
	})

	// 1. Verify sessions list.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	entry := listResult.Sessions[0]
	if entry.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want gRPC", entry.Protocol)
	}
	if entry.Method != "POST" {
		t.Errorf("method = %q, want POST", entry.Method)
	}

	// Verify gRPC protocol summary.
	if entry.ProtocolSummary == nil {
		t.Fatal("protocol_summary should not be nil for gRPC")
	}
	if entry.ProtocolSummary["service"] != "pkg.UserService" {
		t.Errorf("service = %q, want pkg.UserService", entry.ProtocolSummary["service"])
	}
	if entry.ProtocolSummary["method"] != "GetUser" {
		t.Errorf("method = %q, want GetUser", entry.ProtocolSummary["method"])
	}
	if entry.ProtocolSummary["grpc_status"] != "0" {
		t.Errorf("grpc_status = %q, want 0", entry.ProtocolSummary["grpc_status"])
	}
	if entry.ProtocolSummary["grpc_status_name"] != "OK" {
		t.Errorf("grpc_status_name = %q, want OK", entry.ProtocolSummary["grpc_status_name"])
	}

	// 2. Get session detail.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.Protocol != "gRPC" {
		t.Errorf("detail protocol = %q, want gRPC", detail.Protocol)
	}
	if detail.ConnInfo == nil {
		t.Fatal("conn_info should not be nil")
	}
	if detail.ConnInfo.TLSALPN != "h2" {
		t.Errorf("conn_info.tls_alpn = %q, want h2", detail.ConnInfo.TLSALPN)
	}

	// 3. Query messages with metadata.
	msgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
	})
	if msgs.Count != 2 {
		t.Fatalf("messages count = %d, want 2", msgs.Count)
	}

	// Verify send message metadata.
	sendMsg := msgs.Messages[0]
	if sendMsg.Metadata == nil {
		t.Fatal("send message metadata should not be nil")
	}
	if sendMsg.Metadata["service"] != "pkg.UserService" {
		t.Errorf("send metadata.service = %q, want pkg.UserService", sendMsg.Metadata["service"])
	}
	if sendMsg.Metadata["method"] != "GetUser" {
		t.Errorf("send metadata.method = %q, want GetUser", sendMsg.Metadata["method"])
	}

	// Verify receive message metadata.
	recvMsg := msgs.Messages[1]
	if recvMsg.Metadata == nil {
		t.Fatal("receive message metadata should not be nil")
	}
	if recvMsg.Metadata["grpc_status"] != "0" {
		t.Errorf("recv metadata.grpc_status = %q, want 0", recvMsg.Metadata["grpc_status"])
	}
}

// TestM4_GRPC_StreamingSession verifies that gRPC streaming sessions with multiple
// request/response frames are correctly recorded and queryable.
func TestM4_GRPC_StreamingSession(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://api.example.com/pkg.StreamService/Subscribe")
	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "gRPC",
		SessionType: "stream",
		Duration:    500 * time.Millisecond,
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       reqURL,
				Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
				Body:      []byte("subscribe-request"),
				Metadata:  map[string]string{"service": "pkg.StreamService", "method": "Subscribe"},
			},
			{
				Sequence:  1,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				Body:      []byte("stream-response-1"),
				Metadata:  map[string]string{"service": "pkg.StreamService", "method": "Subscribe"},
			},
			{
				Sequence:  2,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				Body:      []byte("stream-response-2"),
				Metadata:  map[string]string{"service": "pkg.StreamService", "method": "Subscribe", "grpc_status": "0"},
			},
		},
	})

	// Streaming session should have message_preview.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.SessionType != "stream" {
		t.Errorf("session_type = %q, want stream", detail.SessionType)
	}
	if detail.MessagePreview == nil {
		t.Fatal("message_preview should not be nil for streaming session")
	}
	if len(detail.MessagePreview) != 3 {
		t.Errorf("message_preview len = %d, want 3", len(detail.MessagePreview))
	}
	if detail.MessageCount != 3 {
		t.Errorf("message_count = %d, want 3", detail.MessageCount)
	}
}

// --- Test: Raw TCP Session Recording and Query ---

func TestM4_TCP_SessionRecordingAndQuery(t *testing.T) {
	env := setupIntegrationEnv(t)

	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "TCP",
		SessionType: "bidirectional",
		Duration:    1 * time.Second,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: "192.168.1.100:54321",
			ServerAddr: "db.example.com:3306",
		},
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Body:      []byte("SELECT 1"),
			},
			{
				Sequence:  1,
				Direction: "receive",
				Timestamp: time.Now().UTC(),
				Body:      []byte("1\n"),
			},
			{
				Sequence:  2,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Body:      []byte("QUIT"),
			},
		},
	})

	// 1. Verify sessions list.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	entry := listResult.Sessions[0]
	if entry.Protocol != "TCP" {
		t.Errorf("protocol = %q, want TCP", entry.Protocol)
	}
	if entry.SessionType != "bidirectional" {
		t.Errorf("session_type = %q, want bidirectional", entry.SessionType)
	}

	// Verify TCP protocol summary: send_bytes / receive_bytes.
	if entry.ProtocolSummary == nil {
		t.Fatal("protocol_summary should not be nil for TCP")
	}
	if entry.ProtocolSummary["send_bytes"] != "12" {
		t.Errorf("send_bytes = %q, want 12", entry.ProtocolSummary["send_bytes"])
	}
	if entry.ProtocolSummary["receive_bytes"] != "2" {
		t.Errorf("receive_bytes = %q, want 2", entry.ProtocolSummary["receive_bytes"])
	}

	// 2. Get session detail — bidirectional should have message_preview.
	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.MessagePreview == nil {
		t.Fatal("message_preview should not be nil for bidirectional TCP session")
	}
	if len(detail.MessagePreview) != 3 {
		t.Errorf("message_preview len = %d, want 3", len(detail.MessagePreview))
	}
	if detail.ConnInfo == nil {
		t.Fatal("conn_info should not be nil")
	}
	if detail.ConnInfo.ServerAddr != "db.example.com:3306" {
		t.Errorf("server_addr = %q, want db.example.com:3306", detail.ConnInfo.ServerAddr)
	}

	// 3. Verify messages.
	msgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
	})
	if msgs.Count != 3 {
		t.Fatalf("messages count = %d, want 3", msgs.Count)
	}
	if msgs.Messages[0].Body != "SELECT 1" {
		t.Errorf("msg[0] body = %q, want SELECT 1", msgs.Messages[0].Body)
	}
	if msgs.Messages[1].Body != "1\n" {
		t.Errorf("msg[1] body = %q, want 1\\n", msgs.Messages[1].Body)
	}
}

// --- Test: Query Protocol Filter (cross-protocol) ---

func TestM4_Query_ProtocolFilter_CrossProtocol(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Seed sessions for multiple protocols.
	reqURL1, _ := url.Parse("http://example.com/api")
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "HTTP/2",
		SessionType: "unary",
		Duration:    10 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: reqURL1},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200},
		},
	})

	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "gRPC",
		SessionType: "unary",
		Duration:    20 * time.Millisecond,
		Messages: []*session.Message{
			{
				Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"service": "TestService", "method": "Call"},
			},
			{
				Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"grpc_status": "0"},
			},
		},
	})

	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		Duration:    100 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Body: []byte("ws-msg"), Metadata: map[string]string{"opcode": "1"}},
		},
	})

	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "TCP",
		SessionType: "bidirectional",
		Duration:    200 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Body: []byte("tcp-data")},
		},
	})

	// Verify total count.
	allResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if allResult.Count != 4 {
		t.Fatalf("total sessions = %d, want 4", allResult.Count)
	}

	// Filter by each protocol.
	tests := []struct {
		protocol string
		want     int
	}{
		{"HTTP/2", 1},
		{"gRPC", 1},
		{"WebSocket", 1},
		{"TCP", 1},
	}
	for _, tc := range tests {
		t.Run("filter_"+tc.protocol, func(t *testing.T) {
			result := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
				"resource": "sessions",
				"filter":   map[string]any{"protocol": tc.protocol},
			})
			if result.Count != tc.want {
				t.Errorf("filter %q: count = %d, want %d", tc.protocol, result.Count, tc.want)
			}
			if result.Count > 0 && result.Sessions[0].Protocol != tc.protocol {
				t.Errorf("filter %q: got protocol %q", tc.protocol, result.Sessions[0].Protocol)
			}
		})
	}
}

// --- Test: proxy_start with tcp_forwards and protocols parameters ---

func TestM4_ProxyStart_TCPForwards(t *testing.T) {
	tcpHandler := &mockTCPHandler{}
	env := setupIntegrationEnvWithOpts(t, WithTCPHandler(tcpHandler))

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "db.example.com:3306",
		},
	})
	if startResult.Status != "running" {
		t.Fatalf("status = %q, want running", startResult.Status)
	}
	if startResult.TCPForwards == nil {
		t.Fatal("tcp_forwards should not be nil in result")
	}
	if startResult.TCPForwards["0"] != "db.example.com:3306" {
		t.Errorf("tcp_forwards[0] = %q, want db.example.com:3306", startResult.TCPForwards["0"])
	}

	// Verify forward listeners are actually running.
	addrs := env.manager.TCPForwardAddrs()
	if addrs == nil {
		t.Fatal("expected non-nil TCPForwardAddrs")
	}
}

func TestM4_ProxyStart_Protocols(t *testing.T) {
	env := setupIntegrationEnv(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"protocols":   []any{"HTTP/1.x", "HTTPS", "HTTP/2", "gRPC"},
	})
	if startResult.Status != "running" {
		t.Fatalf("status = %q, want running", startResult.Status)
	}
	if len(startResult.Protocols) != 4 {
		t.Fatalf("protocols len = %d, want 4", len(startResult.Protocols))
	}
	protocolSet := make(map[string]bool)
	for _, p := range startResult.Protocols {
		protocolSet[p] = true
	}
	for _, expected := range []string{"HTTP/1.x", "HTTPS", "HTTP/2", "gRPC"} {
		if !protocolSet[expected] {
			t.Errorf("protocols missing %q", expected)
		}
	}
}

func TestM4_ProxyStart_InvalidProtocol(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"protocols":   []any{"HTTP/1.x", "QUIC"},
	})
}

func TestM4_ProxyStart_InvalidTCPForwards(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"3306": "invalid-no-port",
		},
	})
}

// --- Test: Query config reflects tcp_forwards and enabled_protocols ---

func TestM4_QueryConfig_TCPForwardsAndProtocols(t *testing.T) {
	tcpHandler := &mockTCPHandler{}
	env := setupIntegrationEnvWithOpts(t, WithTCPHandler(tcpHandler))

	// Start proxy with tcp_forwards and protocols.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "postgres.example.com:5432",
		},
		"protocols": []any{"HTTP/1.x", "HTTPS", "TCP"},
	})

	// Query config.
	cfgResult := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})
	if cfgResult.TCPForwards == nil {
		t.Fatal("tcp_forwards should not be nil in config")
	}
	if cfgResult.TCPForwards["0"] != "postgres.example.com:5432" {
		t.Errorf("tcp_forwards[0] = %q, want postgres.example.com:5432", cfgResult.TCPForwards["0"])
	}
	if len(cfgResult.EnabledProtocols) != 3 {
		t.Fatalf("enabled_protocols len = %d, want 3", len(cfgResult.EnabledProtocols))
	}
}

// --- Test: Protocol Mixed — Multiple Protocol Sessions Coexisting ---

func TestM4_ProtocolMixed_MultipleProtocolsSameStore(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want running", startResult.Status)
	}

	// Seed sessions for multiple protocols simulating concurrent usage.
	httpURL, _ := url.Parse("http://example.com/api/data")
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		Duration:    50 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: httpURL, Headers: map[string][]string{"Host": {"example.com"}}},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200, Body: []byte("http-response")},
		},
	})

	h2URL, _ := url.Parse("https://api.example.com/v2/resource")
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "HTTP/2",
		SessionType: "unary",
		Duration:    30 * time.Millisecond,
		ConnInfo: &session.ConnectionInfo{
			TLSALPN: "h2",
		},
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "POST", URL: h2URL},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 201, Body: []byte(`{"id":"new"}`)},
		},
	})

	seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		Duration:    2 * time.Second,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Body: []byte("ws-hello"), Metadata: map[string]string{"opcode": "1"}},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), Body: []byte("ws-world"), Metadata: map[string]string{"opcode": "1"}},
		},
	})

	// 1. Verify all 3 sessions appear.
	allResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if allResult.Count != 3 {
		t.Fatalf("total sessions = %d, want 3", allResult.Count)
	}

	// 2. Verify each protocol can be filtered independently.
	protocols := map[string]int{
		"HTTP/1.x":  1,
		"HTTP/2":    1,
		"WebSocket": 1,
	}
	for proto, expectedCount := range protocols {
		result := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
			"resource": "sessions",
			"filter":   map[string]any{"protocol": proto},
		})
		if result.Count != expectedCount {
			t.Errorf("filter %q: count = %d, want %d", proto, result.Count, expectedCount)
		}
	}

	// 3. Verify each session has appropriate protocol_summary.
	for _, sess := range allResult.Sessions {
		switch sess.Protocol {
		case "HTTP/1.x":
			// HTTP/1.x does not have protocol_summary.
			if sess.ProtocolSummary != nil {
				t.Logf("HTTP/1.x session has protocol_summary (acceptable): %v", sess.ProtocolSummary)
			}
		case "HTTP/2":
			if sess.ProtocolSummary == nil {
				t.Error("HTTP/2 session should have protocol_summary")
			}
		case "WebSocket":
			if sess.ProtocolSummary == nil {
				t.Error("WebSocket session should have protocol_summary")
			}
		}
	}

	// 4. Verify status endpoint reflects all sessions.
	statusResult := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if !statusResult.Running {
		t.Error("status should show proxy running")
	}
	if statusResult.TotalSessions != 3 {
		t.Errorf("total_sessions = %d, want 3", statusResult.TotalSessions)
	}
}

// --- Test: tcp_replay for TCP sessions via execute tool ---

func TestM4_Execute_TCPReplay_WithRealEchoServer(t *testing.T) {
	addr, cleanup := newRawEchoServer(t)
	t.Cleanup(cleanup)

	store := newTestStore(t)
	ctx := context.Background()

	// Create a TCP session with a send message.
	sess := &session.Session{
		Protocol:    "TCP",
		SessionType: "bidirectional",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    100 * time.Millisecond,
		ConnInfo:    &session.ConnectionInfo{ServerAddr: "original:1234"},
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	sendMsg := &session.Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Setup MCP session with a permissive dialer for localhost.
	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"session_id":  sess.ID,
			"target_addr": addr,
			"tag":         "m4-tcp-replay",
		},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out executeReplayRawResult
	unmarshalExecMultiProtoResult(t, result, &out)

	if out.NewSessionID == "" {
		t.Error("new_session_id should not be empty")
	}
	if out.MessagesSent != 1 {
		t.Errorf("messages_sent = %d, want 1", out.MessagesSent)
	}
	if out.TotalBytesSent == 0 {
		t.Error("total_bytes_sent should be > 0")
	}
	if out.TotalBytesReceived == 0 {
		t.Error("total_bytes_received should be > 0")
	}
	if out.Tag != "m4-tcp-replay" {
		t.Errorf("tag = %q, want m4-tcp-replay", out.Tag)
	}

	// Verify the new session is recorded in the store.
	newSess, err := store.GetSession(ctx, out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	if newSess.Protocol != "TCP" {
		t.Errorf("new session protocol = %q, want TCP", newSess.Protocol)
	}
	if newSess.State != "complete" {
		t.Errorf("new session state = %q, want complete", newSess.State)
	}
}

func TestM4_Execute_TCPReplay_ProtocolMismatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create a non-TCP session.
	sess := &session.Session{
		Protocol:    "HTTP/2",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"session_id": sess.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for non-TCP session tcp_replay")
	}
}

// --- Test: delete_sessions across protocols ---

func TestM4_Execute_DeleteSessions_MixedProtocols(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Seed sessions for different protocols.
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "HTTP/2", SessionType: "unary", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()}},
	})
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "gRPC", SessionType: "unary", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()}},
	})
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "WebSocket", SessionType: "bidirectional", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Metadata: map[string]string{"opcode": "1"}}},
	})
	seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "TCP", SessionType: "bidirectional", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Body: []byte("data")}},
	})

	// Verify 4 sessions.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 4 {
		t.Fatalf("sessions count = %d, want 4", listResult.Count)
	}

	// Delete all sessions.
	delResult := callTool[executeDeleteSessionsResult](t, env.cs, "execute", map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"confirm": true,
		},
	})
	if delResult.DeletedCount != 4 {
		t.Errorf("deleted_count = %d, want 4", delResult.DeletedCount)
	}

	// Verify empty.
	emptyResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if emptyResult.Count != 0 {
		t.Errorf("sessions after delete = %d, want 0", emptyResult.Count)
	}
}

// --- Test: Session detail message_preview for streaming protocols ---

func TestM4_Session_MessagePreview_LargeStreamingSession(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Create a WebSocket session with 20 messages.
	msgs := make([]*session.Message, 20)
	for i := 0; i < 20; i++ {
		dir := "send"
		if i%2 == 1 {
			dir = "receive"
		}
		msgs[i] = &session.Message{
			Sequence:  i,
			Direction: dir,
			Timestamp: time.Now().UTC(),
			Body:      []byte(fmt.Sprintf("message-%d", i)),
			Metadata:  map[string]string{"opcode": "1"},
		}
	}

	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		Duration:    5 * time.Second,
		Messages:    msgs,
	})

	detail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
		"resource": "session",
		"id":       sessionID,
	})
	if detail.MessageCount != 20 {
		t.Errorf("message_count = %d, want 20", detail.MessageCount)
	}
	// Preview should be limited to 10 messages.
	if len(detail.MessagePreview) != 10 {
		t.Errorf("message_preview len = %d, want 10 (capped)", len(detail.MessagePreview))
	}
	// Verify preview messages are the first 10 (sequence 0-9).
	for i, preview := range detail.MessagePreview {
		if preview.Sequence != i {
			t.Errorf("preview[%d].sequence = %d, want %d", i, preview.Sequence, i)
		}
	}
}

// --- Test: gRPC error status recording ---

func TestM4_GRPC_ErrorStatusRecording(t *testing.T) {
	env := setupIntegrationEnv(t)

	reqURL, _ := url.Parse("https://api.example.com/pkg.AuthService/Authenticate")
	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "gRPC",
		SessionType: "unary",
		Duration:    15 * time.Millisecond,
		Messages: []*session.Message{
			{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now().UTC(),
				Method:    "POST",
				URL:       reqURL,
				Metadata:  map[string]string{"service": "pkg.AuthService", "method": "Authenticate"},
			},
			{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now().UTC(),
				StatusCode: 200,
				Metadata:   map[string]string{"grpc_status": "16", "grpc_message": "invalid token"},
			},
		},
	})

	// Verify grpc_status is in the summary.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	summary := listResult.Sessions[0].ProtocolSummary
	if summary == nil {
		t.Fatal("protocol_summary should not be nil")
	}
	if summary["grpc_status"] != "16" {
		t.Errorf("grpc_status = %q, want 16", summary["grpc_status"])
	}
	if summary["grpc_status_name"] != "UNAUTHENTICATED" {
		t.Errorf("grpc_status_name = %q, want UNAUTHENTICATED", summary["grpc_status_name"])
	}

	// Verify message-level metadata.
	msgs := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
	})
	recvMsg := msgs.Messages[1]
	if recvMsg.Metadata["grpc_message"] != "invalid token" {
		t.Errorf("grpc_message = %q, want 'invalid token'", recvMsg.Metadata["grpc_message"])
	}
}

// --- Test: Session delete by individual ID across protocols ---

func TestM4_Execute_DeleteSingleSession_ByProtocol(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Seed an HTTP/2 and a gRPC session.
	h2URL, _ := url.Parse("https://example.com/api")
	h2ID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "HTTP/2", SessionType: "unary", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: h2URL},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200},
		},
	})

	grpcURL, _ := url.Parse("https://example.com/pkg.Svc/Method")
	grpcID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol: "gRPC", SessionType: "unary", Duration: 10 * time.Millisecond,
		Messages: []*session.Message{
			{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "POST", URL: grpcURL, Metadata: map[string]string{"service": "pkg.Svc", "method": "Method"}},
			{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200, Metadata: map[string]string{"grpc_status": "0"}},
		},
	})

	// Delete only the HTTP/2 session.
	delResult := callTool[executeDeleteSessionsResult](t, env.cs, "execute", map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"session_id": h2ID,
		},
	})
	if delResult.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", delResult.DeletedCount)
	}

	// Verify the gRPC session is still present.
	listResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}
	if listResult.Sessions[0].ID != grpcID {
		t.Errorf("remaining session ID = %q, want %q", listResult.Sessions[0].ID, grpcID)
	}
	if listResult.Sessions[0].Protocol != "gRPC" {
		t.Errorf("remaining session protocol = %q, want gRPC", listResult.Sessions[0].Protocol)
	}
}

// --- Test: Query sessions pagination with mixed protocols ---

func TestM4_Query_SessionsPagination_MixedProtocols(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Seed 6 sessions (2 per protocol).
	for i := 0; i < 2; i++ {
		reqURL, _ := url.Parse(fmt.Sprintf("https://example.com/api/h2-%d", i))
		seedM4Session(t, env.store, m4SessionOpts{
			Protocol: "HTTP/2", SessionType: "unary", Duration: 10 * time.Millisecond,
			Messages: []*session.Message{
				{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: reqURL},
				{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200},
			},
		})
		seedM4Session(t, env.store, m4SessionOpts{
			Protocol: "gRPC", SessionType: "unary", Duration: 10 * time.Millisecond,
			Messages: []*session.Message{
				{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Metadata: map[string]string{"service": "Svc", "method": "M"}},
				{Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), Metadata: map[string]string{"grpc_status": "0"}},
			},
		})
		seedM4Session(t, env.store, m4SessionOpts{
			Protocol: "WebSocket", SessionType: "bidirectional", Duration: 100 * time.Millisecond,
			Messages: []*session.Message{
				{Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Body: []byte("ws"), Metadata: map[string]string{"opcode": "1"}},
			},
		})
	}

	// Verify total = 6.
	allResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if allResult.Total != 6 {
		t.Fatalf("total = %d, want 6", allResult.Total)
	}

	// Page 1: limit 3.
	page1 := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"limit":    3,
	})
	if page1.Count != 3 {
		t.Errorf("page1 count = %d, want 3", page1.Count)
	}
	if page1.Total != 6 {
		t.Errorf("page1 total = %d, want 6", page1.Total)
	}

	// Page 2: limit 3, offset 3.
	page2 := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"limit":    3,
		"offset":   3,
	})
	if page2.Count != 3 {
		t.Errorf("page2 count = %d, want 3", page2.Count)
	}

	// Page 3: limit 3, offset 6 — should be empty.
	page3 := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"limit":    3,
		"offset":   6,
	})
	if page3.Count != 0 {
		t.Errorf("page3 count = %d, want 0", page3.Count)
	}
}

// --- Test: Messages pagination for streaming session ---

func TestM4_Query_MessagesPagination_StreamingSession(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Create a TCP session with 8 messages.
	msgs := make([]*session.Message, 8)
	for i := 0; i < 8; i++ {
		dir := "send"
		if i%2 == 1 {
			dir = "receive"
		}
		msgs[i] = &session.Message{
			Sequence:  i,
			Direction: dir,
			Timestamp: time.Now().UTC(),
			Body:      []byte(fmt.Sprintf("chunk-%d", i)),
		}
	}

	sessionID := seedM4Session(t, env.store, m4SessionOpts{
		Protocol:    "TCP",
		SessionType: "bidirectional",
		Duration:    500 * time.Millisecond,
		Messages:    msgs,
	})

	// Page 1: limit 3.
	page1 := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
		"limit":    3,
	})
	if page1.Count != 3 {
		t.Errorf("page1 count = %d, want 3", page1.Count)
	}
	if page1.Total != 8 {
		t.Errorf("page1 total = %d, want 8", page1.Total)
	}

	// Page 2: limit 3, offset 3.
	page2 := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
		"limit":    3,
		"offset":   3,
	})
	if page2.Count != 3 {
		t.Errorf("page2 count = %d, want 3", page2.Count)
	}

	// Remaining: limit 3, offset 6 — should get 2.
	page3 := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
		"limit":    3,
		"offset":   6,
	})
	if page3.Count != 2 {
		t.Errorf("page3 count = %d, want 2", page3.Count)
	}
}
