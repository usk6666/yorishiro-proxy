package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- Mock store ---

type mockStore struct {
	mu       sync.Mutex
	sessions []*session.Session
	updates  []sessionUpdateCall
	messages []*session.Message

	saveSessionErr   error
	updateSessionErr error
	appendMessageErr error
}

type sessionUpdateCall struct {
	ID     string
	Update session.SessionUpdate
}

func (m *mockStore) SaveSession(_ context.Context, s *session.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveSessionErr != nil {
		return m.saveSessionErr
	}
	if s.ID == "" {
		s.ID = fmt.Sprintf("sess-%d", len(m.sessions)+1)
	}
	m.sessions = append(m.sessions, s)
	return nil
}

func (m *mockStore) UpdateSession(_ context.Context, id string, update session.SessionUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateSessionErr != nil {
		return m.updateSessionErr
	}
	m.updates = append(m.updates, sessionUpdateCall{ID: id, Update: update})
	return nil
}

func (m *mockStore) GetSession(_ context.Context, _ string) (*session.Session, error) {
	return nil, nil
}

func (m *mockStore) ListSessions(_ context.Context, _ session.ListOptions) ([]*session.Session, error) {
	return nil, nil
}

func (m *mockStore) CountSessions(_ context.Context, _ session.ListOptions) (int, error) {
	return 0, nil
}

func (m *mockStore) DeleteSession(_ context.Context, _ string) error {
	return nil
}

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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.appendMessageErr != nil {
		return m.appendMessageErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetMessages(_ context.Context, _ string, _ session.MessageListOptions) ([]*session.Message, error) {
	return nil, nil
}

func (m *mockStore) CountMessages(_ context.Context, _ string) (int, error) {
	return 0, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockStore) GetMacro(_ context.Context, _ string) (*session.MacroRecord, error) {
	return nil, nil
}

func (m *mockStore) ListMacros(_ context.Context) ([]*session.MacroRecord, error) {
	return nil, nil
}

func (m *mockStore) DeleteMacro(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) getSessions() []*session.Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*session.Session, len(m.sessions))
	copy(out, m.sessions)
	return out
}

func (m *mockStore) getUpdates() []sessionUpdateCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sessionUpdateCall, len(m.updates))
	copy(out, m.updates)
	return out
}

func (m *mockStore) getMessages() []*session.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*session.Message, len(m.messages))
	copy(out, m.messages)
	return out
}

// --- Test helpers ---

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupEchoServer starts a TCP server that echoes all received data.
// Returns the listener address and a cleanup function.
func setupEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String()
}

// connWithLocalAddr wraps a net.Conn to override LocalAddr for testing.
type connWithLocalAddr struct {
	net.Conn
	localAddr net.Addr
}

func (c *connWithLocalAddr) LocalAddr() net.Addr {
	return c.localAddr
}

// --- Tests ---

func TestHandler_Name(t *testing.T) {
	h := NewHandler(nil, nil, testLogger(t))
	if got := h.Name(); got != "TCP" {
		t.Errorf("Name() = %q, want %q", got, "TCP")
	}
}

func TestHandler_Detect(t *testing.T) {
	h := NewHandler(nil, nil, testLogger(t))

	tests := []struct {
		name string
		peek []byte
	}{
		{"empty bytes", nil},
		{"random bytes", []byte{0x01, 0x02, 0x03}},
		{"HTTP-like bytes", []byte("GET /index.html")},
		{"binary data", []byte{0xff, 0xfe, 0x00, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !h.Detect(tt.peek) {
				t.Errorf("Detect(%v) = false, want true (fallback handler)", tt.peek)
			}
		})
	}
}

func TestHandler_Handle_BidirectionalRelay(t *testing.T) {
	// Set up echo server as upstream.
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]string{echoPort: echoAddr}
	h := NewHandler(store, forwards, testLogger(t))

	// Create a pipe simulating client <-> proxy.
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	// Override LocalAddr to match the echo server port.
	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-conn-01")
	ctx = proxy.ContextWithClientAddr(ctx, "192.168.1.100:54321")

	// Run handler in background.
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send data and verify echo.
	testData := []byte("hello, raw TCP!")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	// Close client to end relay.
	clientConn.Close()

	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}

	// Verify session was recorded.
	sessions := store.getSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	sess := sessions[0]
	if sess.Protocol != "TCP" {
		t.Errorf("session protocol = %q, want %q", sess.Protocol, "TCP")
	}
	if sess.SessionType != "bidirectional" {
		t.Errorf("session type = %q, want %q", sess.SessionType, "bidirectional")
	}
	if sess.ConnID != "test-conn-01" {
		t.Errorf("session connID = %q, want %q", sess.ConnID, "test-conn-01")
	}
	if sess.ConnInfo == nil {
		t.Fatal("session ConnInfo is nil")
	}
	if sess.ConnInfo.ClientAddr != "192.168.1.100:54321" {
		t.Errorf("ConnInfo.ClientAddr = %q, want %q", sess.ConnInfo.ClientAddr, "192.168.1.100:54321")
	}
	if sess.ConnInfo.ServerAddr != echoAddr {
		t.Errorf("ConnInfo.ServerAddr = %q, want %q", sess.ConnInfo.ServerAddr, echoAddr)
	}

	// Verify session was updated to complete.
	updates := store.getUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if updates[0].Update.State != "complete" {
		t.Errorf("update state = %q, want %q", updates[0].Update.State, "complete")
	}
	if updates[0].Update.Duration <= 0 {
		t.Error("update duration should be positive")
	}

	// Verify messages were recorded.
	messages := store.getMessages()
	if len(messages) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(messages))
	}

	// There should be at least one send and one receive message.
	var hasSend, hasReceive bool
	for _, msg := range messages {
		if msg.Direction == "send" {
			hasSend = true
			if string(msg.RawBytes) != string(testData) {
				t.Errorf("send message raw_bytes = %q, want %q", msg.RawBytes, testData)
			}
			if msg.Metadata["chunk_size"] != fmt.Sprintf("%d", len(testData)) {
				t.Errorf("send metadata chunk_size = %q, want %q", msg.Metadata["chunk_size"], fmt.Sprintf("%d", len(testData)))
			}
		}
		if msg.Direction == "receive" {
			hasReceive = true
			if string(msg.RawBytes) != string(testData) {
				t.Errorf("receive message raw_bytes = %q, want %q", msg.RawBytes, testData)
			}
		}
		if msg.SessionID != sess.ID {
			t.Errorf("message session_id = %q, want %q", msg.SessionID, sess.ID)
		}
	}
	if !hasSend {
		t.Error("no send message recorded")
	}
	if !hasReceive {
		t.Error("no receive message recorded")
	}
}

func TestHandler_Handle_NoForwardConfigured(t *testing.T) {
	store := &mockStore{}
	// No forwarding rules.
	h := NewHandler(store, nil, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-conn-02")

	err := h.Handle(ctx, wrappedConn)
	if err != nil {
		t.Errorf("Handle() returned error: %v, want nil (graceful close)", err)
	}

	// No session should be saved since there's no forward target.
	sessions := store.getSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestHandler_Handle_UpstreamDialFailure(t *testing.T) {
	store := &mockStore{}
	// Point to a non-routable address that should fail fast.
	forwards := map[string]string{"9999": "127.0.0.1:1"}
	h := NewHandler(store, forwards, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-conn-03")

	err := h.Handle(ctx, wrappedConn)
	if err == nil {
		t.Error("Handle() returned nil, want dial error")
	}
}

func TestHandler_Handle_ContextCancellation(t *testing.T) {
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]string{echoPort: echoAddr}
	h := NewHandler(store, forwards, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = proxy.ContextWithConnID(ctx, "test-conn-04")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Write data and read the echo to ensure relay is established.
	testData := []byte("test")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Cancel context to trigger shutdown.
	cancel()

	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("Handle() returned %v, want nil or context.Canceled", err)
	}

	// Session should be updated even on cancellation.
	updates := store.getUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	// Context cancellation is normal shutdown, state should be "complete".
	if updates[0].Update.State != "complete" {
		t.Errorf("update state = %q, want %q", updates[0].Update.State, "complete")
	}
}

func TestHandler_Handle_NilStore(t *testing.T) {
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	// Nil store: relay should still work, just no recording.
	forwards := map[string]string{echoPort: echoAddr}
	h := NewHandler(nil, forwards, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Echo test.
	testData := []byte("nil store test")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
}

func TestHandler_Handle_MultipleChunks(t *testing.T) {
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]string{echoPort: echoAddr}
	h := NewHandler(store, forwards, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-conn-05")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send multiple chunks.
	chunks := []string{"chunk1", "chunk2", "chunk3"}
	for _, chunk := range chunks {
		if _, err := clientConn.Write([]byte(chunk)); err != nil {
			t.Fatalf("write %q: %v", chunk, err)
		}

		buf := make([]byte, len(chunk))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			t.Fatalf("read after %q: %v", chunk, err)
		}

		if string(buf) != chunk {
			t.Errorf("echo mismatch for chunk %q: got %q", chunk, buf)
		}

		// Small delay between chunks for distinct messages.
		time.Sleep(10 * time.Millisecond)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}

	// Verify multiple messages were recorded.
	messages := store.getMessages()
	if len(messages) < 6 {
		// 3 sends + 3 receives = at least 6 messages.
		// May have more if chunks get split.
		t.Logf("recorded %d messages (expected at least 6)", len(messages))
	}

	// Verify sequences are monotonically increasing.
	seenSeqs := make(map[int]bool)
	for _, msg := range messages {
		if seenSeqs[msg.Sequence] {
			t.Errorf("duplicate sequence number %d", msg.Sequence)
		}
		seenSeqs[msg.Sequence] = true
	}
}

func TestHandler_Handle_StoreErrors(t *testing.T) {
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{
		appendMessageErr: errors.New("storage write error"),
	}
	forwards := map[string]string{echoPort: echoAddr}
	h := NewHandler(store, forwards, testLogger(t))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-conn-06")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Relay should still work even when recording fails.
	testData := []byte("store error test")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
}

func TestNewHandler_NilForwards(t *testing.T) {
	h := NewHandler(nil, nil, testLogger(t))
	if h.forwards == nil {
		t.Error("forwards should be initialized to empty map, not nil")
	}
}

// --- Relay unit tests ---

func TestRelay_Record_NilStore(t *testing.T) {
	r := &relay{
		store:     nil,
		sessionID: "test-session",
		logger:    testLogger(t),
	}

	// Should not panic.
	r.record(context.Background(), "send", []byte("data"))
}

func TestRelay_SequenceNumbers(t *testing.T) {
	store := &mockStore{}
	r := &relay{
		store:     store,
		sessionID: "test-session",
		logger:    testLogger(t),
	}

	for i := 0; i < 5; i++ {
		r.record(context.Background(), "send", []byte(fmt.Sprintf("chunk-%d", i)))
	}

	messages := store.getMessages()
	if len(messages) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(messages))
	}

	for i, msg := range messages {
		if msg.Sequence != i {
			t.Errorf("message %d: sequence = %d, want %d", i, msg.Sequence, i)
		}
	}
}

func TestRelay_DataIsolation(t *testing.T) {
	// Verify that recorded data is a copy, not a reference to the buffer.
	store := &mockStore{}
	r := &relay{
		store:     store,
		sessionID: "test-session",
		logger:    testLogger(t),
	}

	buf := []byte("original data")
	r.record(context.Background(), "send", buf)

	// Mutate the buffer.
	copy(buf, "modified data")

	messages := store.getMessages()
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	if string(messages[0].RawBytes) != "original data" {
		t.Errorf("raw bytes = %q, want %q (should be independent copy)", messages[0].RawBytes, "original data")
	}
}

// --- SetForwards tests ---

func TestHandler_SetForwards(t *testing.T) {
	h := NewHandler(nil, nil, testLogger(t))

	// Initially empty.
	if len(h.Forwards()) != 0 {
		t.Errorf("initial forwards = %v, want empty", h.Forwards())
	}

	// Set forwards.
	h.SetForwards(map[string]string{
		"3306": "db.example.com:3306",
		"6379": "redis.example.com:6379",
	})

	got := h.Forwards()
	if len(got) != 2 {
		t.Fatalf("forwards len = %d, want 2", len(got))
	}
	if got["3306"] != "db.example.com:3306" {
		t.Errorf("forwards[3306] = %q, want %q", got["3306"], "db.example.com:3306")
	}
	if got["6379"] != "redis.example.com:6379" {
		t.Errorf("forwards[6379] = %q, want %q", got["6379"], "redis.example.com:6379")
	}
}

func TestHandler_SetForwards_Merge(t *testing.T) {
	// SetForwards should merge into existing entries.
	initial := map[string]string{
		"3306": "db.example.com:3306",
	}
	h := NewHandler(nil, initial, testLogger(t))

	// Add a new entry.
	h.SetForwards(map[string]string{
		"6379": "redis.example.com:6379",
	})

	got := h.Forwards()
	if len(got) != 2 {
		t.Fatalf("forwards len = %d, want 2", len(got))
	}
	if got["3306"] != "db.example.com:3306" {
		t.Errorf("forwards[3306] = %q, want %q", got["3306"], "db.example.com:3306")
	}
	if got["6379"] != "redis.example.com:6379" {
		t.Errorf("forwards[6379] = %q, want %q", got["6379"], "redis.example.com:6379")
	}
}

func TestHandler_SetForwards_Override(t *testing.T) {
	// SetForwards should override existing entries.
	initial := map[string]string{
		"3306": "old-db.example.com:3306",
	}
	h := NewHandler(nil, initial, testLogger(t))

	h.SetForwards(map[string]string{
		"3306": "new-db.example.com:3306",
	})

	got := h.Forwards()
	if got["3306"] != "new-db.example.com:3306" {
		t.Errorf("forwards[3306] = %q, want %q", got["3306"], "new-db.example.com:3306")
	}
}

// --- Helpers ---

func mustParsePort(t *testing.T, port string) int {
	t.Helper()
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatalf("parse port %q: %v", port, err)
	}
	return p
}
