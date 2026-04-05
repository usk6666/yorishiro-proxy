package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Mock store ---

type mockStore struct {
	mu       sync.Mutex
	flows    []*flow.Stream
	updates  []sessionUpdateCall
	messages []*flow.Flow

	saveSessionErr   error
	updateSessionErr error
	appendMessageErr error
}

type sessionUpdateCall struct {
	ID     string
	Update flow.StreamUpdate
}

func (m *mockStore) SaveStream(_ context.Context, s *flow.Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveSessionErr != nil {
		return m.saveSessionErr
	}
	if s.ID == "" {
		s.ID = fmt.Sprintf("sess-%d", len(m.flows)+1)
	}
	m.flows = append(m.flows, s)
	return nil
}

func (m *mockStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateSessionErr != nil {
		return m.updateSessionErr
	}
	m.updates = append(m.updates, sessionUpdateCall{ID: id, Update: update})
	return nil
}

func (m *mockStore) GetFlow(_ context.Context, _ string) (*flow.Stream, error) {
	return nil, nil
}

func (m *mockStore) ListFlows(_ context.Context, _ flow.StreamListOptions) ([]*flow.Stream, error) {
	return nil, nil
}

func (m *mockStore) CountStreams(_ context.Context, _ flow.StreamListOptions) (int, error) {
	return 0, nil
}

func (m *mockStore) DeleteStream(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) DeleteAllFlows(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteFlowsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteFlowsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) {
	return 0, nil
}

func (m *mockStore) SaveFlow(_ context.Context, msg *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.appendMessageErr != nil {
		return m.appendMessageErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetFlows(_ context.Context, _ string, _ flow.FlowListOptions) ([]*flow.Flow, error) {
	return nil, nil
}

func (m *mockStore) CountFlows(_ context.Context, _ string) (int, error) {
	return 0, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *mockStore) GetMacro(_ context.Context, _ string) (*flow.MacroRecord, error) {
	return nil, nil
}

func (m *mockStore) ListMacros(_ context.Context) ([]*flow.MacroRecord, error) {
	return nil, nil
}

func (m *mockStore) DeleteMacro(_ context.Context, _ string) error {
	return nil
}

func (m *mockStore) getFlows() []*flow.Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*flow.Stream, len(m.flows))
	copy(out, m.flows)
	return out
}

func (m *mockStore) getUpdates() []sessionUpdateCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sessionUpdateCall, len(m.updates))
	copy(out, m.updates)
	return out
}

func (m *mockStore) getMessages() []*flow.Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*flow.Flow, len(m.messages))
	copy(out, m.messages)
	return out
}

// --- Test helpers ---

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

func TestHandler_Detect(t *testing.T) {
	h := NewHandler(nil, nil, testutil.DiscardLogger())

	if !h.Detect([]byte{0x01, 0x02, 0x03}) {
		t.Error("Detect(random bytes) = false, want true (fallback handler)")
	}
}

func TestHandler_Handle_BidirectionalRelay(t *testing.T) {
	// Set up echo server as upstream.
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())

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

	// Verify flow was recorded.
	sessions := store.getFlows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}

	fl := sessions[0]
	if fl.Protocol != "TCP" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "TCP")
	}
	if fl.ConnID != "test-conn-01" {
		t.Errorf("flow connID = %q, want %q", fl.ConnID, "test-conn-01")
	}
	if fl.ConnInfo == nil {
		t.Fatal("flow ConnInfo is nil")
	}
	if fl.ConnInfo.ClientAddr != "192.168.1.100:54321" {
		t.Errorf("ConnInfo.ClientAddr = %q, want %q", fl.ConnInfo.ClientAddr, "192.168.1.100:54321")
	}
	if fl.ConnInfo.ServerAddr != echoAddr {
		t.Errorf("ConnInfo.ServerAddr = %q, want %q", fl.ConnInfo.ServerAddr, echoAddr)
	}

	// Verify flow was updated to complete.
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
		if msg.StreamID != fl.ID {
			t.Errorf("message session_id = %q, want %q", msg.StreamID, fl.ID)
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
	h := NewHandler(store, nil, testutil.DiscardLogger())

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

	// No flow should be saved since there's no forward target.
	sessions := store.getFlows()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestHandler_Handle_UpstreamDialFailure(t *testing.T) {
	store := &mockStore{}
	// Point to a non-routable address that should fail fast.
	forwards := map[string]*config.ForwardConfig{"9999": {Target: "127.0.0.1:1", Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())

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
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())

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

	// Flow should be updated even on cancellation.
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
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(nil, forwards, testutil.DiscardLogger())

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
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())

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
		t.Errorf("recorded %d messages (expected at least 6)", len(messages))
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
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())

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

// --- Relay unit tests ---

func TestRelay_Record_NilStore(t *testing.T) {
	r := &relay{
		store:  nil,
		flowID: "test-session",
		logger: testutil.DiscardLogger(),
	}

	// Should not panic.
	r.record(context.Background(), "send", []byte("data"))
}

func TestRelay_SequenceNumbers(t *testing.T) {
	store := &mockStore{}
	r := &relay{
		store:  store,
		flowID: "test-session",
		logger: testutil.DiscardLogger(),
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
		store:  store,
		flowID: "test-session",
		logger: testutil.DiscardLogger(),
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
	// Scenario 1: Set forwards on empty handler.
	h := NewHandler(nil, nil, testutil.DiscardLogger())

	if len(h.Forwards()) != 0 {
		t.Errorf("initial forwards = %v, want empty", h.Forwards())
	}

	h.SetForwards(map[string]*config.ForwardConfig{
		"3306": {Target: "db.example.com:3306", Protocol: "raw"},
		"6379": {Target: "redis.example.com:6379", Protocol: "raw"},
	})

	got := h.Forwards()
	if len(got) != 2 {
		t.Fatalf("forwards len = %d, want 2", len(got))
	}
	if got["3306"] == nil || got["3306"].Target != "db.example.com:3306" {
		t.Errorf("forwards[3306].Target = %v, want db.example.com:3306", got["3306"])
	}
	if got["6379"] == nil || got["6379"].Target != "redis.example.com:6379" {
		t.Errorf("forwards[6379].Target = %v, want redis.example.com:6379", got["6379"])
	}

	// Scenario 2: Merge into existing entries.
	h2 := NewHandler(nil, map[string]*config.ForwardConfig{
		"3306": {Target: "db.example.com:3306", Protocol: "raw"},
	}, testutil.DiscardLogger())

	h2.SetForwards(map[string]*config.ForwardConfig{
		"6379": {Target: "redis.example.com:6379", Protocol: "raw"},
	})

	got = h2.Forwards()
	if len(got) != 2 {
		t.Fatalf("merge: forwards len = %d, want 2", len(got))
	}
	if got["3306"] == nil || got["3306"].Target != "db.example.com:3306" {
		t.Errorf("merge: forwards[3306].Target = %v, want db.example.com:3306", got["3306"])
	}
	if got["6379"] == nil || got["6379"].Target != "redis.example.com:6379" {
		t.Errorf("merge: forwards[6379].Target = %v, want redis.example.com:6379", got["6379"])
	}

	// Scenario 3: Override existing entries.
	h3 := NewHandler(nil, map[string]*config.ForwardConfig{
		"3306": {Target: "old-db.example.com:3306", Protocol: "raw"},
	}, testutil.DiscardLogger())

	h3.SetForwards(map[string]*config.ForwardConfig{
		"3306": {Target: "new-db.example.com:3306", Protocol: "raw"},
	})

	got = h3.Forwards()
	if got["3306"] == nil || got["3306"].Target != "new-db.example.com:3306" {
		t.Errorf("override: forwards[3306].Target = %v, want new-db.example.com:3306", got["3306"])
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
