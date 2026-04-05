package tcp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// relayMockStore is a minimal FlowWriter mock for relay tests.
type relayMockStore struct {
	mu       sync.Mutex
	messages []*flow.Flow
}

func (m *relayMockStore) SaveStream(_ context.Context, s *flow.Stream) error {
	if s.ID == "" {
		s.ID = "test-flow-id"
	}
	return nil
}

func (m *relayMockStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (m *relayMockStore) SaveFlow(_ context.Context, msg *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *relayMockStore) getMessages() []*flow.Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*flow.Flow, len(m.messages))
	copy(out, m.messages)
	return out
}

func TestRunRelay_RecordsMessages(t *testing.T) {
	store := &relayMockStore{}

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunRelay(ctx, clientEnd, upstreamConn, RelayConfig{
			Store:    store,
			StreamID: "flow-1",
			Logger:   testutil.DiscardLogger(),
			Target:   "db.example.com:5432",
		})
	}()

	// client -> upstream
	testData := []byte("hello from client")
	clientConn.Write(testData)

	buf := make([]byte, 100)
	upstreamEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamEnd.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %q, got %q", testData, buf[:n])
	}

	// upstream -> client
	replyData := []byte("hello from server")
	upstreamEnd.Write(replyData)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], replyData) {
		t.Fatalf("expected %q, got %q", replyData, buf[:n])
	}

	// Close connections to end relay.
	clientConn.Close()
	upstreamEnd.Close()
	<-errCh

	// Verify messages were recorded.
	msgs := store.getMessages()
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}

	// Check that we have both directions.
	var hasSend, hasReceive bool
	for _, msg := range msgs {
		if msg.StreamID != "flow-1" {
			t.Errorf("message has wrong flow ID: %q", msg.StreamID)
		}
		if msg.Direction == "send" {
			hasSend = true
		}
		if msg.Direction == "receive" {
			hasReceive = true
		}
	}
	if !hasSend {
		t.Error("no send message recorded")
	}
	if !hasReceive {
		t.Error("no receive message recorded")
	}
}

func TestRunRelay_NilStore(t *testing.T) {
	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunRelay(ctx, clientEnd, upstreamConn, RelayConfig{
			Store:    nil,
			StreamID: "",
			Logger:   testutil.DiscardLogger(),
		})
	}()

	// Data should still flow.
	testData := []byte("test data")
	clientConn.Write(testData)

	buf := make([]byte, 100)
	upstreamEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamEnd.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %q, got %q", testData, buf[:n])
	}

	clientConn.Close()
	upstreamEnd.Close()
	<-errCh
}

func TestRunRelay_ContextCancellation(t *testing.T) {
	store := &relayMockStore{}

	_, clientEnd := net.Pipe()
	upstreamConn, _ := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunRelay(ctx, clientEnd, upstreamConn, RelayConfig{
			Store:    store,
			StreamID: "flow-cancel",
			Logger:   testutil.DiscardLogger(),
		})
	}()

	// Cancel the context.
	cancel()

	err := <-errCh
	if err != context.Canceled {
		// err may be nil or context.Canceled depending on timing.
		if err != nil {
			t.Errorf("expected context.Canceled or nil, got: %v", err)
		}
	}

	// Cleanup.
	clientEnd.Close()
	upstreamConn.Close()
}

// Verify RelayConfig fields are passed through correctly.
func TestRunRelay_ConfigFieldsUsed(t *testing.T) {
	store := &relayMockStore{}

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunRelay(ctx, clientEnd, upstreamConn, RelayConfig{
			Store:    store,
			StreamID: "custom-flow-id",
			Logger:   testutil.DiscardLogger(),
			Target:   "192.168.1.100:9999",
		})
	}()

	clientConn.Write([]byte("data"))
	// Wait for relay to process.
	buf := make([]byte, 10)
	upstreamEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	upstreamEnd.Read(buf)

	clientConn.Close()
	upstreamEnd.Close()
	<-errCh

	msgs := store.getMessages()
	if len(msgs) == 0 {
		t.Fatal("expected messages to be recorded")
	}
	for _, msg := range msgs {
		if msg.StreamID != "custom-flow-id" {
			t.Errorf("expected flow ID %q, got %q", "custom-flow-id", msg.StreamID)
		}
		if msg.Metadata["chunk_size"] != fmt.Sprintf("%d", len("data")) {
			// Only check send direction.
			if msg.Direction == "send" {
				t.Errorf("expected chunk_size=%d, got %s", len("data"), msg.Metadata["chunk_size"])
			}
		}
	}
}
