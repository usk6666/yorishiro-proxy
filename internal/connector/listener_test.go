package connector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// recordingDispatcher captures every dispatched connection for test
// assertions. It closes the connection after reading all bytes so the
// accept loop can continue cleanly.
type recordingDispatcher struct {
	mu      sync.Mutex
	entries []dispatchEntry
	// releaseCh, when non-nil, is signalled once per Dispatch call so
	// tests can control when a connection is considered finished. When
	// nil, Dispatch returns immediately after recording.
	releaseCh <-chan struct{}
	// returnErr, when non-nil, is returned by Dispatch (after recording).
	returnErr error
}

type dispatchEntry struct {
	Kind    ProtocolKind
	Peek    string
	HasFact bool
}

func (r *recordingDispatcher) Dispatch(_ context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error {
	peek, _ := conn.Peek(conn.Buffered())
	r.mu.Lock()
	r.entries = append(r.entries, dispatchEntry{
		Kind:    kind,
		Peek:    string(peek),
		HasFact: factory != nil,
	})
	r.mu.Unlock()

	// Drain the connection so accept doesn't block on client close.
	go io.Copy(io.Discard, conn)

	if r.releaseCh != nil {
		<-r.releaseCh
	}
	return r.returnErr
}

func (r *recordingDispatcher) snapshot() []dispatchEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]dispatchEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// newTestLogger returns a slog.Logger that discards output.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// startListener launches a Listener on 127.0.0.1:0 and blocks until it is
// accepting. It returns the listener, its context cancel, and a cleanup func.
func startListener(t *testing.T, cfg ListenerConfig) (*Listener, context.CancelFunc) {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = newTestLogger()
	}
	l := NewListener(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Start(ctx)
	}()
	select {
	case <-l.Ready():
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("listener did not become ready")
	}
	cleanup := func() {
		cancel()
		<-done
	}
	t.Cleanup(cleanup)
	return l, cancel
}

func TestListener_StartAccept(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolHTTP1, &fakeFactory{kind: ProtocolHTTP1})

	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Wait for the dispatcher to record.
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	entries := recorder.snapshot()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Kind != ProtocolHTTP1 {
		t.Errorf("kind = %v, want HTTP1", entries[0].Kind)
	}
	if !entries[0].HasFact {
		t.Error("factory should be non-nil")
	}
	conn.Close()
}

func TestListener_DetectSOCKS5(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolSOCKS5, &fakeFactory{kind: ProtocolSOCKS5})

	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// SOCKS5 greeting: version 0x05, nmethods=1, method=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	entries := recorder.snapshot()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Kind != ProtocolSOCKS5 {
		t.Errorf("kind = %v, want SOCKS5", entries[0].Kind)
	}
	conn.Close()
}

func TestListener_DetectConnect(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolHTTPConnect, &fakeFactory{kind: ProtocolHTTPConnect})

	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	entries := recorder.snapshot()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Kind != ProtocolHTTPConnect {
		t.Errorf("kind = %v, want HTTP/CONNECT", entries[0].Kind)
	}
	conn.Close()
}

func TestListener_H2cDetectedButNoFactory(t *testing.T) {
	// Q3 in the Issue: h2c is detected in M39 but has no CodecFactory
	// registered. The listener should still dispatch (so the dispatcher
	// can log the decision and close the connection).
	detector := NewDetector()
	// No factory registered for HTTP/2.
	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	entries := recorder.snapshot()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Kind != ProtocolHTTP2 {
		t.Errorf("kind = %v, want HTTP2", entries[0].Kind)
	}
	if entries[0].HasFact {
		t.Error("factory should be nil for h2c in M39")
	}
	conn.Close()
}

func TestListener_TCPFallthrough(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})

	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Opaque binary bytes.
	if _, err := conn.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	entries := recorder.snapshot()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Kind != ProtocolTCP {
		t.Errorf("kind = %v, want TCP", entries[0].Kind)
	}
	conn.Close()
}

func TestListener_ShortReadAndClose(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})
	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Dispatch:    recorder,
		PeekTimeout: 100 * time.Millisecond,
	})

	// Dial then close immediately without writing anything — the listener
	// should not panic, and DetectKind should return Unknown; the listener
	// logs and returns without dispatching.
	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	// Give the listener a moment to clean up.
	time.Sleep(200 * time.Millisecond)

	if len(recorder.snapshot()) != 0 {
		t.Errorf("dispatcher entries = %d, want 0 for immediate close", len(recorder.snapshot()))
	}
}

func TestListener_MaxConnections(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})
	release := make(chan struct{})
	recorder := &recordingDispatcher{releaseCh: release}

	l, _ := startListener(t, ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Dispatch:       recorder,
		MaxConnections: 1,
	})

	// First connection: occupies the slot.
	c1, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	if _, err := c1.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write c1: %v", err)
	}

	// Wait for the dispatcher to have recorded the first connection.
	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1 && l.ActiveConnections() == 1
	})

	// Second connection: should be rejected.
	c2, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	// Try reading — rejected connections are closed by the listener
	// immediately, so Read should return EOF quickly.
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = c2.Read(buf)
	if err == nil {
		t.Error("expected read error from rejected connection")
	}
	c2.Close()

	// Release the first connection and verify the active count drops.
	close(release)
	c1.Close()
	waitFor(t, 500*time.Millisecond, func() bool {
		return l.ActiveConnections() == 0
	})

	if got := len(recorder.snapshot()); got != 1 {
		t.Errorf("dispatcher entries = %d, want 1 (second connection must not have been dispatched)", got)
	}
}

func TestListener_SetMaxConnections(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})
	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Dispatch:       recorder,
		MaxConnections: 10,
	})
	if got := l.MaxConnections(); got != 10 {
		t.Errorf("MaxConnections = %d, want 10", got)
	}
	l.SetMaxConnections(42)
	if got := l.MaxConnections(); got != 42 {
		t.Errorf("MaxConnections after set = %d, want 42", got)
	}
	// Invalid values are ignored.
	l.SetMaxConnections(0)
	l.SetMaxConnections(-1)
	if got := l.MaxConnections(); got != 42 {
		t.Errorf("MaxConnections after invalid set = %d, want 42", got)
	}
}

func TestListener_SetPeekTimeout(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})
	recorder := &recordingDispatcher{}
	l, _ := startListener(t, ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	})
	if got := l.PeekTimeout(); got != DefaultPeekTimeout {
		t.Errorf("PeekTimeout = %v, want %v", got, DefaultPeekTimeout)
	}
	l.SetPeekTimeout(2 * time.Second)
	if got := l.PeekTimeout(); got != 2*time.Second {
		t.Errorf("PeekTimeout after set = %v, want 2s", got)
	}
	// Zero/negative ignored.
	l.SetPeekTimeout(0)
	l.SetPeekTimeout(-1)
	if got := l.PeekTimeout(); got != 2*time.Second {
		t.Errorf("PeekTimeout after invalid set = %v, want 2s", got)
	}
}

func TestListener_RequiresDetectorAndDispatcher(t *testing.T) {
	t.Run("missing detector", func(t *testing.T) {
		l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", Dispatch: DispatcherFunc(func(context.Context, *PeekConn, ProtocolKind, CodecFactory) error { return nil })})
		err := l.Start(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("missing dispatcher", func(t *testing.T) {
		l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", Detector: NewDetector()})
		err := l.Start(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestConnector_StartStopNamed(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolTCP, &fakeFactory{kind: ProtocolTCP})
	recorder := &recordingDispatcher{}

	c := NewConnector(ConnectorConfig{
		Detector: detector,
		Dispatch: recorder,
		Logger:   newTestLogger(),
	})

	ctx := context.Background()
	if err := c.StartNamed(ctx, "a", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed a: %v", err)
	}
	if err := c.StartNamed(ctx, "b", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed b: %v", err)
	}
	if err := c.StartNamed(ctx, "a", "127.0.0.1:0"); !errors.Is(err, ErrListenerExists) {
		t.Errorf("duplicate StartNamed err = %v, want ErrListenerExists", err)
	}

	statuses := c.ListenerStatuses()
	if len(statuses) != 2 {
		t.Errorf("statuses = %d, want 2", len(statuses))
	}
	if got := c.ListenerCount(); got != 2 {
		t.Errorf("ListenerCount = %d, want 2", got)
	}

	if err := c.StopNamed(ctx, "a"); err != nil {
		t.Errorf("StopNamed a: %v", err)
	}
	if err := c.StopNamed(ctx, "missing"); !errors.Is(err, ErrListenerNotFound) {
		t.Errorf("stop missing err = %v, want ErrListenerNotFound", err)
	}

	if err := c.StopAll(ctx); err != nil {
		t.Errorf("StopAll: %v", err)
	}
	if got := c.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}

// waitFor repeatedly calls cond until it returns true or timeout expires.
// It is a lightweight helper to avoid arbitrary sleeps in listener tests.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %v", timeout)
}
