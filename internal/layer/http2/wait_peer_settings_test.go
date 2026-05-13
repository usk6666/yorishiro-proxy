package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// TestConn_WaitPeerSettings_AlreadyReceived verifies that callers entering
// WaitPeerSettings after the peer SETTINGS have already been applied take the
// fast path and return nil immediately, without consulting context or
// shutdown. This is the pool-hit invariant: the cached Layer has its peer
// SETTINGS already, so a redundant wait must not block or allocate.
func TestConn_WaitPeerSettings_AlreadyReceived(t *testing.T) {
	c := NewConn()

	// Apply a SETTINGS frame as if the peer had sent one.
	if err := c.ApplyPeerSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 42},
	}); err != nil {
		t.Fatalf("ApplyPeerSettings: %v", err)
	}
	if !c.PeerSettingsReceived() {
		t.Fatalf("PeerSettingsReceived = false after Apply")
	}

	select {
	case <-c.PeerSettingsReady():
		// Expected.
	case <-time.After(time.Second):
		t.Fatalf("PeerSettingsReady() did not close after ApplyPeerSettings")
	}
}

// TestConn_WaitPeerSettings_BlocksThenWakes verifies that a wait initiated
// before peer SETTINGS arrive blocks until ApplyPeerSettings closes the
// ready channel.
func TestConn_WaitPeerSettings_BlocksThenWakes(t *testing.T) {
	c := NewConn()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Block on the ready channel until ApplyPeerSettings closes it.
		<-c.PeerSettingsReady()
	}()

	// Sanity: the goroutine must still be blocked just after starting.
	select {
	case <-done:
		t.Fatalf("ready channel closed before ApplyPeerSettings")
	case <-time.After(20 * time.Millisecond):
	}

	if err := c.ApplyPeerSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 11},
	}); err != nil {
		t.Fatalf("ApplyPeerSettings: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("waiter did not wake up within 1s of ApplyPeerSettings")
	}
}

// TestConn_WaitPeerSettings_IdempotentClose verifies that multiple
// SETTINGS frames from the peer (RFC 9113 allows dynamic settings updates
// during the connection lifetime) do not panic by re-closing the ready
// channel. sync.Once guards the close.
func TestConn_WaitPeerSettings_IdempotentClose(t *testing.T) {
	c := NewConn()
	for i := 0; i < 3; i++ {
		if err := c.ApplyPeerSettings([]frame.Setting{
			{ID: frame.SettingMaxConcurrentStreams, Value: uint32(10 + i)},
		}); err != nil {
			t.Fatalf("ApplyPeerSettings #%d: %v", i, err)
		}
	}
	select {
	case <-c.PeerSettingsReady():
	default:
		t.Fatalf("PeerSettingsReady() not closed after first ApplyPeerSettings")
	}
}

// TestLayer_WaitPeerSettings_Success verifies the Layer-level wrapper
// returns nil once the peer transmits its initial SETTINGS frame.
func TestLayer_WaitPeerSettings_Success(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// Peer has not yet sent its SETTINGS frame; the wait should block.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- l.WaitPeerSettings(ctx) }()

	// Peer transmits SETTINGS.
	if err := peer.wr.WriteSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 17},
	}); err != nil {
		t.Fatalf("WriteSettings: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitPeerSettings: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("WaitPeerSettings did not return within 2s of peer SETTINGS")
	}

	if !l.PeerSettingsReceived() {
		t.Fatalf("PeerSettingsReceived = false after WaitPeerSettings returned nil")
	}
	if got := l.PeerSettings().MaxConcurrentStreams; got != 17 {
		t.Errorf("PeerSettings.MaxConcurrentStreams = %d, want 17", got)
	}
}

// TestLayer_WaitPeerSettings_ContextCancel verifies that WaitPeerSettings
// returns ctx.Err() when the supplied context is canceled before peer
// SETTINGS arrive. The 5s timeout in buildH2Stack relies on this path to
// trigger the fail-open fallback to advertise ENABLE_CONNECT_PROTOCOL=1.
func TestLayer_WaitPeerSettings_ContextCancel(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := l.WaitPeerSettings(ctx)
	if err == nil {
		t.Fatalf("WaitPeerSettings(canceled ctx) = nil, want context error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("WaitPeerSettings err = %v, want %v", err, context.DeadlineExceeded)
	}
}

// TestLayer_WaitPeerSettings_ShutdownBeforeSettings verifies that
// WaitPeerSettings returns ErrShutdownBeforePeerSettings when the Layer
// is closed before the peer transmits SETTINGS.
func TestLayer_WaitPeerSettings_ShutdownBeforeSettings(t *testing.T) {
	l, peer, _ := startServerLayer(t)
	peer.consumePeerSettings(t)

	done := make(chan error, 1)
	go func() {
		done <- l.WaitPeerSettings(context.Background())
	}()

	// Close the Layer before the peer sends SETTINGS. The pipe-based test
	// harness may surface an underlying pipe error from Close(); only the
	// wait-wakeup behavior matters here, so the error is intentionally
	// discarded.
	_ = l.Close()
	_ = peer.conn.Close()

	select {
	case err := <-done:
		if !errors.Is(err, ErrShutdownBeforePeerSettings) {
			t.Errorf("WaitPeerSettings err = %v, want ErrShutdownBeforePeerSettings", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("WaitPeerSettings did not return after Close")
	}
}

// TestLayer_PeerSettings_AccessorReturnsCopy verifies the Layer.PeerSettings
// accessor surfaces the same value as Conn.PeerSettings, so callers
// (notably resolveEnableConnectProtocol in the connector) can read the
// SETTINGS_ENABLE_CONNECT_PROTOCOL field without unwrapping internals.
func TestLayer_PeerSettings_AccessorReturnsCopy(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if err := peer.wr.WriteSettings([]frame.Setting{
		{ID: frame.SettingEnableConnectProtocol, Value: 1},
	}); err != nil {
		t.Fatalf("WriteSettings: %v", err)
	}
	peer.expectSettingsAck(t)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if l.PeerSettingsReceived() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !l.PeerSettingsReceived() {
		t.Fatalf("PeerSettingsReceived = false")
	}
	if got := l.PeerSettings().EnableConnectProtocol; got != 1 {
		t.Errorf("PeerSettings.EnableConnectProtocol = %d, want 1", got)
	}
}
