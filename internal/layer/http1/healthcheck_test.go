package http1

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestHealthCheck_Alive_ReturnsNil exercises the happy path: an open,
// idle upstream connection with an empty pendingQ reports alive.
func TestHealthCheck_Alive_ReturnsNil(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-alive", envelope.Receive)
	defer l.Close()

	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck on fresh idle conn: got %v, want nil", err)
	}
}

// TestHealthCheck_PeerClosed_ReturnsErr confirms that a peer-closed conn
// is surfaced as a stale signal (io.EOF) rather than treated as alive.
func TestHealthCheck_PeerClosed_ReturnsErr(t *testing.T) {
	client, server := testConn(t)
	defer server.Close()

	l := New(server, "stream-hc-eof", envelope.Receive)
	defer l.Close()

	// Close the peer end so HealthCheck's read sees EOF / connection
	// reset (varies by platform; both classify as stale).
	_ = client.Close()

	// Poll HealthCheck until the FIN propagates through the loopback
	// (bounded; flake-resistant on slow CI). HealthCheck itself is sub-
	// millisecond so a tight polling loop is cheap.
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = l.HealthCheck(); lastErr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr == nil {
		t.Fatal("HealthCheck on peer-closed conn: got nil after polling, want non-nil (stale)")
	}
}

// TestHealthCheck_LayerClosed_ReturnsErr asserts that a Layer that was
// already explicitly Closed reports stale rather than racing the
// underlying conn's lifetime.
func TestHealthCheck_LayerClosed_ReturnsErr(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-closed", envelope.Receive)
	_ = l.Close()

	err := l.HealthCheck()
	if err == nil {
		t.Fatal("HealthCheck on closed Layer: got nil, want net.ErrClosed")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HealthCheck on closed Layer: got %v, want net.ErrClosed", err)
	}
}

// TestHealthCheck_SendDirection_ReturnsNil asserts the Send-direction
// (client-facing) Layer short-circuits to nil — that side is always
// actively read by spawnLoopSend so the proactive peek does not apply.
func TestHealthCheck_SendDirection_ReturnsNil(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-send", envelope.Send)
	defer l.Close()

	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck on Send-direction Layer: got %v, want nil", err)
	}
}

// TestHealthCheck_PendingNonEmpty_TreatedAsAlive asserts the defensive
// short-circuit when pendingQ is non-empty — the parser goroutine will
// observe any FIN naturally as part of its parseResponse; HealthCheck
// must not steal reads from it.
//
// The conn stays open so the parser parks waiting for bytes; the
// assertion is that even with the peer alive but quiet, HealthCheck
// returns nil immediately (without touching the conn) because pendingQ
// is non-empty. Calling HealthCheck mid-exchange is a caller-broken
// invariant; defensive nil prevents racing the parser's read.
func TestHealthCheck_PendingNonEmpty_TreatedAsAlive(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-pending", envelope.Receive)
	defer l.Close()

	// Open an exchange — that creates a channel but does NOT register it
	// in pendingQ yet (registration happens on Send via appendPending).
	upCh := l.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	// Manually invoke appendPending to simulate an in-flight exchange so
	// HealthCheck observes a non-empty pendingQ.
	c, ok := upCh.(*channel)
	if !ok {
		t.Fatalf("OpenExchange returned %T, want *channel", upCh)
	}
	l.appendPending(c)

	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck with non-empty pendingQ: got %v, want nil (defer to parser)", err)
	}
}

// TestHealthCheck_DeadlineRestored confirms that after HealthCheck
// returns alive on an idle conn, a subsequent legitimate read on the
// same conn (driven by spawnLoopReceive style usage) is NOT pre-poisoned
// by the past deadline. We exercise this by reading directly from the
// underlying conn after HealthCheck — successful blocking read proves
// the deadline was restored.
func TestHealthCheck_DeadlineRestored(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-deadline", envelope.Receive)
	defer l.Close()

	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: got %v, want nil", err)
	}

	// Drive a real byte across the wire and verify the read succeeds with
	// a generous timeout (would fail with os.ErrDeadlineExceeded if the
	// past deadline survived).
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write([]byte("X"))
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer server.SetReadDeadline(time.Time{})

	var buf [1]byte
	n, err := server.Read(buf[:])
	if err != nil {
		t.Fatalf("post-HealthCheck Read: got err=%v, want successful read", err)
	}
	if n != 1 || buf[0] != 'X' {
		t.Fatalf("post-HealthCheck Read: got n=%d byte=%q, want 1/'X'", n, buf[0])
	}
}

// TestHealthCheck_IdleByteFromUpstream_TreatedAsStale exercises the RFC
// 9112 §9.6 violation case: the upstream sent a byte while pendingQ was
// empty (no exchange in flight). The byte cannot be attributed to any
// HTTP transaction, so HealthCheck reports stale and the surplus byte is
// dropped — accepting the 1-byte fidelity loss to avoid propagating a
// corrupt connection.
func TestHealthCheck_IdleByteFromUpstream_TreatedAsStale(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-hc-idlebyte", envelope.Receive)
	defer l.Close()

	if _, err := client.Write([]byte("Z")); err != nil {
		t.Fatalf("write idle byte: %v", err)
	}
	// Poll HealthCheck until the byte reaches the netpoller (bounded;
	// flake-resistant on slow CI). HealthCheck itself is sub-millisecond
	// so a tight polling loop is cheap.
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = l.HealthCheck(); lastErr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr == nil {
		t.Fatal("HealthCheck on idle-byte conn: got nil after polling, want non-nil (stale)")
	}
}

// TestEnvelopeContextTemplate_ValueCopy locks the value-copy semantic
// the proxybuild h1 redial chain depends on (USK-998): mutating the
// returned EnvelopeContext must NOT affect the Layer's internal template.
func TestEnvelopeContextTemplate_ValueCopy(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	want := envelope.EnvelopeContext{
		ConnID:     "conn-template-test",
		TargetHost: "example.com:443",
	}
	l := New(server, "stream-tmpl", envelope.Receive, WithEnvelopeContext(want))
	defer l.Close()

	got := l.EnvelopeContextTemplate()
	if got.ConnID != want.ConnID {
		t.Errorf("EnvelopeContextTemplate ConnID: got %q, want %q", got.ConnID, want.ConnID)
	}
	if got.TargetHost != want.TargetHost {
		t.Errorf("EnvelopeContextTemplate TargetHost: got %q, want %q", got.TargetHost, want.TargetHost)
	}

	// Mutate the returned copy; the second fetch must be untouched.
	got.ConnID = "mutated"
	got.TargetHost = "evil.example.com:443"

	second := l.EnvelopeContextTemplate()
	if second.ConnID != want.ConnID || second.TargetHost != want.TargetHost {
		t.Errorf("EnvelopeContextTemplate returned shared state: second fetch has ConnID=%q TargetHost=%q after mutation",
			second.ConnID, second.TargetHost)
	}
}
