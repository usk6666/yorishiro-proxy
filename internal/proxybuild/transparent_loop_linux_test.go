//go:build linux

package proxybuild

import (
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// T16 (USK-1316, decision R4): when the proxy's own upstream dial is
// REDIRECTed back to the transparent listener (an nftables rule without a
// UID / cgroup exclusion), the looped connection is recognised — its
// remote address is the local address of a live upstream socket the
// transparent handler dialed — and rejected with a Warn, instead of
// chaining hops until max_connections.
//
// The loop is simulated without NAT: the listener is bound to 0.0.0.0,
// and the fake resolver names the next 127.0.0.0/8 address on the same
// port as the original destination (never the connection's own local
// address, so the self-address check does not fire). Dialing it reaches
// the listener again, like a REDIRECT would.
func TestBuildLiveStack_Transparent_OwnDialLoopRejected(t *testing.T) {
	var accepts atomic.Int32
	resolver := connector.OriginalDstFunc(func(c net.Conn) (netip.AddrPort, error) {
		accepts.Add(1)
		local := netip.MustParseAddrPort(c.LocalAddr().String())
		next := local.Addr().Unmap().As4()
		next[3]++
		return netip.AddrPortFrom(netip.AddrFrom4(next), local.Port()), nil
	})
	stack, logs := startTransparentUnitStack(t, "0.0.0.0:0", resolver)
	_, port, _ := net.SplitHostPort(stack.Listener.Addr())

	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET /loop HTTP/1.1\r\nHost: loop.test\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The looped leg is closed, which ends the client's connection: the
	// client sees a close (or the 502-free RST), never a hop chain.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("client connection still open after 10s (accepts = %d)", accepts.Load())
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for !(logs.Contains("level=WARN") && logs.Contains("transparent loop")) {
		if time.Now().After(deadline) {
			t.Fatalf("no Warn \"transparent loop\"; log:\n%s", logs.Output())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Settle: the listener's active connections drain to zero once both
	// legs are closed; no further hop may have been accepted.
	for stack.Listener.ActiveConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("connections did not drain (active %d)", stack.Listener.ActiveConnections())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := accepts.Load(); n != 2 {
		t.Errorf("listener accepted %d connections, want 2 (the client and one looped dial)", n)
	}
}
