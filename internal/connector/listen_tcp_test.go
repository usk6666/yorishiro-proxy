package connector

import (
	"net"
	"testing"
	"time"
)

// TestListenTCP_IPv4WildcardStaysIPv4 verifies that "0.0.0.0" binds the
// IPv4 wildcard only. Go's net.Listen("tcp", "0.0.0.0:p") opens a
// dual-stack socket, which would also expose the listener on every IPv6
// address — wider than the operator wrote, and invisible to IPv4-only
// firewall rules.
func TestListenTCP_IPv4WildcardStaysIPv4(t *testing.T) {
	ln, err := ListenTCP("0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind 0.0.0.0 in this environment: %v", err)
	}
	defer ln.Close()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr().String(), err)
	}
	if host != "0.0.0.0" {
		t.Errorf("bound host = %q, want 0.0.0.0", host)
	}

	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return // no IPv6 loopback; the reachability half is not applicable
	}
	_ = probe.Close()
	conn, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", port), 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Errorf("dial [::1]:%s succeeded; a 0.0.0.0 listener must not accept IPv6", port)
	}
}

// TestListenTCP_Forms checks the bound host for the other accepted forms.
func TestListenTCP_Forms(t *testing.T) {
	tests := []struct {
		addr     string
		wantHost string
	}{
		{addr: "127.0.0.1:0", wantHost: "127.0.0.1"},
		{addr: "localhost:0", wantHost: "127.0.0.1"},
	}
	for _, tt := range tests {
		ln, err := ListenTCP(tt.addr)
		if err != nil {
			t.Fatalf("ListenTCP(%q): %v", tt.addr, err)
		}
		host, _, _ := net.SplitHostPort(ln.Addr().String())
		_ = ln.Close()
		if host != tt.wantHost {
			t.Errorf("ListenTCP(%q) bound host = %q, want %q", tt.addr, host, tt.wantHost)
		}
	}
}
