package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1316 T3/T4: the transparent FullListener resolves each accepted
// connection's original destination before reading a byte and rejects
// connections without a usable one.

// transparentProbe records OnTransparent invocations.
type transparentProbe struct {
	mu    sync.Mutex
	calls int
	dst   netip.AddrPort
	ok    bool
	seen  chan struct{}
}

func newTransparentProbe() *transparentProbe {
	return &transparentProbe{seen: make(chan struct{}, 16)}
}

func (p *transparentProbe) handler(ctx context.Context, pc *PeekConn) error {
	dst, ok := OriginalDstFromContext(ctx)
	p.mu.Lock()
	p.calls++
	p.dst, p.ok = dst, ok
	p.mu.Unlock()
	_, _ = pc.Write([]byte("handled\n"))
	p.seen <- struct{}{}
	return pc.Close()
}

func (p *transparentProbe) snapshot() (int, netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.dst, p.ok
}

// startTransparentTestListener starts a transparent FullListener on addr.
func startTransparentTestListener(t *testing.T, addr string, r OriginalDstResolver, probe *transparentProbe) (*FullListener, *testutil.CaptureLogger) {
	t.Helper()
	if probe == nil {
		probe = newTransparentProbe()
	}
	logs, logger := testutil.NewCaptureLogger()
	fl := NewFullListener(FullListenerConfig{
		Name:          "transparent-test",
		Addr:          addr,
		Logger:        logger,
		OriginalDst:   r,
		OnTransparent: probe.handler,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = fl.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}
	return fl, logs
}

// dialPort dials the listener's port on 127.0.0.1.
func dialPort(t *testing.T, fl *FullListener) net.Conn {
	t.Helper()
	_, port, _ := net.SplitHostPort(fl.Addr())
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// expectClosedWithoutResponse asserts the proxy closes conn without
// writing a byte.
func expectClosedWithoutResponse(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(conn)
	if len(b) != 0 {
		t.Fatalf("read %q, want no bytes", b)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection not closed within 5s")
	}
}

// waitLog waits until the captured log contains every substring on one line.
func waitLog(t *testing.T, logs *testutil.CaptureLogger, subs ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, line := range strings.Split(logs.Output(), "\n") {
			all := true
			for _, s := range subs {
				if !strings.Contains(line, s) {
					all = false
					break
				}
			}
			if all {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line with %q; log:\n%s", subs, logs.Output())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFullListener_Transparent_RejectsUnusableOriginalDst(t *testing.T) {
	tests := []struct {
		name     string
		resolver func(c net.Conn) (netip.AddrPort, error)
	}{
		{name: "resolver error", resolver: func(net.Conn) (netip.AddrPort, error) {
			return netip.AddrPort{}, errors.New("ENOENT")
		}},
		{name: "zero value", resolver: func(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, nil }},
		{name: "unspecified IPv4", resolver: func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("0.0.0.0:80"), nil
		}},
		{name: "unspecified IPv6", resolver: func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("[::]:80"), nil
		}},
		{name: "port 0", resolver: func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.0.2.1:0"), nil
		}},
		{name: "own local address", resolver: func(c net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort(c.LocalAddr().String()), nil
		}},
		{name: "own local address v4-mapped", resolver: func(c net.Conn) (netip.AddrPort, error) {
			l := netip.MustParseAddrPort(c.LocalAddr().String())
			return netip.AddrPortFrom(netip.AddrFrom16(l.Addr().As16()), l.Port()), nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe := newTransparentProbe()
			fl, logs := startTransparentTestListener(t, "127.0.0.1:0", OriginalDstFunc(tc.resolver), probe)
			conn := dialPort(t, fl)
			expectClosedWithoutResponse(t, conn)
			waitLog(t, logs, "level=WARN", "remote_addr="+conn.LocalAddr().String())
			if n, _, _ := probe.snapshot(); n != 0 {
				t.Errorf("handler invoked %d times, want 0", n)
			}
		})
	}
}

// Connections without a usable original destination (direct clients,
// health checks, scans) warn at most once per window; the rest log at
// Debug and are counted in the next Warn.
func TestFullListener_Transparent_UnusableOriginalDstWarnRateLimited(t *testing.T) {
	fl, logs := startTransparentTestListener(t, "127.0.0.1:0", OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return netip.AddrPort{}, errors.New("ENOENT")
	}), nil)
	first := dialPort(t, fl)
	expectClosedWithoutResponse(t, first)
	waitLog(t, logs, "level=WARN", "remote_addr="+first.LocalAddr().String())
	second := dialPort(t, fl)
	expectClosedWithoutResponse(t, second)
	waitLog(t, logs, "level=DEBUG", "no usable original destination", "remote_addr="+second.LocalAddr().String())
	if n := strings.Count(logs.Output(), "level=WARN msg=\"transparent connection rejected: no usable original destination\""); n != 1 {
		t.Errorf("%d Warn lines for two rejections within the window, want 1; log:\n%s", n, logs.Output())
	}
}

func TestFullListener_Transparent_AdmittedDstOnContext(t *testing.T) {
	want := netip.MustParseAddrPort("192.0.2.10:8443")
	probe := newTransparentProbe()
	fl, _ := startTransparentTestListener(t, "127.0.0.1:0", OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(netip.AddrFrom16(want.Addr().As16()), want.Port()), nil
	}), probe)
	conn := dialPort(t, fl)
	// The client sends nothing: transparent mode must not wait for
	// protocol detection before handing the connection off.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "handled\n" {
		t.Fatalf("read %q, %v; want the handler's reply", buf, err)
	}
	n, dst, ok := probe.snapshot()
	if n != 1 || !ok || dst != want {
		t.Fatalf("handler calls=%d dst=%v ok=%v, want 1 call with the unmapped %v", n, dst, ok, want)
	}
}
