package proxybuild

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// T8 (USK-1374): the transparent rate-limit refusal label is the canonical
// BlockedBy vocabulary entry (connector cannot import pipeline).
func TestTransparentBlockedByRateLimit_MatchesPipelineLabel(t *testing.T) {
	if connector.TransparentBlockedByRateLimit != pipeline.BlockedByRateLimit {
		t.Fatalf("connector.TransparentBlockedByRateLimit = %q, want pipeline.BlockedByRateLimit %q",
			connector.TransparentBlockedByRateLimit, pipeline.BlockedByRateLimit)
	}
}

// T7 (USK-1374): Deps.RateLimiter reaches the transparent handler built by
// BuildLiveStack — the connection over a burst-1 limit gets a 429 and the
// upstream sees only the first.
func TestBuildLiveStack_Transparent_RateLimiterWired(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts <- struct{}{}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	dst := netip.MustParseAddrPort(ln.Addr().String())

	deps, _ := transparentUnitDeps(t, "127.0.0.1:0", connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return dst, nil
	}))
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 0.001})
	deps.RateLimiter = rl
	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = stack.Listener.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}

	statusLine := func() string {
		t.Helper()
		c, err := net.Dial("tcp", stack.Listener.Addr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("read status line: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	if got := statusLine(); got != "HTTP/1.1 200 OK" {
		t.Fatalf("first connection: %q, want HTTP/1.1 200 OK", got)
	}
	if got := statusLine(); got != "HTTP/1.1 429 Too Many Requests" {
		t.Errorf("second connection: %q, want HTTP/1.1 429 Too Many Requests", got)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(accepts); n != 1 {
		t.Errorf("upstream accepted %d connections, want 1", n)
	}
}
