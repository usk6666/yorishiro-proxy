package connector

import (
	"context"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// TestMaybeDialViaUpstreamProxy_FallsThroughToDirect verifies that when
// ctx carries no upstream-proxy override, MaybeDialViaUpstreamProxy
// dials the target directly via net.Dialer — the behaviour the
// historical resend / fuzz dial path relied on.
func TestMaybeDialViaUpstreamProxy_FallsThroughToDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Bool
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted.Store(true)
			_ = c.Close()
		}
	}()

	conn, err := MaybeDialViaUpstreamProxy(context.Background(), ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	// Give the accept goroutine a moment to record the connection.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !accepted.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !accepted.Load() {
		t.Fatal("target listener did not observe the direct dial")
	}
}

// TestMaybeDialViaUpstreamProxy_DirectWhenOverrideIsExplicitNil verifies
// the explicit nil override semantics: ctx carries an override marker but
// no URL, so the helper falls through to a direct dial rather than
// returning an error.
func TestMaybeDialViaUpstreamProxy_DirectWhenOverrideIsExplicitNil(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	ctx := ContextWithUpstreamProxyOverride(context.Background(), nil)
	conn, err := MaybeDialViaUpstreamProxy(ctx, ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// TestMaybeDialViaUpstreamProxy_HTTPProxyCONNECT verifies that a
// ctx-attached HTTP proxy URL drives the dial through HTTP CONNECT. A
// minimal in-process CONNECT proxy accepts the tunnel and bridges to
// the target listener so the test exercises the full handshake path.
func TestMaybeDialViaUpstreamProxy_HTTPProxyCONNECT(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer target.Close()

	var targetSawHello atomic.Bool
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		_, _ = c.Read(buf)
		if string(buf) == "hello" {
			targetSawHello.Store(true)
		}
	}()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxy.Close()

	var observedAuth atomic.Value
	observedAuth.Store("")
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read CONNECT request headers.
		header := make([]byte, 0, 512)
		buf := make([]byte, 1)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			header = append(header, buf[0])
			if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
				break
			}
		}
		// Surface Proxy-Authorization for the assertion.
		const needle = "Proxy-Authorization: "
		if idx := indexOf(string(header), needle); idx >= 0 {
			rest := string(header[idx+len(needle):])
			if eol := indexOf(rest, "\r\n"); eol >= 0 {
				observedAuth.Store(rest[:eol])
			}
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			return
		}

		// Bridge the tunnel to the target.
		upstream, err := net.Dial("tcp", target.Addr().String())
		if err != nil {
			return
		}
		defer upstream.Close()

		done := make(chan struct{}, 2)
		copy := func(dst, src net.Conn) {
			b := make([]byte, 1024)
			for {
				n, err := src.Read(b)
				if n > 0 {
					if _, werr := dst.Write(b[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			done <- struct{}{}
		}
		go copy(upstream, conn)
		go copy(conn, upstream)
		<-done
	}()

	proxyURL, _ := url.Parse("http://alice:s3cret@" + proxy.Addr().String())
	ctx := ContextWithUpstreamProxyOverride(context.Background(), proxyURL)

	conn, err := MaybeDialViaUpstreamProxy(ctx, target.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial via proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	// Wait for the target to observe the payload.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !targetSawHello.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !targetSawHello.Load() {
		t.Fatal("target did not receive tunneled payload")
	}

	// Basic Auth: base64("alice:s3cret") = YWxpY2U6czNjcmV0
	got, _ := observedAuth.Load().(string)
	want := "Basic YWxpY2U6czNjcmV0"
	if got != want {
		t.Errorf("Proxy-Authorization header = %q, want %q", got, want)
	}
}

// indexOf is a tiny strings.Index without importing the package — keeps
// this file's imports minimal.
func indexOf(haystack, needle string) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
