//go:build e2e

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1409: HTTP/1.x response body streaming, driven through the CONNECT
// MITM harness with the production body-mode predicate
// (proxybuild.NewHTTPBodyModeFunc) built from the harness's own engines.
// The upstreams below are gated: they send part of a body and then wait
// for the test to open a gate, so "the client received the first fragment
// before the upstream sent the rest" is observed without sleeps.

// bodyModeFor returns the production predicate over opts' engines.
func bodyModeFor(opts proxyOpts) layer.BodyModeFunc {
	return proxybuild.NewHTTPBodyModeFunc(proxybuild.HTTPBodyModeEngines{
		Safety:    opts.safetyEngine,
		Intercept: opts.interceptEngine,
		Transform: opts.transformEngine,
	})
}

// gate is a one-shot signal the test opens once.
type gate struct {
	ch   chan struct{}
	once sync.Once
}

func newGate() *gate { return &gate{ch: make(chan struct{})} }

func (g *gate) open() { g.once.Do(func() { close(g.ch) }) }

// wait reports whether the gate opened within 15s.
func (g *gate) wait() bool {
	select {
	case <-g.ch:
		return true
	case <-time.After(15 * time.Second):
		return false
	}
}

// startGatedUpstream starts a TLS upstream running serve on every accepted
// connection. accepts counts the accepted connections.
func startGatedUpstream(t *testing.T, serve func(c net.Conn, br *bufio.Reader)) (target string, accepts *atomic.Int32) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newTestTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				serve(c, bufio.NewReader(c))
			}()
		}
	}()
	return ln.Addr().String(), accepts
}

// readHeadWithin reads a response header section (through the blank line)
// from br, bounded by 5s.
func readHeadWithin(t *testing.T, conn net.Conn, br *bufio.Reader) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			t.Fatalf("read response head (so far %q): %v", head.String(), err)
		}
		if line == "\r\n" {
			return head.String()
		}
	}
}

// readExactlyFromWithin reads exactly n bytes from br, bounded by 5s.
func readExactlyFromWithin(t *testing.T, conn net.Conn, br *bufio.Reader, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	b := make([]byte, n)
	if got, err := io.ReadFull(br, b); err != nil {
		t.Fatalf("read %d bytes: got %d: %v", n, got, err)
	}
	return b
}

// streamSnapshot returns a copy of the Stream with ID id (or the only
// Stream when id is ""), read under the store lock.
func streamSnapshot(store *testStore, id string) (flow.Stream, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, st := range store.streams {
		if id == "" || st.ID == id {
			return *st, true
		}
	}
	return flow.Stream{}, false
}

// waitStreamState polls until a Stream reaches state want.
func waitStreamState(t *testing.T, store *testStore, want string) flow.Stream {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		store.mu.Lock()
		for _, st := range store.streams {
			if st.State == want {
				out := *st
				store.mu.Unlock()
				return out
			}
		}
		store.mu.Unlock()
		if time.Now().After(deadline) {
			st, _ := streamSnapshot(store, "")
			t.Fatalf("no Stream reached state %q within 10s (first stream: %+v)", want, st)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitFlowsByDirection polls until at least n flows with dir exist.
func waitFlowsByDirection(t *testing.T, store *testStore, dir string, n int) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := store.flowsByDirection(dir); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q flows = %d within 10s, want >= %d", dir, len(store.flowsByDirection(dir)), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startStreamingProxy(t *testing.T, ctx context.Context, target string, opts proxyOpts) (string, *testStore, <-chan struct{}) {
	t.Helper()
	opts.responseBodyMode = bodyModeFor(opts)
	return startHTTPMITMProxy(t, ctx, target, opts)
}

// TestSmoke_HTTP1_ResponseBodyStreaming_ContentLength (USK-1409 T6): with
// no rule matching, the first fragment of a Content-Length body reaches
// the client before the upstream sends the rest.
func TestSmoke_HTTP1_ResponseBodyStreaming_ContentLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body := makeSmokeBody(8192)
	g := newGate()
	defer g.open()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = c.Write(body[:4096])
		if !g.wait() {
			return
		}
		_, _ = c.Write(body[4096:])
	})
	proxyAddr, _, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /stream HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	br := bufio.NewReader(conn)
	head := readHeadWithin(t, conn, br)
	if !strings.HasPrefix(head, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("head = %q", head)
	}
	first := readExactlyFromWithin(t, conn, br, 4096)
	g.open()
	rest := readExactlyFromWithin(t, conn, br, 4096)
	if !bytes.Equal(append(first, rest...), body) {
		t.Fatal("client body differs from the upstream body")
	}
}

// TestSmoke_HTTP1_ResponseBodyStreaming_ChunkedByteIdentical (USK-1409 T7):
// a chunked body reaches the client byte-identical to what the upstream
// sent — chunk extensions and the trailer section included — and the first
// chunk arrives before the terminal chunk was sent.
func TestSmoke_HTTP1_ResponseBodyStreaming_ChunkedByteIdentical(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data := makeSmokeBody(4096 + 2048)
	chunk1 := append([]byte("1000;ext=a\r\n"), data[:4096]...)
	chunk1 = append(chunk1, "\r\n"...)
	rest := append([]byte("800;q=\"x y\"\r\n"), data[4096:]...)
	rest = append(rest, "\r\n0;end\r\nX-Checksum: 42\r\n\r\n"...)
	g := newGate()
	defer g.open()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n"))
		_, _ = c.Write(chunk1)
		if !g.wait() {
			return
		}
		_, _ = c.Write(rest)
	})
	proxyAddr, _, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /chunked HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	br := bufio.NewReader(conn)
	head := readHeadWithin(t, conn, br)
	if !strings.Contains(head, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("head = %q, want the upstream's chunked framing", head)
	}
	gotFirst := readExactlyFromWithin(t, conn, br, len(chunk1))
	if !bytes.Equal(gotFirst, chunk1) {
		t.Fatalf("first chunk on the client wire = %q..., want byte-identical %q...", gotFirst[:16], chunk1[:16])
	}
	g.open()
	gotRest := readExactlyFromWithin(t, conn, br, len(rest))
	if !bytes.Equal(gotRest, rest) {
		t.Fatalf("rest of the chunked body differs: got tail %q, want tail %q",
			gotRest[len(gotRest)-32:], rest[len(rest)-32:])
	}
}
