//go:build e2e

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1414: HTTP/1.x request body streaming, driven through the CONNECT
// MITM harness with the production body-mode predicate
// (proxybuild.NewHTTPBodyModeFunc over the harness's engines) on both the
// request and the response side. The upstreams are gated: they open a gate
// once they received the first body fragment, and the client sends the
// rest only after that, so "the first fragment reached the upstream before
// the client sent the rest" is observed without sleeps.

// startRequestStreamingProxy starts the MITM harness with the production
// predicate threaded into both body-mode seams.
func startRequestStreamingProxy(t *testing.T, ctx context.Context, target string, opts proxyOpts) (string, *testStore, <-chan struct{}) {
	t.Helper()
	opts.requestBodyMode = bodyModeFor(opts)
	return startStreamingProxy(t, ctx, target, opts)
}

// readRequestHeadRaw reads a request header section (through the blank
// line) from br exactly as it arrived.
func readRequestHeadRaw(br *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			return head.String(), err
		}
		if line == "\r\n" {
			return head.String(), nil
		}
	}
}

// readFullWithin reads exactly n bytes from br on c, bounded by 15s.
func readFullWithin(c net.Conn, br *bufio.Reader, n int) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	b := make([]byte, n)
	_, err := io.ReadFull(br, b)
	return b, err
}

// fragmentUpstream is a gated upstream for a request whose body arrives in
// two parts: it reads the head and the first part (firstLen wire bytes),
// opens got1, then reads the rest (restLen wire bytes) and answers 200.
type fragmentUpstream struct {
	got1   *gate
	result chan fragmentResult
}

type fragmentResult struct {
	head        string
	first, rest []byte
	err         error
}

func startFragmentUpstream(t *testing.T, firstLen, restLen int) (string, *fragmentUpstream) {
	t.Helper()
	fu := &fragmentUpstream{got1: newGate(), result: make(chan fragmentResult, 1)}
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		var res fragmentResult
		defer func() { fu.result <- res }()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
		if res.head, res.err = readRequestHeadRaw(br); res.err != nil {
			return
		}
		if res.first, res.err = readFullWithin(c, br, firstLen); res.err != nil {
			return
		}
		fu.got1.open()
		if res.rest, res.err = readFullWithin(c, br, restLen); res.err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	return target, fu
}

// countingUpstream discards and counts every byte its connections read.
type countingUpstream struct {
	accepts *atomic.Int32
	bytes   chan int64
}

func startCountingUpstream(t *testing.T) (string, *countingUpstream) {
	t.Helper()
	cu := &countingUpstream{bytes: make(chan int64, 16)}
	target, accepts := startGatedUpstream(t, func(c net.Conn, _ *bufio.Reader) {
		n, _ := io.Copy(io.Discard, c)
		cu.bytes <- n
	})
	cu.accepts = accepts
	return target, cu
}

// total returns the bytes read over every accepted connection. Call it
// after the proxy session ended (its teardown closes the upstream
// connection the stack dialed).
func (cu *countingUpstream) total(t *testing.T) int64 {
	t.Helper()
	var sum int64
	for i := int32(0); i < cu.accepts.Load(); i++ {
		select {
		case n := <-cu.bytes:
			sum += n
		case <-time.After(10 * time.Second):
			t.Fatal("upstream connection was not closed")
		}
	}
	return sum
}

func (fu *fragmentUpstream) wait(t *testing.T) fragmentResult {
	t.Helper()
	select {
	case r := <-fu.result:
		return r
	case <-time.After(20 * time.Second):
		t.Fatal("upstream handler did not finish")
		return fragmentResult{}
	}
}

// TestSmoke_HTTP1_RequestBodyStreaming_ContentLength (USK-1414 T1): with no
// rule matching, the first fragment of a Content-Length request body
// reaches the upstream before the client sends the rest; the upstream
// receives the client's head and body byte-identical.
func TestSmoke_HTTP1_RequestBodyStreaming_ContentLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	body := makeSmokeBody(8192)
	target, fu := startFragmentUpstream(t, 4096, 4096)
	proxyAddr, _, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	head := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", target, len(body))
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := conn.Write(body[:4096]); err != nil {
		t.Fatalf("write fragment 1: %v", err)
	}
	if !fu.got1.wait() {
		t.Fatal("the upstream did not receive the first body fragment before the client sent the rest (request body buffered)")
	}
	if _, err := conn.Write(body[4096:]); err != nil {
		t.Fatalf("write fragment 2: %v", err)
	}
	br := bufio.NewReader(conn)
	if got := readHeadWithin(t, conn, br); !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("client response head = %q, want 200", got)
	}

	res := fu.wait(t)
	if res.err != nil {
		t.Fatalf("upstream read: %v", res.err)
	}
	if res.head != head {
		t.Errorf("upstream head = %q, want the client's head verbatim %q", res.head, head)
	}
	if !bytes.Equal(append(res.first, res.rest...), body) {
		t.Error("upstream body differs from the client's body")
	}
}

// TestSmoke_HTTP1_RequestBodyStreaming_ChunkedByteIdentical (USK-1414 T2):
// a chunked request body reaches the upstream byte-identical to what the
// client sent — chunk extensions and the trailer section included — and
// the first chunk arrives before the client sent the terminal chunk.
func TestSmoke_HTTP1_RequestBodyStreaming_ChunkedByteIdentical(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	data := makeSmokeBody(4096 + 2048)
	chunk1 := append([]byte("1000;ext=a\r\n"), data[:4096]...)
	chunk1 = append(chunk1, "\r\n"...)
	rest := append([]byte("800;q=\"x y\"\r\n"), data[4096:]...)
	rest = append(rest, "\r\n0;end\r\nX-Checksum: 42\r\n\r\n"...)
	target, fu := startFragmentUpstream(t, len(chunk1), len(rest))
	proxyAddr, _, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	head := fmt.Sprintf("POST /chunked HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n", target)
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := conn.Write(chunk1); err != nil {
		t.Fatalf("write chunk 1: %v", err)
	}
	if !fu.got1.wait() {
		t.Fatal("the upstream did not receive the first chunk before the client sent the rest (request body buffered)")
	}
	if _, err := conn.Write(rest); err != nil {
		t.Fatalf("write rest: %v", err)
	}
	br := bufio.NewReader(conn)
	if got := readHeadWithin(t, conn, br); !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("client response head = %q, want 200", got)
	}

	res := fu.wait(t)
	if res.err != nil {
		t.Fatalf("upstream read: %v", res.err)
	}
	if res.head != head {
		t.Errorf("upstream head = %q, want the client's chunked head verbatim %q", res.head, head)
	}
	if !bytes.Equal(res.first, chunk1) {
		t.Errorf("first chunk on the upstream wire = %q..., want byte-identical %q...", res.first[:16], chunk1[:16])
	}
	if !bytes.Equal(res.rest, rest) {
		t.Errorf("rest of the chunked body differs: got tail %q, want tail %q",
			res.rest[len(res.rest)-32:], rest[len(rest)-32:])
	}
}

// TestSmoke_HTTP1_RequestBodyStreaming_ScopeDenyClosesConnection (USK-1414
// T8): a streamed request denied by HTTPScope is answered 403 (Connection:
// close) without waiting for its body, and the connection then closes. A
// second request carried inside the unsent body is never parsed: the
// upstream reads no byte and only one Stream is recorded.
func TestSmoke_HTTP1_RequestBodyStreaming_ScopeDenyClosesConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	target, up := startCountingUpstream(t)
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "127.0.0.1", PathPrefix: "/allowed/"},
	}, nil)
	proxyAddr, store, sessionDone := startRequestStreamingProxy(t, ctx, target, proxyOpts{scope: scope})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	smuggled := fmt.Sprintf("GET /allowed/smuggled HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	req := fmt.Sprintf("POST /forbidden HTTP/1.1\r\nHost: %s\r\nContent-Length: 100000\r\n\r\n", target) + smuggled
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := readRequestHeadRaw(br)
	if err != nil {
		t.Fatalf("read 403 head within 10s (the proxy waited for the whole body?): got %q: %v", resp, err)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Fatalf("response head = %q, want 403", resp)
	}
	if !strings.Contains(resp, "Connection: close\r\n") {
		t.Errorf("response head = %q, want Connection: close", resp)
	}
	_, err = io.Copy(io.Discard, br)
	if err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open after the 403: %v", err)
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for the session to complete")
	}
	if n := up.total(t); n != 0 {
		t.Errorf("upstream read %d bytes, want 0", n)
	}
	if n := len(store.getStreams()); n != 1 {
		t.Errorf("recorded Streams = %d, want 1 (the request inside the unsent body must never be parsed)", n)
	}
}
