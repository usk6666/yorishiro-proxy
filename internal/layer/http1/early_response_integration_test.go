//go:build e2e && !e2e_smoke

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// USK-1415: the upstream answers before the request body was written in
// full. Driven through the CONNECT MITM harness; the helpers live in
// request_body_streaming_smoke_integration_test.go and
// body_streaming_smoke_integration_test.go.

const early413 = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\nConnection: close\r\n\r\ntoo large"

// resetUpstreamConn closes c with SO_LINGER 0, so the peer sees an RST.
func resetUpstreamConn(c net.Conn) {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

// waitSessionDone waits for the harness's connection to end.
func waitSessionDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for the proxy session to end")
	}
}

// assertConnEndedWithin reads br until the proxy ends the connection,
// bounded by d, and returns what was read. A timeout fails the test: the
// proxy kept the connection open.
func assertConnEndedWithin(t *testing.T, conn net.Conn, br *bufio.Reader, d time.Duration) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(br)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("client connection still open %v later (read %q); want it ended by the proxy", d, b)
		}
		// ECONNRESET also ends the connection.
	}
	return b
}

// TestHTTP1_EarlyResponse_BufferedBodyWriteReset (T1): a buffered request
// whose body the upstream stops reading after 64 KiB — it answers 413 with
// Connection: close and resets the connection while the proxy is still
// writing the body. The client receives the 413, the Stream completes, the
// 413 is recorded and the send flow carries the whole body.
func TestHTTP1_EarlyResponse_BufferedBodyWriteReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readRequestHeadRaw(br); err != nil {
			return
		}
		if _, err := readFullWithin(c, br, 64<<10); err != nil {
			return
		}
		_, _ = io.WriteString(c, early413)
		resetUpstreamConn(c)
	})
	proxyAddr, store, sessionDone := startStreamingProxy(t, ctx, target, proxyOpts{
		bodySpillDir:       t.TempDir(),
		bodySpillThreshold: 1 << 20,
		maxBodySize:        64 << 20,
	})

	body := bytes.Repeat([]byte("B"), 32<<20)
	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	go func() {
		_, _ = fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, len(body))
		_, _ = conn.Write(body)
	}()
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	head, err := readRequestHeadRaw(br)
	if err != nil {
		t.Fatalf("client read %q, then %v; want the upstream's 413", head, err)
	}
	if !strings.HasPrefix(head, "HTTP/1.1 413 ") {
		t.Fatalf("client response head = %q, want 413", head)
	}
	if got := readExactlyFromWithin(t, conn, br, 9); string(got) != "too large" {
		t.Errorf("client response body = %q, want %q", got, "too large")
	}
	_ = conn.Close()
	waitSessionDone(t, sessionDone)

	if st, _ := streamSnapshot(store, ""); st.State != "complete" {
		t.Errorf("Stream state = %q, want complete (the response arrived)", st.State)
	}
	var got413 bool
	for _, fl := range waitFlowsByDirection(t, store, "receive", 1) {
		if fl.StatusCode == 413 {
			got413 = true
		}
	}
	if !got413 {
		t.Error("the 413 response was not recorded")
	}
	send := waitFlowsByDirection(t, store, "send", 1)
	if len(send[0].Body) != len(body) {
		t.Errorf("send flow body = %d bytes (truncated %v), want the whole %d-byte body", len(send[0].Body), send[0].BodyTruncated, len(body))
	}
}

// TestHTTP1_EarlyResponse_StreamedNonReusableStopsForwarding (T4, the
// owner's reading of T12): a streamed request; the upstream reads the head
// and the first fragment, then answers 413 with Connection: close. The
// client — still holding its second fragment — receives the 413 and then
// its connection is closed by the proxy. The Stream completes, the send
// flow is saved and the upstream received exactly the head and the first
// fragment.
func TestHTTP1_EarlyResponse_StreamedNonReusableStopsForwarding(t *testing.T) {
	tests := []struct {
		name          string
		upstreamClose bool
	}{
		{"upstream keeps the connection open", false},
		{"upstream closes after the 413", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			frag1 := bytes.Repeat([]byte("1"), 4096)
			type upResult struct {
				head  string
				first []byte
				extra int64
				err   error
			}
			upDone := make(chan upResult, 1)
			got1 := newGate()
			target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
				var res upResult
				defer func() { upDone <- res }()
				if res.head, res.err = readRequestHeadRaw(br); res.err != nil {
					return
				}
				if res.first, res.err = readFullWithin(c, br, len(frag1)); res.err != nil {
					return
				}
				_, _ = io.WriteString(c, early413)
				got1.open()
				if tt.upstreamClose {
					return
				}
				// Keep the connection open and count anything more the
				// proxy forwards, until the proxy closes it.
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				res.extra, _ = io.Copy(io.Discard, br)
			})
			proxyAddr, store, sessionDone := startRequestStreamingProxy(t, ctx, target, proxyOpts{})

			conn := connectThroughProxy(t, proxyAddr, target)
			defer conn.Close()
			head := fmt.Sprintf("PUT /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, len(frag1)+1<<20)
			if _, err := io.WriteString(conn, head); err != nil {
				t.Fatalf("write head: %v", err)
			}
			if _, err := conn.Write(frag1); err != nil {
				t.Fatalf("write fragment 1: %v", err)
			}
			if !got1.wait() {
				t.Fatal("the upstream did not receive the first fragment")
			}
			br := bufio.NewReader(conn)
			if got := readHeadWithin(t, conn, br); !strings.HasPrefix(got, "HTTP/1.1 413 ") {
				t.Fatalf("client response head = %q, want 413", got)
			}
			// The client holds fragment 2: the proxy must end the connection.
			if rest := assertConnEndedWithin(t, conn, br, 10*time.Second); string(rest) != "too large" {
				t.Errorf("client read %q after the head, want the 413 body then the end", rest)
			}
			waitSessionDone(t, sessionDone)

			select {
			case res := <-upDone:
				if res.err != nil {
					t.Fatalf("upstream read: %v", res.err)
				}
				if res.head != head || !bytes.Equal(res.first, frag1) || res.extra != 0 {
					t.Errorf("upstream received head %v, fragment 1 %v, %d bytes more; want exactly the head and fragment 1",
						res.head == head, bytes.Equal(res.first, frag1), res.extra)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("upstream handler did not finish")
			}
			if st, _ := streamSnapshot(store, ""); st.State != "complete" {
				t.Errorf("Stream state = %q, want complete", st.State)
			}
			waitFlowsByDirection(t, store, "send", 1)
			var got413 bool
			for _, fl := range waitFlowsByDirection(t, store, "receive", 1) {
				got413 = got413 || fl.StatusCode == 413
			}
			if !got413 {
				t.Error("the 413 response was not recorded")
			}
		})
	}
}

// TestHTTP1_EarlyResponse_UpstreamClosesWithoutResponse (T5): the upstream
// reads part of the body and closes without answering — with an RST or a
// FIN, for a streamed and a buffered request. The Stream ends in error, the
// client receives no response bytes and its connection is closed.
func TestHTTP1_EarlyResponse_UpstreamClosesWithoutResponse(t *testing.T) {
	tests := []struct {
		name     string
		streamed bool
		reset    bool
	}{
		{"streamed RST", true, true},
		{"streamed FIN", true, false},
		{"buffered RST", false, true},
		{"buffered FIN", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
				if _, err := readRequestHeadRaw(br); err != nil {
					return
				}
				if _, err := readFullWithin(c, br, 64<<10); err != nil {
					return
				}
				if tt.reset {
					resetUpstreamConn(c)
				}
			})
			opts := proxyOpts{bodySpillDir: t.TempDir(), bodySpillThreshold: 1 << 20, maxBodySize: 64 << 20}
			start := startStreamingProxy
			if tt.streamed {
				start = startRequestStreamingProxy
			}
			proxyAddr, store, sessionDone := start(t, ctx, target, opts)

			body := bytes.Repeat([]byte("N"), 8<<20)
			conn := connectThroughProxy(t, proxyAddr, target)
			defer conn.Close()
			go func() {
				_, _ = fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, len(body))
				_, _ = conn.Write(body)
			}()
			br := bufio.NewReader(conn)
			if got := assertConnEndedWithin(t, conn, br, 20*time.Second); len(got) != 0 {
				t.Errorf("client received %q, want no response", got)
			}
			waitSessionDone(t, sessionDone)
			if st, _ := streamSnapshot(store, ""); st.State != "error" {
				t.Errorf("Stream state = %q, want error (no response arrived)", st.State)
			}
		})
	}
}

// TestHTTP1_EarlyResponse_ReusableKeepsForwarding (T8, R13): the upstream
// answers 413 after the first fragment without Connection: close and keeps
// reading. The proxy forwards the whole body, the client gets the 413, the
// Stream completes and the client connection carries a second request.
func TestHTTP1_EarlyResponse_ReusableKeepsForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	frag1 := bytes.Repeat([]byte("1"), 4096)
	frag2 := bytes.Repeat([]byte("2"), 4096)
	got1 := newGate()
	upBody := make(chan []byte, 1)
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readRequestHeadRaw(br); err != nil {
			return
		}
		first, err := readFullWithin(c, br, len(frag1))
		if err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\n\r\ntoo large")
		got1.open()
		rest, err := readFullWithin(c, br, len(frag2))
		upBody <- append(first, rest...)
		if err != nil {
			return
		}
		if _, err := readRequestHeadRaw(br); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	proxyAddr, store, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, len(frag1)+len(frag2))
	if _, err := conn.Write(frag1); err != nil {
		t.Fatalf("write fragment 1: %v", err)
	}
	if !got1.wait() {
		t.Fatal("the upstream did not receive the first fragment")
	}
	br := bufio.NewReader(conn)
	if got := readHeadWithin(t, conn, br); !strings.HasPrefix(got, "HTTP/1.1 413 ") {
		t.Fatalf("client response head = %q, want 413", got)
	}
	readExactlyFromWithin(t, conn, br, 9)
	if _, err := conn.Write(frag2); err != nil {
		t.Fatalf("write fragment 2: %v", err)
	}
	select {
	case got := <-upBody:
		if !bytes.Equal(got, append(append([]byte(nil), frag1...), frag2...)) {
			t.Errorf("upstream body = %d bytes, want the whole %d-byte body", len(got), len(frag1)+len(frag2))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("upstream did not receive the rest of the body")
	}
	waitStreamState(t, store, "complete")

	fmt.Fprintf(conn, "GET /second HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	if got := readHeadWithin(t, conn, br); !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("second response head = %q, want 200 on the same client connection", got)
	}
}
