//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// USK-1229 review round 1 (exhaustive tier). Shared helpers live in
// h1_upstream_eof_smoke_integration_test.go and
// tcp_forward_grpcweb_integration_test.go.

// TestProxybuild_MITM_H1HEADThenUpstreamClose_RecordedComplete covers F-1:
// a HEAD response carries no body whatever its framing headers declare
// (RFC 9112 §6.3), so an upstream that answers HEAD and closes has
// answered completely — the exchange is recorded complete with no
// TruncatedBody anomaly and the client connection stays usable for the
// next request, which is answered on a redialed upstream connection.
func TestProxybuild_MITM_H1HEADThenUpstreamClose_RecordedComplete(t *testing.T) {
	cases := []struct{ name, headReply string }{
		{name: "content-length", headReply: "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"},
		{name: "chunked", headReply: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
	}
	const secondReply = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startUSK1229Upstream(t, true, func(idx int, c net.Conn, br *bufio.Reader) {
				if _, err := usk1229ReadHead(br); err != nil {
					return
				}
				if idx == 1 {
					_, _ = io.WriteString(c, tc.headReply)
					time.Sleep(50 * time.Millisecond)
					return // close after answering HEAD
				}
				_, _ = io.WriteString(c, secondReply)
				time.Sleep(500 * time.Millisecond)
			})
			store, proxyAddr := startUSK1229MITM(t, ctx, nil)
			c, br := usk1229DialMITM(t, proxyAddr, up.Addr())
			host := "Host: " + up.Addr() + "\r\n"

			if _, err := c.Write([]byte("HEAD /h HTTP/1.1\r\n" + host + "\r\n")); err != nil {
				t.Fatalf("write HEAD: %v", err)
			}
			usk1229ReadExact(t, br, tc.headReply)

			st := usk1229WaitStream(store, 5*time.Second)
			if st == nil {
				t.Fatalf("no Stream reached a terminal state; streams=%+v", store.Streams())
			}
			if st.State != "complete" {
				t.Errorf("HEAD Stream.State = %q (failure_reason=%q, error tag=%q), want complete",
					st.State, st.FailureReason, usk1229ErrorTag(store, st.ID))
			}
			recv := usk1229FlowsFor(store, st.ID, "receive")
			if len(recv) == 0 {
				t.Fatalf("no receive flow recorded for stream %s", st.ID)
			}
			if v, ok := recv[0].Metadata["http_anomaly_truncated_body"]; ok {
				t.Errorf("HEAD receive flow carries http_anomaly_truncated_body=%q; a HEAD response has no body", v)
			}

			time.Sleep(100 * time.Millisecond) // let the upstream FIN land
			if _, err := c.Write([]byte("GET /2 HTTP/1.1\r\n" + host + "\r\n")); err != nil {
				t.Fatalf("write GET after HEAD: %v", err)
			}
			usk1229ReadExact(t, br, secondReply)
		})
	}
}

// TestProxybuild_MITM_H1HEADKeepAlive_SecondRequestSameConn covers F-1 on a
// keep-alive upstream: the response after a HEAD response is not swallowed
// as the HEAD response's body, so the second request is answered on the
// same upstream connection.
func TestProxybuild_MITM_H1HEADKeepAlive_SecondRequestSameConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const headReply = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	const getReply = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	up := startUSK1229Upstream(t, true, func(_ int, c net.Conn, br *bufio.Reader) {
		for {
			target, err := usk1229ReadHead(br)
			if err != nil {
				return
			}
			reply := getReply
			if target == "/h" {
				reply = headReply
			}
			if _, err := io.WriteString(c, reply); err != nil {
				return
			}
		}
	})
	_, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())
	host := "Host: " + up.Addr() + "\r\n"

	if _, err := c.Write([]byte("HEAD /h HTTP/1.1\r\n" + host + "\r\n")); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}
	usk1229ReadExact(t, br, headReply)
	if _, err := c.Write([]byte("GET /g HTTP/1.1\r\n" + host + "\r\n")); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	usk1229ReadExact(t, br, getReply)
	if n := up.ConnCount(); n != 1 {
		t.Errorf("upstream connections = %d, want 1 (keep-alive reuse after HEAD)", n)
	}
}

// TestProxybuild_TCPForward_H1GRPCWeb_TruncatedThenKeepAlive_ClosesClient
// covers F-2 / S-1: on tcp_forwards (one upstream conn, no redial chain) a
// gRPC-Web upstream that cuts its response body and closes must end the
// client connection promptly, even when the client sends a second
// keep-alive request — it must not be queued on the dead upstream Layer,
// where it would wait forever and pin a goroutine, an fd and a
// MaxConnections slot.
func TestProxybuild_TCPForward_H1GRPCWeb_TruncatedThenKeepAlive_ClosesClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const ct = "application/grpc-web+proto"
	up := startUSK1229Upstream(t, false, func(_ int, c net.Conn, br *bufio.Reader) {
		hdr, err := readH1Headers(br)
		if err != nil {
			return
		}
		if cl, _ := strconv.Atoi(strings.TrimSpace(hdr["content-length"])); cl > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
				return
			}
		}
		// One complete data LPM, then close well short of Content-Length.
		lpm := buildLPMBody([]byte("hello!!"))
		_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: 100\r\n\r\n", ct)
		_, _ = c.Write(lpm)
		// Half-close: the proxy sees the body end (EOF) while the socket
		// still accepts writes, so a request sent afterwards is neither
		// answered nor rejected with a reset — a hostile target's shape.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, br)
	})
	mgr, fwdAddr, store := startH1ForwardListener(t, ctx, up.Addr())

	c, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)

	body := buildLPMBody([]byte("ping"))
	req := fmt.Sprintf("POST /hello.HelloService/SayHello HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		fwdAddr, ct, len(body), body)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write request 1: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // the truncated response is relayed
	start := time.Now()
	_, _ = c.Write([]byte(req)) // second keep-alive request; may fail if already closed
	usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second)

	upd, ok := usk1229CaptureFinalState(store, 5*time.Second)
	if !ok {
		t.Fatal("no Stream reached a terminal state")
	}
	if upd.State != "error" {
		t.Errorf("Stream final State = %q (failure_reason=%q), want error (the upstream cut its response)", upd.State, upd.FailureReason)
	}

	// No exchange goroutine may still be parked on the dead upstream: the
	// listener must stop promptly.
	stopped := make(chan struct{})
	go func() { _ = mgr.StopAll(context.Background()); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("StopAll still blocked 3s after the client conn closed; an exchange goroutine leaked")
	}
}
