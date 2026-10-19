//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1229 exhaustive tier. See h1_upstream_eof_smoke_integration_test.go
// for the shared helpers and the merge-gate representative.

const (
	usk1229TruncatedCL      = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"
	usk1229TruncatedChunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\na\r\nabc"
)

// requireUSK1229ErrorStream waits for the exchange's Stream to be finalised
// and asserts it was recorded as an aborted error whose error tag carries
// wantTag.
func requireUSK1229ErrorStream(t *testing.T, store *flowStoreForH2Pool, wantTag string) *flow.Stream {
	t.Helper()
	st := usk1229WaitStream(store, 5*time.Second)
	if st == nil {
		t.Fatalf("no Stream reached a terminal state; streams=%+v", store.Streams())
	}
	if st.Protocol != "http" {
		t.Errorf("Stream.Protocol = %q, want http", st.Protocol)
	}
	if st.State != "error" {
		t.Errorf("Stream.State = %q, want error (the upstream never completed its response)", st.State)
	}
	if st.FailureReason != "aborted" {
		t.Errorf("Stream.FailureReason = %q, want aborted", st.FailureReason)
	}
	if tag := usk1229ErrorTag(store, st.ID); !strings.Contains(tag, wantTag) {
		t.Errorf("tags[error] = %q, want it to contain %q", tag, wantTag)
	}
	return st
}

// usk1229FlowsFor returns the recorded flows of stream id with direction dir.
func usk1229FlowsFor(store *flowStoreForH2Pool, id, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.Flows() {
		if f.StreamID == id && f.Direction == dir {
			out = append(out, f)
		}
	}
	return out
}

// TestProxybuild_MITM_H1UpstreamClosesBeforeResponse_RecordsError covers
// Test Plan #2: the unanswered exchange is recorded as an aborted error,
// and its Send flow keeps the request's wire bytes.
func TestProxybuild_MITM_H1UpstreamClosesBeforeResponse_RecordsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startUSK1229Upstream(t, true, usk1229CloseAfterRequest(200*time.Millisecond))
	store, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())

	req := "GET /hang HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n"
	start := time.Now()
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second)

	st := requireUSK1229ErrorStream(t, store, "before sending a response")
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want https", st.Scheme)
	}
	sends := usk1229FlowsFor(store, st.ID, "send")
	if len(sends) == 0 {
		t.Fatalf("no send flow recorded for stream %s", st.ID)
	}
	if !bytes.Equal(sends[0].RawBytes, []byte(req)) {
		t.Errorf("send flow RawBytes = %q, want the request wire bytes %q", sends[0].RawBytes, req)
	}
	if recv := usk1229FlowsFor(store, st.ID, "receive"); len(recv) != 0 {
		t.Errorf("receive flows = %d, want 0 (the upstream sent nothing)", len(recv))
	}
}

// TestProxybuild_ForwardProxy_H1UpstreamClosesBeforeResponse covers Test
// Plan #3: the plain-HTTP forward proxy (absolute-form) path.
func TestProxybuild_ForwardProxy_H1UpstreamClosesBeforeResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startUSK1229Upstream(t, false, usk1229CloseAfterRequest(200*time.Millisecond))
	store, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)

	start := time.Now()
	if _, err := c.Write([]byte("GET http://" + up.Addr() + "/hang HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second); len(got) != 0 {
		t.Errorf("client received %q; want no bytes", got)
	}
	st := requireUSK1229ErrorStream(t, store, "before sending a response")
	if st.Scheme != "http" {
		t.Errorf("Stream.Scheme = %q, want http", st.Scheme)
	}
}

// usk1229CaptureFinalState polls a flowStoreCapture for the first Stream
// whose updates carry a terminal State and returns that update.
func usk1229CaptureFinalState(store *flowStoreCapture, within time.Duration) (flow.StreamUpdate, bool) {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			for _, upd := range store.StreamUpdates(st.ID) {
				if upd.State == "complete" || upd.State == "error" {
					return upd, true
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return flow.StreamUpdate{}, false
}

// TestProxybuild_TCPForward_H1UpstreamClosesBeforeResponse covers Test
// Plan #4: TCP forward with an HTTP/1 client, for Protocol=http (plain and
// TLS upstream) and Protocol=auto with a TLS client negotiating http/1.1.
func TestProxybuild_TCPForward_H1UpstreamClosesBeforeResponse(t *testing.T) {
	cases := []struct {
		name        string
		protocol    string
		clientTLS   bool
		upstreamTLS bool
	}{
		{name: "http plain upstream", protocol: "http"},
		{name: "http tls upstream", protocol: "http", upstreamTLS: true},
		{name: "auto tls client h1", protocol: "auto", clientTLS: true, upstreamTLS: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startUSK1229Upstream(t, tc.upstreamTLS, usk1229CloseAfterRequest(200*time.Millisecond))
			fix := newUpstreamTLSFixture(t, ctx, up.Addr(), upstreamTLSFixtureOpts{
				protocol:     tc.protocol,
				clientTLS:    tc.clientTLS,
				upstreamTLS:  tc.upstreamTLS,
				insecureSkip: true,
			})

			var c net.Conn
			raw, err := net.DialTimeout("tcp", fix.fwdAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial forward: %v", err)
			}
			c = raw
			if tc.clientTLS {
				tlsConn := tls.Client(raw, &tls.Config{
					RootCAs:    fix.rootPool,
					ServerName: "forward.example.test",
					NextProtos: []string{"http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					t.Fatalf("client TLS handshake: %v", err)
				}
				c = tlsConn
			}
			t.Cleanup(func() { _ = c.Close() })
			br := bufio.NewReader(c)

			start := time.Now()
			if _, err := c.Write([]byte("GET /hang HTTP/1.1\r\nHost: forward.example.test\r\n\r\n")); err != nil {
				t.Fatalf("write request: %v", err)
			}
			if got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second); len(got) != 0 {
				t.Errorf("client received %q; want no bytes", got)
			}
			upd, ok := usk1229CaptureFinalState(fix.store, 5*time.Second)
			if !ok {
				t.Fatal("no Stream reached a terminal state")
			}
			if upd.State != "error" || upd.FailureReason != "aborted" {
				t.Errorf("Stream final update State=%q FailureReason=%q, want error/aborted", upd.State, upd.FailureReason)
			}
		})
	}
}

// TestProxybuild_MITM_H1PipelinedBehindUnanswered_NotForwarded covers Test
// Plan #5: a request pipelined behind an unanswered one is never forwarded
// (it would be answered in the unanswered request's place) — the client
// connection ends with no response bytes and a single upstream connection.
func TestProxybuild_MITM_H1PipelinedBehindUnanswered_NotForwarded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startUSK1229Upstream(t, true, func(idx int, c net.Conn, br *bufio.Reader) {
		target, err := usk1229ReadHead(br)
		if err != nil {
			return
		}
		if idx == 1 && target == "/a" {
			return // close without answering
		}
		body := "path=" + target
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		time.Sleep(100 * time.Millisecond)
	})
	_, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())

	host := "Host: " + up.Addr() + "\r\n"
	start := time.Now()
	if _, err := c.Write([]byte("GET /a HTTP/1.1\r\n" + host + "\r\nGET /b HTTP/1.1\r\n" + host + "\r\n")); err != nil {
		t.Fatalf("write pipelined requests: %v", err)
	}
	if got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second); len(got) != 0 {
		t.Errorf("client received %q; want no bytes (the response to /b must never stand in for /a)", got)
	}
	time.Sleep(200 * time.Millisecond)
	if n := up.ConnCount(); n != 1 {
		t.Errorf("upstream connections = %d, want 1 (/b must not be forwarded)", n)
	}
}

// usk1229ReadExact reads exactly len(want) bytes and compares them.
func usk1229ReadExact(t *testing.T, br *bufio.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read response: %v (got %q)", err, got)
	}
	if string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

// TestProxybuild_MITM_H1AnsweredThenUpstreamClose_KeepsClient guards Test
// Plan #6: an upstream that answers and then closes (without Connection:
// close) leaves the client connection usable; the next request is
// answered on a redialed upstream connection.
func TestProxybuild_MITM_H1AnsweredThenUpstreamClose_KeepsClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startUSK1229Upstream(t, true, func(idx int, c net.Conn, br *bufio.Reader) {
		if _, err := usk1229ReadHead(br); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"+strconv.Itoa(idx))
		// conn 1 closes right after answering; later conns stay open.
		if idx > 1 {
			time.Sleep(500 * time.Millisecond)
		}
	})
	_, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())
	host := "Host: " + up.Addr() + "\r\n"

	if _, err := c.Write([]byte("GET /1 HTTP/1.1\r\n" + host + "\r\n")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	usk1229ReadExact(t, br, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1")
	time.Sleep(100 * time.Millisecond) // let the upstream FIN land
	if _, err := c.Write([]byte("GET /2 HTTP/1.1\r\n" + host + "\r\n")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	usk1229ReadExact(t, br, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2")
}

// TestProxybuild_MITM_H1PluginDrop_ClosesClient covers Test Plan #10: a
// plugin DROP on http.on_request leaves the request unanswered, so the
// keep-alive client connection is ended promptly instead of hanging.
func TestProxybuild_MITM_H1PluginDrop_ClosesClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const dropScript = `
def on_req(msg, ctx):
    if msg["path"] == "/drop":
        return action.DROP
register_hook("http", "on_request", on_req)
`
	up := startUSK1229Upstream(t, true, usk1229ReplyThenClose("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	_, proxyAddr := startUSK1229MITM(t, ctx, loadRawWinsPlugin(t, ctx, dropScript))
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())

	start := time.Now()
	if _, err := c.Write([]byte("GET /drop HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second); len(got) != 0 {
		t.Errorf("client received %q; want no bytes", got)
	}
	if n := up.ConnCount(); n != 0 {
		t.Errorf("upstream connections = %d, want 0 (the dropped request is never forwarded)", n)
	}
}

// TestProxybuild_MITM_H1UpstreamTruncatedBody covers Test Plan #11/#12: an
// upstream that closes mid-body has exactly the bytes it sent relayed to
// the client, which then sees the connection end; the exchange is recorded
// as an aborted error whose response flow carries the TruncatedBody
// anomaly and the exact wire bytes.
func TestProxybuild_MITM_H1UpstreamTruncatedBody(t *testing.T) {
	cases := []struct{ name, reply string }{
		{name: "short content-length", reply: usk1229TruncatedCL},
		{name: "unterminated chunked", reply: usk1229TruncatedChunked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startUSK1229Upstream(t, true, usk1229ReplyThenClose(tc.reply))
			store, proxyAddr := startUSK1229MITM(t, ctx, nil)
			c, br := usk1229DialMITM(t, proxyAddr, up.Addr())

			start := time.Now()
			if _, err := c.Write([]byte("GET /trunc HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
				t.Fatalf("write request: %v", err)
			}
			got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second)
			if string(got) != tc.reply {
				t.Errorf("client received %q, want exactly the upstream's bytes %q", got, tc.reply)
			}

			st := requireUSK1229ErrorStream(t, store, "mid-body")
			recv := usk1229FlowsFor(store, st.ID, "receive")
			if len(recv) == 0 {
				t.Fatalf("no receive flow recorded for stream %s", st.ID)
			}
			if !bytes.Equal(recv[0].RawBytes, []byte(tc.reply)) {
				t.Errorf("receive flow RawBytes = %q, want %q", recv[0].RawBytes, tc.reply)
			}
			if _, ok := recv[0].Metadata["http_anomaly_truncated_body"]; !ok {
				t.Errorf("receive flow Metadata = %v, want http_anomaly_truncated_body", recv[0].Metadata)
			}
		})
	}
}

// TestProxybuild_MITM_H1CompleteBodies_KeepAlive guards Test Plan #14:
// complete Content-Length and chunked responses keep working across two
// requests on one keep-alive connection, recorded as complete.
func TestProxybuild_MITM_H1CompleteBodies_KeepAlive(t *testing.T) {
	cases := []struct{ name, reply string }{
		{name: "content-length", reply: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"},
		{name: "chunked", reply: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startUSK1229Upstream(t, true, func(_ int, c net.Conn, br *bufio.Reader) {
				for {
					if _, err := usk1229ReadHead(br); err != nil {
						return
					}
					if _, err := io.WriteString(c, tc.reply); err != nil {
						return
					}
				}
			})
			store, proxyAddr := startUSK1229MITM(t, ctx, nil)
			c, br := usk1229DialMITM(t, proxyAddr, up.Addr())
			host := "Host: " + up.Addr() + "\r\n"
			for i := 0; i < 2; i++ {
				if _, err := c.Write([]byte("GET /ok HTTP/1.1\r\n" + host + "\r\n")); err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
				usk1229ReadExact(t, br, tc.reply)
			}
			end := time.Now().Add(5 * time.Second)
			for time.Now().Before(end) {
				n := 0
				for _, st := range store.Streams() {
					if st.State == "complete" {
						n++
					}
				}
				if n == 2 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, st := range store.Streams() {
				if st.State != "complete" {
					t.Errorf("Stream %s State = %q, want complete", st.ID, st.State)
				}
			}
			if n := up.ConnCount(); n != 1 {
				t.Errorf("upstream connections = %d, want 1 (keep-alive reuse)", n)
			}
		})
	}
}
