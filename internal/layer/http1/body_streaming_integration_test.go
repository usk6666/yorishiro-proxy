//go:build e2e && !e2e_smoke

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-1409 exhaustive tier: recording, error paths, keep-alive and rule
// changes for streamed HTTP/1.x response bodies. Helpers live in
// body_streaming_smoke_integration_test.go.

// TestHTTP1_ResponseBodyStreaming_Recording (T8): while the body is pending
// the Stream is active and no receive Flow exists; after the end the Stream
// is complete and the Flow carries the whole body and the head + raw
// chunked bytes, stamped with the header-arrival time.
func TestHTTP1_ResponseBodyStreaming_Recording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const respHead = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
	const chunk1 = "5;a=b\r\nhello\r\n"
	const rest = "6\r\n world\r\n0\r\nX-Sum: 7\r\n\r\n"
	g := newGate()
	defer g.open()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		_, _ = c.Write([]byte(respHead + chunk1))
		if !g.wait() {
			return
		}
		_, _ = c.Write([]byte(rest))
	})
	proxyAddr, store, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /rec HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	br := bufio.NewReader(conn)
	readHeadWithin(t, conn, br)
	readExactlyFromWithin(t, conn, br, len(chunk1))

	st, ok := streamSnapshot(store, "")
	if !ok || st.State != "active" {
		t.Fatalf("Stream while the body is pending = %+v (ok=%v), want state active", st, ok)
	}
	if n := len(store.flowsByDirection("receive")); n != 0 {
		t.Fatalf("receive flows while the body is pending = %d, want 0", n)
	}

	bodyEnd := time.Now()
	g.open()
	readExactlyFromWithin(t, conn, br, len(rest))

	waitStreamState(t, store, "complete")
	recv := waitFlowsByDirection(t, store, "receive", 1)
	fl := recv[0]
	if string(fl.Body) != "hello world" {
		t.Errorf("recorded body = %q, want %q", fl.Body, "hello world")
	}
	if want := respHead + chunk1 + rest; string(fl.RawBytes) != want {
		t.Errorf("recorded raw bytes = %q, want head + raw chunked body %q", fl.RawBytes, want)
	}
	if got := fl.Trailers["X-Sum"]; len(got) != 1 || got[0] != "7" {
		t.Errorf("recorded trailers = %v, want X-Sum: 7", fl.Trailers)
	}
	if fl.Timestamp.After(bodyEnd) {
		t.Errorf("Flow.Timestamp %v is after the body end %v; want the header-arrival time", fl.Timestamp, bodyEnd)
	}
	if fl.BodyTruncated {
		t.Error("BodyTruncated = true for a complete body")
	}
}

// TestHTTP1_ResponseBodyStreaming_ReplaceBodyStillBuffered (T10): a
// replace_body Transform matching the response forces the buffer; the body
// is rewritten and both variants are recorded.
func TestHTTP1_ResponseBodyStreaming_ReplaceBodyStillBuffered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nthe secret one")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	tf := httprules.NewTransformEngine()
	rule, err := httprules.CompileTransformRule("rb", 0, httprules.DirectionResponse,
		"", "^/rewrite$", nil, httprules.TransformReplaceBody, "", "", "secret", "public")
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	tf.AddRule(*rule)
	proxyAddr, store, _ := startStreamingProxy(t, ctx, target, proxyOpts{transformEngine: tf})

	resp := connectAndSendHTTP(t, proxyAddr, target,
		fmt.Sprintf("GET /rewrite HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target))
	if !strings.HasSuffix(resp, "the public one") {
		t.Fatalf("client response = %q, want the rewritten body", resp)
	}
	waitStreamState(t, store, "complete")
	recv := waitFlowsByDirection(t, store, "receive", 2)
	variants := map[string]*flow.Flow{}
	for _, fl := range recv {
		variants[fl.Metadata["variant"]] = fl
	}
	if o := variants["original"]; o == nil || string(o.Body) != "the secret one" {
		t.Errorf("original variant = %+v, want body %q", o, "the secret one")
	}
	if m := variants["modified"]; m == nil || string(m.Body) != "the public one" {
		t.Errorf("modified variant = %+v, want body %q", m, "the public one")
	}
}

// TestHTTP1_ResponseBodyStreaming_UpstreamCutMidBody (T11): the client gets
// the bytes sent before the cut and then the connection closes; the Stream
// is error and the Flow keeps the partial body and the truncation anomaly.
func TestHTTP1_ResponseBodyStreaming_UpstreamCutMidBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	partial := bytes.Repeat([]byte("p"), 400)
	g := newGate()
	defer g.open()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"))
		_, _ = c.Write(partial)
		g.wait()
		// Return closes the conn mid-body.
	})
	proxyAddr, store, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /cut HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	br := bufio.NewReader(conn)
	readHeadWithin(t, conn, br)
	if got := readExactlyFromWithin(t, conn, br, len(partial)); !bytes.Equal(got, partial) {
		t.Fatal("client did not receive the bytes sent before the cut")
	}
	g.open()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	extra, err := io.ReadAll(br)
	if len(extra) != 0 {
		t.Errorf("client received %d bytes after the cut, want 0", len(extra))
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("client connection was not closed after the upstream cut")
	}

	st := waitStreamState(t, store, "error")
	_ = st
	recv := waitFlowsByDirection(t, store, "receive", 1)
	fl := recv[0]
	if !bytes.Equal(fl.Body, partial) {
		t.Errorf("recorded body = %d bytes, want the %d received before the cut", len(fl.Body), len(partial))
	}
	if fl.Metadata["http_anomaly_truncated_body"] == "" {
		t.Errorf("receive flow metadata lacks http_anomaly_truncated_body: %v", fl.Metadata)
	}
}

// TestHTTP1_ResponseBodyStreaming_KeepAlive (T12): after a streamed
// response, the next request on the same client connection gets its own
// response over the same upstream connection.
func TestHTTP1_ResponseBodyStreaming_KeepAlive(t *testing.T) {
	cases := []struct {
		name        string
		head, first string
		rest        string
	}{
		{name: "content-length", head: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", first: "first", rest: "-last"},
		{name: "chunked", head: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", first: "5\r\nfirst\r\n", rest: "5\r\n-last\r\n0\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			g := newGate()
			defer g.open()
			target, accepts := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
				if _, err := readHTTPRequest(br); err != nil {
					return
				}
				_, _ = c.Write([]byte(tc.head + tc.first))
				if !g.wait() {
					return
				}
				_, _ = c.Write([]byte(tc.rest))
				if _, err := readHTTPRequest(br); err != nil {
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"))
			})
			proxyAddr, store, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

			conn := connectThroughProxy(t, proxyAddr, target)
			defer conn.Close()
			br := bufio.NewReader(conn)
			fmt.Fprintf(conn, "GET /one HTTP/1.1\r\nHost: %s\r\n\r\n", target)
			readHeadWithin(t, conn, br)
			readExactlyFromWithin(t, conn, br, len(tc.first))
			g.open()
			readExactlyFromWithin(t, conn, br, len(tc.rest))

			fmt.Fprintf(conn, "GET /two HTTP/1.1\r\nHost: %s\r\n\r\n", target)
			head2 := readHeadWithin(t, conn, br)
			if !strings.Contains(head2, "Content-Length: 6") {
				t.Fatalf("second response head = %q", head2)
			}
			if got := readExactlyFromWithin(t, conn, br, 6); string(got) != "second" {
				t.Fatalf("second body = %q, want %q", got, "second")
			}
			if n := accepts.Load(); n != 1 {
				t.Errorf("upstream accepted %d connections, want 1 (keep-alive reuse)", n)
			}
			recv := waitFlowsByDirection(t, store, "receive", 2)
			bodies := map[string]bool{}
			for _, fl := range recv {
				bodies[string(fl.Body)] = true
			}
			if !bodies["first-last"] || !bodies["second"] {
				t.Errorf("recorded receive bodies = %v, want first-last and second", bodies)
			}
		})
	}
}

// TestHTTP1_ResponseBodyStreaming_ClientGoneAfterHead (T18): the client
// closes after the head; the upstream body is abandoned, the receive Flow
// is saved exactly once with the partial body, before the Stream's final
// error state.
func TestHTTP1_ResponseBodyStreaming_ClientGoneAfterHead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const total = 64 << 20
	g := newGate()
	defer g.open()
	upstreamEnded := make(chan error, 1)
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			upstreamEnded <- err
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nstart", total)
		if !g.wait() {
			upstreamEnded <- fmt.Errorf("gate never opened")
			return
		}
		chunk := bytes.Repeat([]byte("z"), 32<<10)
		_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
		for sent := 5; sent < total; sent += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				upstreamEnded <- err
				return
			}
		}
		upstreamEnded <- nil
	})
	proxyAddr, store, _ := startStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	fmt.Fprintf(conn, "GET /gone HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	br := bufio.NewReader(conn)
	readHeadWithin(t, conn, br)
	_ = conn.Close()
	g.open()

	select {
	case err := <-upstreamEnded:
		if err == nil {
			t.Fatal("upstream wrote the whole 64 MiB body; the proxy did not abandon it")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("upstream write never failed after the client left")
	}

	waitStreamState(t, store, "error")
	recv := waitFlowsByDirection(t, store, "receive", 1)
	if len(recv) != 1 {
		t.Fatalf("receive flows = %d, want exactly 1", len(recv))
	}
	if n := len(recv[0].Body); n == 0 || n >= total {
		t.Errorf("recorded body = %d bytes, want a partial body", n)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	flowAt, stateAt := -1, -1
	for i, e := range events {
		if e == "flow:receive" && flowAt < 0 {
			flowAt = i
		}
		if e == "state:error" && stateAt < 0 {
			stateAt = i
		}
	}
	if flowAt < 0 || stateAt < 0 || flowAt > stateAt {
		t.Errorf("store events = %v; want the receive flow saved before the final error state", events)
	}
}

// TestHTTP1_ResponseBodyStreaming_RuleAddedMidStream (T19): rules added
// after a head was streamed do not hold or rewrite that in-flight response;
// they apply from the next response.
func TestHTTP1_ResponseBodyStreaming_RuleAddedMidStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	g := newGate()
	defer g.open()
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nsecret-"))
		if !g.wait() {
			return
		}
		_, _ = c.Write([]byte("secret!"))
		if _, err := readHTTPRequest(br); err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret"))
	})
	ie := httprules.NewInterceptEngine()
	tf := httprules.NewTransformEngine()
	hq := common.NewHoldQueue()
	proxyAddr, _, _ := startStreamingProxy(t, ctx, target, proxyOpts{
		interceptEngine: ie, transformEngine: tf, holdQueue: hq,
	})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	br := bufio.NewReader(conn)
	fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	readHeadWithin(t, conn, br)
	readExactlyFromWithin(t, conn, br, len("secret-"))

	// Holds every response from now on.
	ic, err := httprules.CompileInterceptRule("late-hold", httprules.DirectionResponse, "", "", nil, nil)
	if err != nil {
		t.Fatalf("CompileInterceptRule: %v", err)
	}
	ie.AddRule(*ic)
	rb, err := httprules.CompileTransformRule("late-rb", 0, httprules.DirectionResponse,
		"", "", nil, httprules.TransformReplaceBody, "", "", "secret", "public")
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	tf.AddRule(*rb)

	g.open()
	if got := readExactlyFromWithin(t, conn, br, len("secret!")); string(got) != "secret!" {
		t.Fatalf("in-flight body tail = %q, want the upstream bytes unchanged", got)
	}
	if n := hq.Len(); n != 0 {
		t.Fatalf("hold queue has %d entries after the in-flight response, want 0", n)
	}

	fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: %s\r\n\r\n", target)
	deadline := time.Now().Add(10 * time.Second)
	for hq.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the next response was not held by the rule added mid-stream")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, e := range hq.List() {
		e.Envelope.ReleaseBuffers()
		if err := hq.Release(e.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
			t.Fatalf("Release: %v", err)
		}
	}
	readHeadWithin(t, conn, br)
	if got := readExactlyFromWithin(t, conn, br, len("public")); string(got) != "public" {
		t.Fatalf("next body = %q, want the rewrite of the rule added mid-stream", got)
	}
}
