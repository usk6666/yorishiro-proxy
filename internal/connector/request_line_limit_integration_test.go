//go:build e2e && !e2e_smoke

package connector_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestFullListener_CONNECT_HTTPS_MITM_LongRequestLine covers USK-1137 Test
// Plan #14 (Issue repro D): an HTTP/1.1 request with a 9 KiB query through
// CONNECT + TLS MITM reaches upstream with the full request line, the client
// gets the upstream response (not an empty reply), and the exchange is
// recorded complete with the full URL.
func TestFullListener_CONNECT_HTTPS_MITM_LongRequestLine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// The custom onStack records into its own store: the harness's store
	// is created inside startFullListenerProxy, after onStack is bound.
	store := &testStore{}
	stateCh := make(chan string, 1)
	onStack := func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer stack.Close()
		clientCh := <-stack.ClientTopmost().Channels()
		p := pipeline.New(
			pipeline.NewHostScopeStep(nil),
			pipeline.NewRecordStep(store, slog.Default()),
		)
		session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if streamID != "" {
					_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{State: state})
				}
				select {
				case stateCh <- state:
				default:
				}
			},
		})
	}
	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{onStack: onStack})

	query := "q=" + strings.Repeat("x", 9000)
	requestLine := "GET /?" + query + " HTTP/1.1"
	rawReq := fmt.Sprintf("%s\r\nHost: %s\r\nConnection: close\r\n\r\n", requestLine, target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Errorf("response = %.120q, want the upstream 200 OK", resp)
	}
	if !strings.HasSuffix(resp, "hello") {
		t.Errorf("response body not 'hello': %.120q", resp)
	}

	upstreamReqs := getUpstreamReqs()
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.HasPrefix(upstreamReqs[0], []byte(requestLine+"\r\n")) {
		t.Errorf("upstream request line is not the full %d-byte line: %.120q", len(requestLine), upstreamReqs[0])
	}

	select {
	case st := <-stateCh:
		if st != "complete" {
			t.Errorf("session ended with state %q, want complete", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session did not complete")
	}

	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want http", streams[0].Protocol)
	}
	if streams[0].State != "complete" {
		t.Errorf("stream state = %q, want complete", streams[0].State)
	}
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	if u := sendFlows[0].URL; u == nil || u.RawQuery != query {
		got := 0
		if u != nil {
			got = len(u.RawQuery)
		}
		t.Errorf("send flow URL RawQuery is %d bytes, want %d", got, len(query))
	}
	if len(sendFlows[0].RawBytes) == 0 {
		t.Error("send flow RawBytes is empty")
	}
	if recv := store.flowsByDirection("receive"); len(recv) < 1 || recv[0].StatusCode != 200 {
		t.Errorf("receive flows = %d, want one with StatusCode 200", len(recv))
	}
}

// TestFullListener_CONNECT_HTTPS_MITM_RequestLineTooLong_414 covers the
// over-limit side of USK-1137 defect D on the production path: a request
// line past the 4 MiB limit, sent inside CONNECT + TLS MITM, gets a 414 URI
// Too Long with Connection: close from the proxy followed by a clean
// close, never reaches upstream, and is not recorded.
func TestFullListener_CONNECT_HTTPS_MITM_RequestLineTooLong_414(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var upstreamHits atomic.Int32
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamHits.Add(1)
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	wg.Add(1)
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	rawReq := "GET /?q=" + strings.Repeat("x", 4<<20) + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	go func() { _, _ = tlsConn.Write([]byte(rawReq)) }()

	_ = tlsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := io.ReadAll(tlsConn)
	if err != nil {
		t.Errorf("reading the response: %v (want the 414 followed by a clean close)", err)
	}
	if !bytes.HasPrefix(resp, []byte("HTTP/1.1 414 URI Too Long\r\n")) {
		t.Fatalf("response = %.200q, want HTTP/1.1 414 URI Too Long", resp)
	}
	if !bytes.Contains(resp, []byte("\r\nConnection: close\r\n")) {
		t.Errorf("414 response lacks Connection: close: %q", resp)
	}
	waitSessionDone(t, wg)
	if n := upstreamHits.Load(); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}
	if n := len(store.flowsByDirection("send")); n != 0 {
		t.Errorf("recorded %d send flows for the rejected request, want 0", n)
	}
}
