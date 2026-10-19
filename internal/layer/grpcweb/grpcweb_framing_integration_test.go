//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
)

// USK-1203: body forwarding and framing-header reconciliation at the gRPC-Web
// re-assembly seam. Exhaustive tier; the smoke-tier siblings live in
// grpcweb_integration_test.go (runMalformedAnomalyTest,
// TestGRPCWeb_UnexpectedRequestTrailerProducesAnomaly,
// TestGRPCWeb_VariantRecordingOnTransform).

// malformedLPMBody is a binary gRPC-Web body whose single LPM header declares
// 1000 payload bytes while only 4 follow (readAllFrames → ErrMalformedLPM).
// Same shape as TestGRPCWeb_MalformedLPMProducesAnomaly.
var malformedLPMBody = []byte{
	0x00,                   // flags: not compressed, not trailer
	0x00, 0x00, 0x03, 0xe8, // length: 1000 (big-endian)
	'a', 'b', 'c', 'd', // only 4 payload bytes
}

// TestGRPCWeb_ChunkedRequestForwardedWithContentLength — a gRPC-Web request
// framed with Transfer-Encoding: chunked is re-assembled by the grpcweb Layer
// into a de-chunked body. The upstream must receive that body framed by a
// Content-Length equal to its length and NO Transfer-Encoding: forwarding the
// client's TE header over an un-chunked body (plus a synthesized CL) is the
// CL+TE request-smuggling shape. Mirrors http1 applyTEToCLRewrite (USK-769);
// the chunk boundaries themselves are not reproduced on the next hop.
//
// Invented fixture: hand-built chunked request per RFC 9112 §7.1 (chunk-size
// in hex, CRLF, chunk-data, CRLF; terminated by a zero-size last-chunk). The
// 9-byte LPM frame is split across two chunks so the de-chunking is real.
func TestGRPCWeb_ChunkedRequestForwardedWithContentLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamResp := buildGRPCWebResponseHTTP([]byte("ack-chunked"), 0, "OK", false)
	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return upstreamResp
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	frame := grpcweb.EncodeFrame(false, false, []byte("ping"))
	chunked := fmt.Sprintf("%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n",
		4, frame[:4], len(frame)-4, frame[4:])
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web+proto\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%s",
		target, chunked)

	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write chunked request: %v", err)
	}
	clientResp := readUntilClose(tlsConn, 5*time.Second)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertClientGotUpstreamResponse(t, clientResp, upstreamResp)
	upstreamLn.Close()
	assertUpstreamBody(t, captured(), frame)
}

// TestGRPCWeb_MalformedResponseForwardedToClient — the Receive-direction twin
// of runMalformedAnomalyTest: an upstream response whose body fails LPM
// parsing must reach the client byte-for-byte under the upstream's
// Content-Length, while the Receive Start flow records the anomaly with the
// malformed body on RawBytes.
func TestGRPCWeb_MalformedResponseForwardedToClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamResp := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(malformedLPMBody)) + string(malformedLPMBody))
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return upstreamResp
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	clientResp := sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping"), false)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertClientGotUpstreamResponse(t, clientResp, upstreamResp)
	if len(clientResp) > 0 {
		hdrs, _ := splitHTTPMessage(t, clientResp)
		wantCL := strconv.Itoa(len(malformedLPMBody))
		if got := headerValues(hdrs, "Content-Length"); len(got) != 1 || got[0] != wantCL {
			t.Errorf("client Content-Length = %q, want [%q]", got, wantCL)
		}
	}

	startF := firstFlowWithEvent(flowsForFirstStream(store), "receive", "start")
	if startF == nil {
		t.Fatal("no receive start flow recorded")
	}
	if startF.Metadata["grpc_anomaly_malformed_lpm"] == "" {
		t.Errorf("receive start flow missing grpc_anomaly_malformed_lpm; metadata keys: %v", metadataKeys(startF.Metadata))
	}
	if !bytes.Equal(startF.RawBytes, malformedLPMBody) {
		t.Errorf("receive start RawBytes = %q, want %q", startF.RawBytes, malformedLPMBody)
	}
}

// h2BodyCapture is a mutex-guarded record of what an h2 upstream handler
// observed on the request.
type h2BodyCapture struct {
	mu   sync.Mutex
	got  bool
	cl   []string
	body []byte
}

func (c *h2BodyCapture) set(cl []string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got, c.cl, c.body = true, cl, body
}

func (c *h2BodyCapture) get() (bool, []string, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got, c.cl, c.body
}

// startGRPCWebHTTP2CaptureUpstream starts a TLS+ALPN h2 upstream that records
// the request body and content-length field values, then replies with
// respBody under content-type ct.
func startGRPCWebHTTP2CaptureUpstream(t *testing.T, capture *h2BodyCapture, respBody []byte, ct string) string {
	t.Helper()
	tlsCfg := newTestTLSConfig(t, []string{"h2"})
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	h2s := &http2.Server{}
	handler := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		capture.set(r.Header.Values("Content-Length"), body)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(200)
		_, _ = w.Write(respBody)
	})
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			go func(tc *tls.Conn) {
				defer tc.Close()
				if err := tc.Handshake(); err != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tls.Server(c, tlsCfg))
		}
	}()
	return tcpLn.Addr().String()
}

// postGRPCWebHTTP2 posts body through the proxy over h2 with a 5s overall
// deadline and returns the response status and body (or the client error).
func postGRPCWebHTTP2(proxyAddr, target, ct string, body []byte) (int, []byte, error) {
	cli := &nethttp.Client{Transport: h2TransportViaProxy(proxyAddr, target), Timeout: 5 * time.Second}
	req, err := nethttp.NewRequest("POST", "https://"+target+"/pkg.Echo/Say", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", ct)
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	return resp.StatusCode, rb, err
}

// TestGRPCWeb_MalformedRequestForwardedOverHTTP2 — T1 over the h2 leg: a
// malformed request body sent by an h2 client reaches the h2 upstream
// byte-for-byte (content-length intact) and the upstream reply reaches the
// client.
func TestGRPCWeb_MalformedRequestForwardedOverHTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var capture h2BodyCapture
	respBody := buildGRPCWebResponseBody([]byte("ack-h2"), 0, "OK", false)
	upAddr := startGRPCWebHTTP2CaptureUpstream(t, &capture, respBody, "application/grpc-web+proto")

	proxyAddr, _, _ := startGRPCWebHTTP2Proxy(t, ctx, pipelineOpts{})

	status, gotResp, err := postGRPCWebHTTP2(proxyAddr, upAddr, "application/grpc-web+proto", malformedLPMBody)
	if err != nil {
		t.Fatalf("h2 client: %v (the proxy did not relay the request/response)", err)
	}
	if status != 200 {
		t.Errorf("client status = %d, want 200", status)
	}
	if !bytes.Equal(gotResp, respBody) {
		t.Errorf("client response body = %q, want %q", gotResp, respBody)
	}

	got, cl, body := capture.get()
	if !got {
		t.Fatal("h2 upstream never saw the request")
	}
	if !bytes.Equal(body, malformedLPMBody) {
		t.Errorf("upstream body = %q, want %q", body, malformedLPMBody)
	}
	if want := strconv.Itoa(len(malformedLPMBody)); len(cl) != 1 || cl[0] != want {
		t.Errorf("upstream content-length = %q, want [%q]", cl, want)
	}
}

// TestGRPCWeb_MalformedResponseForwardedOverHTTP2 — T6 over the h2 leg: an
// h2 upstream's malformed response body reaches the h2 client verbatim.
func TestGRPCWeb_MalformedResponseForwardedOverHTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var capture h2BodyCapture
	upAddr := startGRPCWebHTTP2CaptureUpstream(t, &capture, malformedLPMBody, "application/grpc-web+proto")

	proxyAddr, _, _ := startGRPCWebHTTP2Proxy(t, ctx, pipelineOpts{})

	reqBody := grpcweb.EncodeFrame(false, false, []byte("ping"))
	status, gotResp, err := postGRPCWebHTTP2(proxyAddr, upAddr, "application/grpc-web+proto", reqBody)
	if err != nil {
		t.Fatalf("h2 client: %v (the proxy did not relay the malformed response)", err)
	}
	if status != 200 {
		t.Errorf("client status = %d, want 200", status)
	}
	if !bytes.Equal(gotResp, malformedLPMBody) {
		t.Errorf("client response body = %q, want %q", gotResp, malformedLPMBody)
	}
}
