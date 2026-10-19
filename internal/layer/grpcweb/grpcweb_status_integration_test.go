//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	nethttp "net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// startGRPCWebHTTP2StatusUpstream is startGRPCWebHTTP2Upstream with a
// caller-chosen HTTP status (the shared helper is fixed at 200).
func startGRPCWebHTTP2StatusUpstream(t *testing.T, status int, ct string, body []byte) (string, func()) {
	t.Helper()
	tlsCfg := newTestTLSConfig(t, []string{"h2"})
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2s := &http2.Server{}
	handler := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	tracker := &upstreamConnTracker{}
	tracker.wg.Add(1)
	go func() {
		defer tracker.wg.Done()
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			if !tracker.track(c) {
				_ = c.Close()
				continue
			}
			tlsConn := tls.Server(c, tlsCfg)
			tracker.wg.Add(1)
			go func(tc *tls.Conn) {
				defer tracker.wg.Done()
				defer tc.Close()
				if err := tc.Handshake(); err != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tlsConn)
		}
	}()
	return tcpLn.Addr().String(), func() { tracker.shutdown(t, tcpLn) }
}

// TestGRPCWeb_HTTP2_UpstreamStatusReachesClient — T9 (USK-1219): an h2
// upstream answering :status 503 with a gRPC-Web body must reach the h2
// client as :status 503 (it used to be rewritten to 200), and the
// recorded receive-start flow must report 503.
func TestGRPCWeb_HTTP2_UpstreamStatusReachesClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body := buildGRPCWebResponseBody([]byte("busy"), 14, "unavailable", false)
	target, shutdown := startGRPCWebHTTP2StatusUpstream(t, 503, "application/grpc-web+proto", body)
	defer shutdown()

	proxyAddr, store, sessionDone := startGRPCWebHTTP2Proxy(t, ctx, pipelineOpts{})
	status, _, _ := sendGRPCWebHTTP2Request(t, proxyAddr, target, []byte("ping"), false)
	if status != 503 {
		t.Errorf("h2 client :status = %d, want 503", status)
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
	if !waitFor(t, 5*time.Second, func() bool {
		return firstFlowWithEvent(flowsForFirstStream(store), "receive", "start") != nil
	}) {
		t.Fatal("no receive-start flow recorded")
	}
	if f := firstFlowWithEvent(flowsForFirstStream(store), "receive", "start"); f.StatusCode != 503 {
		t.Errorf("recorded receive-start StatusCode = %d, want 503", f.StatusCode)
	}
}
