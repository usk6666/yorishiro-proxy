//go:build e2e && !e2e_smoke

// USK-1252: the gRPC-Web Layer relays the client's observed HTTP request
// method to the upstream instead of forcing POST, and records it as the
// Send start flow's Method. Driven through the production wiring
// (BuildLiveStack + a tcp_forwards entry) on both inner transports:
// HTTP/1.1 (Protocol="http", DispatchH1Channel) and h2c
// (Protocol="http2", DispatchH2Stream). Classification is
// content-type-only on both, so a non-POST request carrying a gRPC-Web
// content-type is wrapped in the grpcweb Layer.
package proxybuild_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// grpcWebOKBody is one data LPM plus a grpc-status: 0 trailer LPM.
func grpcWebOKBody() []byte {
	body := buildLPMBody([]byte("hello!!"))
	body = append(body, 0x80, 0, 0, 0, 16)
	return append(body, []byte("grpc-status: 0\r\n")...)
}

// TestProxybuild_TCPForward_H1_GRPCWeb_RequestMethodReachesUpstream (T1):
// the request line the upstream reads carries the client's method
// verbatim, and the recorded Send start flow reports it.
func TestProxybuild_TCPForward_H1_GRPCWeb_RequestMethodReachesUpstream(t *testing.T) {
	for _, method := range []string{"GET", "PUT", "post", "POST"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			okBody := grpcWebOKBody()
			resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(okBody)))
			resp = append(resp, okBody...)
			up := startRawH1Upstream(t, resp)
			fwdAddr, store := startH1ForwardListenerWithGRPCSafety(t, ctx, up.addr, nil)

			const target = "/hello.HelloService/SayHello"
			got := exchangeRaw(t, fwdAddr, grpcWebRequestWithMethod(method, target, fwdAddr,
				[]string{"Content-Type: application/grpc-web+proto"}, buildLPMBody([]byte("ping"))))
			if startLine, _, _ := splitRawHTTP(t, got); startLine != "HTTP/1.1 200 OK" {
				t.Errorf("client status line = %q, want %q", startLine, "HTTP/1.1 200 OK")
			}

			reqs := up.requests()
			if len(reqs) != 1 {
				t.Fatalf("upstream saw %d requests, want 1", len(reqs))
			}
			startLine, _, _ := splitRawHTTP(t, reqs[0])
			if want := method + " " + target + " HTTP/1.1"; startLine != want {
				t.Errorf("upstream request line = %q, want %q", startLine, want)
			}

			f := flowWhere(t, store, "send start", isGRPCEvent("send", "start"))
			if f.Method != method {
				t.Errorf("recorded send-start Flow.Method = %q, want %q", f.Method, method)
			}
		})
	}
}

// TestProxybuild_TCPForward_H2C_GRPCWeb_RequestMethodReachesUpstream (T2):
// the :method the h2c upstream reads is the client's, verbatim, and the
// recorded Send start flow reports it.
func TestProxybuild_TCPForward_H2C_GRPCWeb_RequestMethodReachesUpstream(t *testing.T) {
	for _, method := range []string{"GET", "PUT", "put", "POST"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var (
				upMu      sync.Mutex
				upMethods []string
			)
			respBody := grpcWebOKBody()
			upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				upMu.Lock()
				upMethods = append(upMethods, r.Method)
				upMu.Unlock()
				w.Header().Set("Content-Type", "application/grpc-web+proto")
				_, _ = w.Write(respBody)
			}))
			defer upStop()

			mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "http2")
			defer mgr.StopAll(context.Background())

			var dialedConns []net.Conn
			var mu sync.Mutex
			cli := h2cForwardClient(fwdAddr, &dialedConns, &mu)
			defer func() {
				mu.Lock()
				closeDialedConns(dialedConns)
				mu.Unlock()
			}()

			req, err := gohttp.NewRequestWithContext(ctx, method, "http://"+fwdAddr+"/hello.HelloService/SayHello",
				bytes.NewReader(buildLPMBody([]byte("ping"))))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/grpc-web+proto")
			resp, err := cli.Do(req)
			if err != nil {
				t.Fatalf("client Do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("client status = %d, want 200", resp.StatusCode)
			}

			upMu.Lock()
			gotMethods := append([]string(nil), upMethods...)
			upMu.Unlock()
			if strings.Join(gotMethods, ",") != method {
				t.Errorf("upstream :method = %q, want [%q]", gotMethods, method)
			}

			f := flowWhere(t, store, "send start", isGRPCEvent("send", "start"))
			if f.Method != method {
				t.Errorf("recorded send-start Flow.Method = %q, want %q", f.Method, method)
			}
		})
	}
}
