//go:build e2e

// Package mcptest_test holds the regression test for USK-777: live
// production gRPC-Web dispatch must deliver envelopes to the Pipeline
// (and hence to RecordStep) without a structural divergence from the
// gRPC sibling (USK-771).
//
// USK-771 (PR #761) added connector.WrapH2UpstreamForDispatch with three
// branches (ProtocolGRPC / ProtocolGRPCWeb / default). The gRPC branch
// is exercised end-to-end by TestE2E_LiveGRPC_DispatchDeliversEnvelope
// via a real grpc-go client. The ProtocolGRPCWeb branch was unit-tested
// (TestWrapH2UpstreamForDispatch) but had no live client driving
// proxybuild.BuildLiveStack — so a future regression of the
// httpaggregator + grpcweb composition would not be caught by smoke.
//
// This file closes that gap. It boots the production server with a
// hand-rolled http2.Server upstream that responds to
// application/grpc-web+proto requests with a single data frame plus a
// trailer frame, drives a single unary RPC through proxy_start over
// CONNECT + TLS(h2), and asserts the recorded flow.Stream carries
// Protocol="grpc-web". RecordStep is the terminal Pipeline Step, so a
// recorded grpc-web stream proves the dispatch decision propagated all
// the way through Pipeline.
//
// The test runs in the smoke tier (plain //go:build e2e) for the same
// reason TestE2E_LiveGRPC_DispatchDeliversEnvelope does: the regression
// class — "in-package layer tests pass but live BuildLiveStack does
// not" — is exactly what the merge gate exists to catch.
//
// USK-780 dependency: the proxy session loop currently does not
// synthesise a Send-direction GRPCEndMessage when the client side
// EOFs without an embedded trailer (gRPC-Web request bodies are
// spec'd not to carry one). Without that injection the upstream-side
// grpcweb.RoleClient never flushes the request body to the upstream
// wire and a well-formed unary RPC hangs at the upstream Send buffer.
// This test therefore drives the request asynchronously and asserts
// only that envelopes reached Pipeline (recorded grpc-web flow), NOT a
// full RPC round-trip + hit count. Once USK-780 closes the gap, the
// assertions should be tightened to match TestE2E_LiveGRPC_*.
package mcptest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope is the USK-777 regression
// gate. It boots the production server with a real gRPC-Web upstream
// behind the harness, drives a single unary Echo over
// application/grpc-web+proto through proxy_start via CONNECT + TLS(h2),
// and asserts at least one envelope of the appropriate gRPC-Web type
// reaches Pipeline.
//
// Acceptance criteria (USK-777):
//
//  1. RPC request flows through the proxy: the dispatcher recognises
//     application/grpc-web+proto and wraps the client stream with
//     httpaggregator + grpcweb (debug log "DispatchH2Stream: gRPC-Web
//     content-type detected"). Verified indirectly via (2).
//  2. At least one envelope of the gRPC-Web type reaches Pipeline,
//     proven via the recorded flow.Stream's Protocol="grpc-web"
//     value: RecordStep is the terminal Pipeline Step, so a recorded
//     grpc-web flow means the envelope traversed every preceding
//     Step.
//
// The full RPC round-trip + hit-count assertions that the gRPC sibling
// asserts are deferred to USK-780 (production lacks Send-direction
// End injection for gRPC-Web; see this file's package comment).
//
// Reverse-canary (manual, document in PR body): with the
// ProtocolGRPCWeb case in WrapH2UpstreamForDispatch reverted, the
// upstream-side wrap stays httpaggregator-only. The first upstream
// Send rejects *envelope.GRPCStartMessage with a type mismatch, the
// session aborts via OnComplete with state="error", and this test's
// foundActiveOrCompleteGRPCWebFlow check fails the deadline because
// every recorded grpc-web flow is in state="error". Restoring the
// branch returns the test to green within ~6s on the smoke tier.
func TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "grpc-web",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	upstreamHostPort := grpcWebUpstreamHostPort(t, h.UpstreamTLS.URL)

	reqPayload := []byte("yorishiro-proxy USK-777 grpc-web echo")

	// Drive the gRPC-Web request in a goroutine. The request may hang
	// or error today (USK-780: production lacks a Send-direction End
	// injection), so we do not gate the test on its return value.
	// Cleanup cancels the request context so the goroutine never leaks.
	reqCtx, cancelReq := context.WithCancel(context.Background())

	var clientWG sync.WaitGroup
	clientWG.Add(1)
	go func() {
		defer clientWG.Done()
		// Bound the per-request timeout below the default test timeout
		// so a hang surfaces as a goroutine return rather than a test
		// hang.
		ctx, cancel := context.WithTimeout(reqCtx, 10*time.Second)
		defer cancel()
		_ = sendGRPCWebRequestThroughProxy(
			ctx, proxyAddr, upstreamHostPort,
			mcptest.GRPCWebSafetyEchoMethod, reqPayload,
		)
	}()
	t.Cleanup(func() {
		cancelReq()
		clientWG.Wait()
	})

	// Acceptance criterion (2): poll for at least one recorded
	// grpc-web flow whose Stream is NOT in state="error". RecordStep
	// runs at the end of the canonical Pipeline, so a recorded grpc-web
	// flow proves at least one envelope reached every Pipeline Step.
	// The state guard differentiates with-fix from without-fix:
	//
	//   * With the ProtocolGRPCWeb branch in WrapH2UpstreamForDispatch
	//     in place, the upstream-side wrap accepts GRPCStartMessage,
	//     the session does not abort, the Stream stays state="active"
	//     (or completes), and message_count rises past 1.
	//   * With that branch reverted, the upstream is httpaggregator-
	//     only; the first upstream Send rejects GRPCStartMessage with a
	//     type mismatch, the session aborts, and OnComplete latches
	//     Stream.State="error" with message_count=1. The state="error"
	//     check below catches that regression deterministically.
	//
	// Pollable: the recording is published asynchronously by RecordStep
	// from the session goroutine, so we wait up to a deadline for the
	// recorded flow to appear. We exit at the FIRST observation of a
	// non-error grpc-web flow — re-checking once a stream has settled
	// would needlessly slow the smoke tier.
	deadline := time.Now().Add(8 * time.Second)
	var lastDecoded map[string]any
	for {
		queryRes := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter": map[string]any{
				"protocol": "grpc-web",
			},
		})
		lastDecoded = queryRes.Decoded
		if foundActiveOrCompleteGRPCWebFlow(queryRes.Decoded) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(flows, protocol=grpc-web): no non-error flow recorded after deadline; either no gRPC-Web envelope reached RecordStep, or the Stream is state=error (which means the upstream Send rejected GRPCStartMessage — i.e. the USK-777 regression). Decoded=%v", lastDecoded)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// foundActiveOrCompleteGRPCWebFlow reports whether the query response
// includes at least one grpc-web flow whose Stream is not in
// state="error". This is the regression discriminator for
// WrapH2UpstreamForDispatch's ProtocolGRPCWeb branch (see
// TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope's polling loop above).
func foundActiveOrCompleteGRPCWebFlow(decoded map[string]any) bool {
	flowsAny, _ := decoded["flows"].([]any)
	for _, fa := range flowsAny {
		fm, _ := fa.(map[string]any)
		if fm == nil {
			continue
		}
		state, _ := fm["state"].(string)
		if state != "error" {
			return true
		}
	}
	return false
}

// grpcWebUpstreamHostPort parses the httptest server URL ("https://h:p")
// returned by mcptest into the "host:port" string the gRPC-Web client
// must reach via CONNECT.
func grpcWebUpstreamHostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse upstream URL %q: %v", rawURL, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return host + ":" + port
}

// sendGRPCWebRequestThroughProxy issues a single unary gRPC-Web request
// through the proxy at proxyAddr to upstreamHostPort. It opens a
// CONNECT tunnel (mirroring openCONNECTTunnel in
// grpc_dispatch_smoke_integration_test.go), layers TLS+ALPN h2 on top,
// and uses x/net/http2.Transport to drive a single POST with an
// LPM-framed request body. The return value is whatever the http
// client surfaced — the caller does not gate on it because the live
// production stack currently lacks a Send-direction End injection
// (USK-780) and may either hang or stream-error.
//
// We hand-roll the client (vs pulling in a third-party gRPC-Web library)
// to keep the dependency surface small and stay aligned with the
// project's "no external proxy libraries" L4/L7 discipline.
func sendGRPCWebRequestThroughProxy(
	ctx context.Context,
	proxyAddr, upstreamHostPort, fullMethod string,
	payload []byte,
) error {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         hostOnly(upstreamHostPort),
			InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
			NextProtos:         []string{"h2"},
			MinVersion:         tls.VersionTLS12,
		},
		DialTLSContext: func(dctx context.Context, _ string, _ string, cfg *tls.Config) (net.Conn, error) {
			rawConn, err := openCONNECTTunnel(dctx, proxyAddr, upstreamHostPort)
			if err != nil {
				return nil, fmt.Errorf("CONNECT tunnel: %w", err)
			}
			tlsConn := tls.Client(rawConn, cfg)
			if err := tlsConn.HandshakeContext(dctx); err != nil {
				_ = rawConn.Close()
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	frame := grpcweb.EncodeFrame(false, false, payload)
	urlStr := "https://" + upstreamHostPort + fullMethod

	req, err := nethttp.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(frame))
	if err != nil {
		return fmt.Errorf("build gRPC-Web request: %w", err)
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("Accept", "application/grpc-web+proto")

	cli := &nethttp.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection is reusable / cleanly closed,
	// even though the test does not gate on its content.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}
