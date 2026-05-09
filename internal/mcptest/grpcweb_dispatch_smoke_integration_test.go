//go:build e2e

// Package mcptest_test holds the regression test for USK-777 / USK-780:
// live production gRPC-Web dispatch must deliver envelopes to the
// Pipeline (and hence to RecordStep) AND complete a unary round-trip
// without hanging at the upstream Send buffer.
//
// USK-771 (PR #761) added connector.WrapH2UpstreamForDispatch with three
// branches (ProtocolGRPC / ProtocolGRPCWeb / default). The gRPC branch
// is exercised end-to-end by TestE2E_LiveGRPC_DispatchDeliversEnvelope
// via a real grpc-go client. USK-777 added the gRPC-Web envelope-delivery
// gate; USK-780 closed the End-injection gap inside the grpcweb Layer so
// well-formed unary RPCs flush cleanly to upstream. This file is the
// merged smoke gate for both: it boots the production server with a
// hand-rolled http2.Server upstream, drives a single unary Echo through
// proxy_start over CONNECT + TLS(h2), and asserts (a) the RPC completes
// with a matching echo response, (b) Harness.GRPCWebObservedHits records
// exactly one invocation, and (c) the recorded flow.Stream carries
// Protocol="grpc-web". Both binary (application/grpc-web+proto) and
// base64/text (application/grpc-web-text+proto) wire formats are
// exercised via a table.
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
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope is the merged USK-777 /
// USK-780 regression gate. It boots the production server with a real
// gRPC-Web upstream behind the harness, drives a single unary Echo over
// the gRPC-Web wire under both binary and base64/text content types
// through proxy_start via CONNECT + TLS(h2), and asserts the proxy did
// not RST_STREAM(CANCEL), did not hang at the upstream Send buffer, and
// did record the envelope through every Pipeline Step.
//
// Acceptance criteria (USK-777 + USK-780):
//
//  1. RPC request flows through the proxy: the dispatcher recognises
//     application/grpc-web[-text]+proto and wraps the upstream stream
//     with httpaggregator + grpcweb (USK-777). USK-780's Layer-internal
//     Send-direction End sentinel is what lets the upstream side flush
//     the assembled HTTPMessage, so a successful round-trip is what
//     verifies the fix is wired in production.
//  2. RPC completes end-to-end: response payload bytes match the
//     request payload bytes.
//  3. Upstream observed exactly one invocation per content-type
//     variant — Harness.GRPCWebObservedHits.PerMethod increments by
//     one per round-trip; Total accumulates across the table.
//  4. At least one recorded grpc-web flow per variant: RecordStep is
//     terminal in the Pipeline, so the recorded flow proves the
//     envelope traversed every preceding Step.
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

	cases := []struct {
		name       string
		base64Wire bool
		contentTyp string
	}{
		{"binary_proto", false, "application/grpc-web+proto"},
		{"text_base64_proto", true, "application/grpc-web-text+proto"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			reqPayload := []byte(fmt.Sprintf("yorishiro-proxy USK-780 grpc-web echo %s", tc.name))

			respPayload, err := sendGRPCWebRequestThroughProxy(
				ctx, proxyAddr, upstreamHostPort,
				mcptest.GRPCWebSafetyEchoMethod, reqPayload, tc.base64Wire, tc.contentTyp,
			)
			if err != nil {
				t.Fatalf("gRPC-Web round-trip through live proxy (%s): %v (this is the USK-780 hang-at-upstream-Send-buffer regression if err mentions context deadline or stream reset)", tc.name, err)
			}

			if !bytes.Equal(respPayload, reqPayload) {
				t.Fatalf("gRPC-Web echo mismatch (%s): got %q want %q", tc.name, respPayload, reqPayload)
			}

			// Acceptance criterion (3): upstream handler observed exactly
			// one additional invocation for this variant. Hits=0 means the
			// proxy short-circuited; hits>1 means a duplicate forward.
			if got := h.GRPCWebObservedHits.PerMethod(mcptest.GRPCWebSafetyEchoMethod); got != int64(i+1) {
				t.Fatalf("upstream per-method hits after %s = %d, want %d", tc.name, got, i+1)
			}
			if got := h.GRPCWebObservedHits.Total(); got != int64(i+1) {
				t.Fatalf("upstream total hits after %s = %d, want %d", tc.name, got, i+1)
			}

			// Acceptance criterion (4): at least one grpc-web flow recorded
			// in non-error state. RecordStep runs at the end of the
			// canonical Pipeline; a non-error grpc-web flow proves
			// the envelope reached every preceding Step.
			queryRes := h.MustOK(t, "query", map[string]any{
				"resource": "flows",
				"filter": map[string]any{
					"protocol": "grpc-web",
				},
			})
			if !foundActiveOrCompleteGRPCWebFlow(queryRes.Decoded) {
				t.Fatalf("query(flows, protocol=grpc-web) after %s: no non-error flow recorded; envelope did not reach RecordStep, or the Stream is state=error. Decoded=%v", tc.name, queryRes.Decoded)
			}
		})
	}
}

// foundActiveOrCompleteGRPCWebFlow reports whether the query response
// includes at least one grpc-web flow whose Stream is not in
// state="error".
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
// through the proxy at proxyAddr to upstreamHostPort. It opens a CONNECT
// tunnel (mirroring openCONNECTTunnel in
// grpc_dispatch_smoke_integration_test.go), layers TLS+ALPN h2 on top,
// and uses x/net/http2.Transport to drive a single POST with an
// LPM-framed request body. Returns the decoded payload of the first
// response data frame on success.
//
// We hand-roll the client (vs pulling in a third-party gRPC-Web library)
// to keep the dependency surface small and stay aligned with the
// project's "no external proxy libraries" L4/L7 discipline. base64Wire
// controls request body wrapping and the upstream's response wire form;
// the response is parsed symmetrically.
func sendGRPCWebRequestThroughProxy(
	ctx context.Context,
	proxyAddr, upstreamHostPort, fullMethod string,
	payload []byte,
	base64Wire bool,
	contentType string,
) ([]byte, error) {
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
	body := frame
	if base64Wire {
		body = grpcweb.EncodeBase64Body(frame)
	}
	urlStr := "https://" + upstreamHostPort + fullMethod

	req, err := nethttp.NewRequestWithContext(ctx, "POST", urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build gRPC-Web request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)

	cli := &nethttp.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != nethttp.StatusOK {
		return nil, fmt.Errorf("upstream HTTP status %d: body=%q", resp.StatusCode, respBody)
	}

	parsed, perr := grpcweb.DecodeBody(respBody, base64Wire)
	if perr != nil {
		return nil, fmt.Errorf("decode response gRPC-Web body: %w", perr)
	}
	if len(parsed.DataFrames) == 0 {
		return nil, fmt.Errorf("response had no data frame; trailers=%v", parsed.Trailers)
	}
	return parsed.DataFrames[0].Payload, nil
}
