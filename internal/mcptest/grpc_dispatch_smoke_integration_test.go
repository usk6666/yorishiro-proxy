//go:build e2e

// Package mcptest_test holds the regression test for USK-771: live
// production gRPC dispatch must deliver envelopes to the Pipeline
// (and hence to RecordStep) without RST_STREAM(CANCEL)ing the inner
// gRPC stream.
//
// Pre-USK-771, proxybuild.buildOnHTTP2Stack always wrapped the upstream
// HTTP/2 stream with httpaggregator regardless of the client-side
// dispatch decision. When DispatchH2StreamWithOpts routed the client
// side to grpclayer (because the request carried application/grpc),
// the session loop's first upstream Send fed a *envelope.GRPCStartMessage
// to httpaggregator, which rejected it. The error cascade closed the
// upstream stream, surfacing as RST_STREAM(CANCEL) before any envelope
// reached pipeline.SafetyStep / pipeline.RecordStep.
//
// The fix wires connector.WrapH2UpstreamForDispatch into the dial
// closure so the upstream is wrapped with grpclayer.Wrap when the
// client side is gRPC. This file proves the wiring end-to-end by
// driving a real google.golang.org/grpc client through proxy_start
// (which boots the production proxybuild.BuildLiveStack) and asserting
// (a) the RPC completes with a matching echo response, (b) the upstream
// gRPC handler observed exactly one invocation, and (c) the recorded
// flow.Stream carries Protocol="grpc" so the gRPC envelope reached
// RecordStep — which only happens after a non-trivial pass through
// pipeline.SafetyStep / Pipeline as a whole.
//
// The test runs in the smoke tier (plain //go:build e2e) because the
// regression class — "in-package layer tests pass but live
// BuildLiveStack does not" — is exactly what the merge gate exists to
// catch. Promoting to smoke costs ~2-3s of test time but blocks the
// reintroduction of any future structural divergence between the
// hand-rolled gRPC MITM (internal/layer/grpc/grpc_integration_test.go::
// startGRPCMITMProxy) and the production stack assembly.
package mcptest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_LiveGRPC_DispatchDeliversEnvelope is the USK-771 regression
// gate. It boots the production server with a real gRPC upstream
// behind the harness, drives a single unary Echo RPC through
// proxy_start over CONNECT + TLS(h2), and asserts the proxy did NOT
// RST_STREAM(CANCEL) before envelope delivery.
//
// Acceptance criteria (USK-771):
//
//  1. RPC completes end-to-end through the proxy without RST_STREAM
//     — proven by the echo's payload equality and the absence of a
//     gRPC client error.
//  2. At least one *envelope.GRPCDataMessage reaches the Pipeline —
//     proven indirectly via the recorded flow.Stream's Protocol="grpc"
//     value: RecordStep is the terminal Pipeline Step, so a Stream
//     under that protocol means the upstream Send accepted the gRPC
//     envelope (i.e. the dispatch wired grpclayer correctly) AND the
//     envelope traversed every preceding Step.
//  3. The upstream gRPC handler advanced its hit counter exactly
//     once, ruling out a "the proxy invented a response from cache /
//     intercept" false positive.
func TestE2E_LiveGRPC_DispatchDeliversEnvelope(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "grpc",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	upstreamHostPort := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
	cc := dialGRPCThroughProxy(t, proxyAddr, upstreamHostPort)
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	reqPayload := []byte("yorishiro-proxy USK-771 echo")
	var respPayload []byte
	if err := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &reqPayload, &respPayload,
		grpc.ForceCodec(grpcRegressionRawCodec{})); err != nil {
		t.Fatalf("gRPC Invoke through live proxy: %v (this is the USK-771 RST_STREAM(CANCEL) regression if err mentions context cancelled or stream reset)", err)
	}

	if !bytes.Equal(respPayload, reqPayload) {
		t.Fatalf("gRPC echo mismatch: got %q want %q", respPayload, reqPayload)
	}

	// Acceptance criterion (3): upstream handler observed exactly one
	// invocation. Hits=0 would mean the proxy somehow short-circuited
	// the request; hits>1 would mean a duplicate forward. Either way
	// the round-trip would be unsound.
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after gRPC call = %d, want 1", got)
	}
	if got := h.GRPCObservedHits.PerMethod(mcptest.GRPCSafetyEchoMethod); got != 1 {
		t.Fatalf("upstream per-method hits = %d, want 1", got)
	}

	// Acceptance criterion (2): assert at least one gRPC flow was
	// recorded under Protocol="grpc". RecordStep runs at the end of
	// the canonical 8-step Pipeline, so a recorded grpc-protocol
	// stream proves the dispatch decision propagated all the way
	// through Pipeline → upstream Send. Protocol family filter
	// "grpc" matches any envelope whose Message implements
	// envelope.ProtocolGRPC (Start / Data / End).
	queryRes := h.MustOK(t, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"protocol": "grpc",
		},
	})
	flowsAny, _ := queryRes.Decoded["flows"].([]any)
	if len(flowsAny) == 0 {
		t.Fatalf("query(flows, protocol=grpc): no flows recorded; gRPC envelope did not reach RecordStep. Decoded=%v Text=%s", queryRes.Decoded, queryRes.Text)
	}
}

// grpcUpstreamHostPort parses the httptest server URL ("https://h:p")
// returned by mcptest into the "host:port" string the gRPC client must
// reach via CONNECT.
func grpcUpstreamHostPort(t *testing.T, rawURL string) string {
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

// dialGRPCThroughProxy returns a gRPC client connection whose dialer
// reaches upstreamHostPort via an HTTP CONNECT tunnel through the
// proxy at proxyAddr, then layers TLS(NextProtos=h2) on top. The TLS
// peer is verified as InsecureSkipVerify because the proxy MITMs the
// connection with an ephemeral CA whose root the test does not pin.
func dialGRPCThroughProxy(t *testing.T, proxyAddr, upstreamHostPort string) *grpc.ClientConn {
	t.Helper()
	tlsCfg := &tls.Config{
		ServerName:         hostOnly(upstreamHostPort),
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return openCONNECTTunnel(ctx, proxyAddr, upstreamHostPort)
	}
	cc, err := grpc.NewClient(
		upstreamHostPort,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	return cc
}

// openCONNECTTunnel dials the proxy and issues an HTTP/1.1 CONNECT
// request to upstreamHostPort. On success it returns the raw TCP conn
// positioned right after the "200 Connection established" headers so
// gRPC can layer TLS over it. The CONNECT response is bounded to
// 16 KiB to avoid unbounded reads on a misbehaving proxy.
func openCONNECTTunnel(ctx context.Context, proxyAddr, upstreamHostPort string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstreamHostPort, upstreamHostPort)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", rerr)
		}
		if bytes.Contains(buf, []byte("\r\n\r\n")) {
			break
		}
		if len(buf) > 16<<10 {
			_ = conn.Close()
			return nil, errors.New("CONNECT response exceeds 16 KiB")
		}
	}
	if !bytes.Contains(buf, []byte(" 200 ")) && !bytes.HasPrefix(buf, []byte("HTTP/1.1 200")) {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %q", string(buf))
	}
	hdrEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if hdrEnd >= 0 && hdrEnd+4 < len(buf) {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected buffered bytes after CONNECT (%d)", len(buf)-hdrEnd-4)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}
	return conn, nil
}

// hostOnly returns the host portion of a "host:port" string. Used to
// populate tls.Config.ServerName which must NOT include the port.
func hostOnly(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

// grpcRegressionRawCodec is a per-test []byte codec used by the
// USK-771 regression client. Symmetrical to the harness upstream
// codec (mcptest.grpcRawCodec) but registered under a distinct name
// so init order across the test binary cannot trigger
// encoding.RegisterCodec's duplicate-name panic.
const grpcRegressionRawCodecName = "mcptest-usk771-raw"

type grpcRegressionRawCodec struct{}

func (grpcRegressionRawCodec) Name() string { return grpcRegressionRawCodecName }

func (grpcRegressionRawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("grpcRegressionRawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (grpcRegressionRawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("grpcRegressionRawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}
