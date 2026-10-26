//go:build e2e && !e2e_smoke

// USK-1220: a SafetyFilter block of a gRPC-Web request — on the Data
// payload or on the Start — sends nothing upstream and answers the client
// with the gRPC-Web form of the native-gRPC PERMISSION_DENIED terminator:
// HTTP 200 whose body is a single trailer frame carrying grpc-status 7. The
// audit Stream is recorded with state=error and blocked_by=safety_filter,
// the same rule as an HTTP or native-gRPC block. Driven through the
// production wiring (mcptest JSON-RPC harness + proxybuild).
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// grpcWebBlockedMaxWait bounds how long the proxy may take to answer a
// blocked gRPC-Web request.
const grpcWebBlockedMaxWait = 2 * time.Second

// grpcWebH2Response is what sendGRPCWebH2 observed.
type grpcWebH2Response struct {
	status  int
	header  nethttp.Header
	body    []byte
	elapsed time.Duration
}

// sendGRPCWebH2 drives one gRPC-Web POST of body with content-type ct over
// CONNECT + TLS(h2) and returns the response. A non-empty authority
// overrides :authority.
func sendGRPCWebH2(proxyAddr, upstreamHostPort, authority, fullMethod, ct string, body []byte) (*grpcWebH2Response, error) {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         hostOnly(upstreamHostPort),
			InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
			NextProtos:         []string{"h2"},
			MinVersion:         tls.VersionTLS12,
		},
		DialTLSContext: func(dctx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
			rawConn, err := openCONNECTTunnel(dctx, proxyAddr, upstreamHostPort)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(rawConn, cfg)
			if err := tc.HandshakeContext(dctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "https://"+upstreamHostPort+fullMethod, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if authority != "" {
		req.Host = authority
	}
	req.Header.Set("Content-Type", ct)
	start := time.Now()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return &grpcWebH2Response{status: resp.StatusCode, header: resp.Header, body: b, elapsed: time.Since(start)}, nil
}

// grpcWebTrailerFrame decodes body (base64 for a -text content-type) and
// returns the trailers of its trailer frame plus the number of data frames.
func grpcWebTrailerFrame(t *testing.T, ct string, body []byte) (map[string]string, int) {
	t.Helper()
	res, err := grpcweb.DecodeBody(body, grpcweb.IsBase64Encoded(ct))
	if err != nil {
		t.Fatalf("decode gRPC-Web body %q: %v", body, err)
	}
	if res.TrailerFrame == nil {
		t.Fatalf("gRPC-Web body %q carries no trailer frame", body)
	}
	trailers, err := grpcweb.ParseTrailers(res.TrailerFrame.Payload)
	if err != nil {
		t.Fatalf("parse trailers: %v", err)
	}
	return trailers, len(res.DataFrames)
}

// assertGRPCWebBlockTrailers asserts the terminator trailer frame names the
// blocking mechanism with grpc-status 7 and carries no data frames.
func assertGRPCWebBlockTrailers(t *testing.T, ct string, body []byte, blockedBy string) {
	t.Helper()
	trailers, dataFrames := grpcWebTrailerFrame(t, ct, body)
	if dataFrames != 0 {
		t.Errorf("terminator body carries %d data frames, want 0", dataFrames)
	}
	if trailers["grpc-status"] != "7" {
		t.Errorf("trailer grpc-status = %q, want 7 (PERMISSION_DENIED); trailers %v", trailers["grpc-status"], trailers)
	}
	if !strings.Contains(trailers["grpc-message"], blockedBy) {
		t.Errorf("trailer grpc-message = %q, want it to contain %q", trailers["grpc-message"], blockedBy)
	}
	if trailers["server"] != "yorishiro-proxy" {
		t.Errorf("trailer server = %q, want yorishiro-proxy", trailers["server"])
	}
}

// countBlockedStreamsBy returns how many Streams of protocol blocked by
// blockedBy the query tool reports, reporting an error for any such Stream
// whose state is not "error".
func countBlockedStreamsBy(t *testing.T, h *mcptest.Harness, protocol, blockedBy string) int {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flows",
		"filter":   map[string]any{"blocked_by": blockedBy, "protocol": protocol},
	})
	flows, _ := res.Decoded["flows"].([]any)
	n := 0
	for _, raw := range flows {
		f, _ := raw.(map[string]any)
		if f["protocol"] != protocol || f["blocked_by"] != blockedBy {
			continue
		}
		if st, _ := f["state"].(string); !strings.EqualFold(st, "error") {
			t.Errorf("blocked %s Stream state = %q, want error", protocol, st)
		}
		n++
	}
	return n
}

// waitBlockedStreamsBy waits until at least want Streams of protocol
// blocked by blockedBy are recorded.
func waitBlockedStreamsBy(t *testing.T, h *mcptest.Harness, protocol, blockedBy string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	got := 0
	for time.Now().Before(deadline) {
		if got = countBlockedStreamsBy(t, h, protocol, blockedBy); got >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("query(flows, protocol=%s, blocked_by=%s) returned %d Streams, want at least %d", protocol, blockedBy, got, want)
}

// T1 / T3: over CONNECT + h2, a gRPC-Web request whose payload matches the
// destructive-sql preset (binary and -text wire forms) is answered with HTTP
// 200 + a trailer frame holding grpc-status 7 in the request's content-type,
// never reaches the upstream, and leaves a grpc-web safety_filter audit
// Stream with state=error. A benign request first proves the path works.
func TestE2E_GRPCWebSafetyBlock_H2_DataTerminator(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterDestructiveSQLConfig,
		UpstreamProto: "grpc-web",
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	up := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)

	benign, err := sendGRPCWebH2(proxyAddr, up, "", mcptest.GRPCWebSafetyEchoMethod, "application/grpc-web+proto",
		grpcweb.EncodeFrame(false, false, []byte("SELECT 1")))
	if err != nil || benign.status != 200 {
		t.Fatalf("benign gRPC-Web call: %+v err %v, want 200", benign, err)
	}
	if got := h.GRPCWebObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after the benign call = %d, want 1", got)
	}
	if got := h.GRPCWebObservedHits.Requests(); got != 1 {
		t.Fatalf("upstream requests after the benign call = %d, want 1", got)
	}

	sqlFrame := grpcweb.EncodeFrame(false, false, []byte("DROP TABLE users"))
	for i, tc := range []struct {
		name string
		ct   string
		body []byte
	}{
		{"binary", "application/grpc-web+proto", sqlFrame},
		{"text", "application/grpc-web-text+proto", grpcweb.EncodeBase64Body(sqlFrame)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sendGRPCWebH2(proxyAddr, up, "", mcptest.GRPCWebSafetyEchoMethod, tc.ct, tc.body)
			if err != nil {
				t.Fatalf("blocked gRPC-Web call: %v (want the gRPC-Web terminator)", err)
			}
			if resp.status != 200 {
				t.Errorf("HTTP status = %d, want 200", resp.status)
			}
			if got := resp.header.Get("Content-Type"); got != tc.ct {
				t.Errorf("Content-Type = %q, want %q", got, tc.ct)
			}
			if got := resp.header.Get("Grpc-Status"); got != "" {
				t.Errorf("grpc-status header = %q, want none (the status travels in the trailer frame)", got)
			}
			assertGRPCWebBlockTrailers(t, tc.ct, resp.body, "safety_filter")
			if resp.elapsed > grpcWebBlockedMaxWait {
				t.Errorf("blocked call answered after %v, want < %v", resp.elapsed, grpcWebBlockedMaxWait)
			}
			if got := h.GRPCWebObservedHits.Total(); got != 1 {
				t.Errorf("upstream hits = %d, want 1 — the blocked request reached the upstream", got)
			}
			// Total only counts well-formed calls; a payload-stripped
			// request leaking upstream shows up only in Requests.
			if got := h.GRPCWebObservedHits.Requests(); got != 1 {
				t.Errorf("upstream requests = %d, want 1 — the blocked request (possibly payload-stripped) reached the upstream", got)
			}
			waitBlockedStreamsBy(t, h, "grpc-web", "safety_filter", i+1)
		})
	}
	// Re-check once the audit Streams are recorded, so a leak that lands
	// after the client already has its terminator is still caught.
	if got := h.GRPCWebObservedHits.Requests(); got != 1 {
		t.Errorf("upstream requests after the blocked calls = %d, want 1", got)
	}
}

// readH1Response reads one HTTP/1.x response from br and returns it with
// its full body.
func readH1Response(t *testing.T, br *bufio.Reader) (*nethttp.Response, []byte) {
	t.Helper()
	resp, err := nethttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, body
}

// T2: plain-forward gRPC-Web over HTTP/1.x whose Start carries a
// destructive query is answered with HTTP 200 + a trailer frame holding
// grpc-status 7; the upstream receives no byte; the audit Stream is
// error / safety_filter; and the client's keep-alive connection survives —
// a second, benign request on it reaches the upstream.
func TestE2E_GRPCWebSafetyBlock_H1_StartTerminator_KeepAlive(t *testing.T) {
	upstreamAddr, received, lastHead := byteCountingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: safetyFilterDestructiveSQLConfig})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)

	body := string(grpcweb.EncodeFrame(false, false, []byte("benign")))
	request := func(target string) string {
		return fmt.Sprintf("POST http://%s%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web\r\nContent-Length: %d\r\n\r\n%s",
			upstreamAddr, target, upstreamAddr, len(body), body)
	}

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)

	start := time.Now()
	if _, err := io.WriteString(c, request("/pkg.Echo/Say?q=DROP/**/TABLE/**/users")); err != nil {
		t.Fatalf("write blocked request: %v", err)
	}
	resp, respBody := readH1Response(t, br)
	elapsed := time.Since(start)
	if resp.StatusCode != 200 {
		t.Errorf("blocked request HTTP status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/grpc-web" {
		t.Errorf("Content-Type = %q, want application/grpc-web (mirrored from the request)", got)
	}
	assertGRPCWebBlockTrailers(t, "application/grpc-web", respBody, "safety_filter")
	if elapsed > grpcWebBlockedMaxWait {
		t.Errorf("blocked request answered after %v, want < %v", elapsed, grpcWebBlockedMaxWait)
	}
	time.Sleep(200 * time.Millisecond)
	if got := received.Load(); got != 0 {
		t.Errorf("upstream received %d bytes (head %q), want 0 — the blocked request reached it", got, lastHead())
	}
	waitBlockedStreamsBy(t, h, "grpc-web", "safety_filter", 1)

	// Same connection: a benign request must still be proxied.
	if _, err := io.WriteString(c, request("/pkg.Echo/Say")); err != nil {
		t.Fatalf("write follow-up request on the same connection: %v", err)
	}
	if resp2, _ := readH1Response(t, br); resp2.StatusCode != 200 {
		t.Errorf("follow-up HTTP status = %d, want 200", resp2.StatusCode)
	}
	if got := received.Load(); got == 0 {
		t.Errorf("follow-up request on the keep-alive connection did not reach the upstream")
	}
}
