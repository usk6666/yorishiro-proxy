//go:build e2e && !e2e_smoke

// USK-1376 / USK-1236: gRPC and gRPC-Web requests are judged against
// TargetScope per request — :authority / Host and the request path — the
// same way HTTP requests are. They reach the Pipeline as GRPCStartMessage,
// so before this change a denied vhost on an allowed IP, or a path_prefix
// rule, never applied to them.
package mcptest_test

import (
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// startGRPCScopeProxy boots the harness with a gRPC (or gRPC-Web) upstream
// and the given config, starts the proxy and returns its address and the
// upstream host:port.
func startGRPCScopeProxy(t *testing.T, upstreamProto, configJSON string) (*mcptest.Harness, string, string) {
	t.Helper()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: upstreamProto, ConfigJSON: configJSON})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	return h, proxyAddr, grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
}

// dialGRPCThroughProxyAs is dialGRPCThroughProxy with an optional
// :authority override (also used as the TLS SNI, which grpc-go requires to
// agree with it).
func dialGRPCThroughProxyAs(t *testing.T, proxyAddr, upstreamHostPort, authority string) *grpc.ClientConn {
	t.Helper()
	serverName := hostOnly(upstreamHostPort)
	var opts []grpc.DialOption
	if authority != "" {
		serverName = hostOnly(authority)
		opts = append(opts, grpc.WithAuthority(authority))
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	all := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return openCONNECTTunnel(ctx, proxyAddr, upstreamHostPort)
		}),
	}, opts...)
	cc, err := grpc.NewClient(upstreamHostPort, all...)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// invokeEcho runs one unary call of fullMethod on cc with a short deadline.
func invokeEcho(cc *grpc.ClientConn, fullMethod string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := []byte("usk-1376")
	var resp []byte
	return cc.Invoke(ctx, fullMethod, &req, &resp, grpc.ForceCodec(grpcRegressionRawCodec{}))
}

// assertPermissionDenied asserts err is a gRPC PERMISSION_DENIED status.
func assertPermissionDenied(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: call succeeded, want PERMISSION_DENIED (target_scope)", what)
	}
	if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied {
		t.Errorf("%s: status %v, want PermissionDenied", what, err)
	}
}

// waitBlockedStream polls query(flows) for an audit Stream of protocol
// with blocked_by=target_scope and asserts it is state=error.
func waitBlockedStream(t *testing.T, h *mcptest.Harness, protocol string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"blocked_by": "target_scope", "protocol": protocol},
		})
		flows, _ := res.Decoded["flows"].([]any)
		for _, raw := range flows {
			f, _ := raw.(map[string]any)
			if f["protocol"] != protocol || f["blocked_by"] != "target_scope" {
				continue
			}
			if st, _ := f["state"].(string); !strings.EqualFold(st, "error") {
				t.Errorf("blocked %s Stream state = %q, want error", protocol, st)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("query(flows, protocol=%s, blocked_by=target_scope) returned no Stream", protocol)
}

// E1: over CONNECT, a native gRPC call whose :authority names a denied
// vhost on the allowed IP is refused with PERMISSION_DENIED, never reaches
// the upstream and leaves a grpc target_scope audit Stream. A non-denied
// vhost still passes (Option B).
func TestE2E_GRPCRequestScope_CONNECT_DeniedAuthority(t *testing.T) {
	h, proxyAddr, up := startGRPCScopeProxy(t, "grpc", hostScopePolicyConfig)

	// grpc-go requires the :authority to equal the TLS ServerName, so the
	// names are port-less (judged on the dial port).
	if err := invokeEcho(dialGRPCThroughProxyAs(t, proxyAddr, up, "vhost.example"), mcptest.GRPCSafetyEchoMethod); err != nil {
		t.Fatalf("non-denied :authority vhost.example: %v, want success", err)
	}
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after the allowed call = %d, want 1", got)
	}

	err := invokeEcho(dialGRPCThroughProxyAs(t, proxyAddr, up, "denied.example"), mcptest.GRPCSafetyEchoMethod)
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the denied :authority reached the upstream", got)
	}
	assertPermissionDenied(t, err, ":authority denied.example")
	waitBlockedStream(t, h, "grpc")
}

// E2: a path_prefix deny applies to gRPC methods; a non-matching prefix
// does not.
func TestE2E_GRPCRequestScope_CONNECT_PathPrefixDeny(t *testing.T) {
	cfg := `{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1","path_prefix":"/yorishiro.test.Safety/"}]}}`
	h, proxyAddr, up := startGRPCScopeProxy(t, "grpc", cfg)
	cc := dialGRPCThroughProxyAs(t, proxyAddr, up, "")

	assertPermissionDenied(t, invokeEcho(cc, mcptest.GRPCSafetyEchoMethod), "Echo under a path_prefix deny")
	if got := h.GRPCObservedHits.Total(); got != 0 {
		t.Errorf("upstream hits = %d, want 0 — the path_prefix deny did not apply to gRPC", got)
	}
	waitBlockedStream(t, h, "grpc")

	h2, proxyAddr2, up2 := startGRPCScopeProxy(t, "grpc",
		`{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1","path_prefix":"/other.Service/"}]}}`)
	if err := invokeEcho(dialGRPCThroughProxyAs(t, proxyAddr2, up2, ""), mcptest.GRPCSafetyEchoMethod); err != nil {
		t.Fatalf("Echo under a non-matching path_prefix deny: %v, want success", err)
	}
	if got := h2.GRPCObservedHits.Total(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

// E3: a path_prefix allow admits the gRPC methods under it and refuses the
// rest (before, every gRPC call on a path-scoped allow failed closed).
func TestE2E_GRPCRequestScope_CONNECT_PathPrefixAllow(t *testing.T) {
	cfg := `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1","path_prefix":"/yorishiro.test.Safety/"}]}}`
	h, proxyAddr, up := startGRPCScopeProxy(t, "grpc", cfg)
	cc := dialGRPCThroughProxyAs(t, proxyAddr, up, "")

	if err := invokeEcho(cc, mcptest.GRPCSafetyEchoMethod); err != nil {
		t.Fatalf("Echo under its path_prefix allow: %v, want success", err)
	}
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	assertPermissionDenied(t, invokeEcho(cc, "/other.Service/Do"), "method outside the allowed prefix")
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
	waitBlockedStream(t, h, "grpc")
}

// sendGRPCWebAs drives one gRPC-Web (binary) POST over CONNECT + TLS(h2)
// with :authority set to authority. It returns the HTTP status, or an
// error (a blocked gRPC-Web request is dropped, so the client times out).
func sendGRPCWebAs(proxyAddr, upstreamHostPort, authority, fullMethod string) (int, error) {
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
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "https://"+upstreamHostPort+fullMethod,
		bytes.NewReader(grpcweb.EncodeFrame(false, false, []byte("usk-1376"))))
	if err != nil {
		return 0, err
	}
	req.Host = authority
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// E4: gRPC-Web over HTTP/2 with a denied :authority never reaches the
// upstream and leaves a grpc-web target_scope audit Stream.
func TestE2E_GRPCRequestScope_GRPCWebH2_DeniedAuthority(t *testing.T) {
	h, proxyAddr, up := startGRPCScopeProxy(t, "grpc-web", hostScopePolicyConfig)
	_, port, _ := net.SplitHostPort(up)

	if code, err := sendGRPCWebAs(proxyAddr, up, "vhost.example:"+port, mcptest.GRPCWebSafetyEchoMethod); err != nil || code != 200 {
		t.Fatalf("non-denied :authority: status %d err %v, want 200", code, err)
	}
	if got := h.GRPCWebObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after the allowed call = %d, want 1", got)
	}

	if code, err := sendGRPCWebAs(proxyAddr, up, "denied.example:"+port, mcptest.GRPCWebSafetyEchoMethod); err == nil && code == 200 {
		t.Errorf("denied :authority answered 200")
	}
	if got := h.GRPCWebObservedHits.Total(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the denied :authority reached the upstream", got)
	}
	waitBlockedStream(t, h, "grpc-web")
}

// writeProxyRequestNoWait writes one raw request to the forward proxy and
// reads whatever comes back within 3s (a blocked gRPC-Web request is
// dropped without a response).
func writeProxyRequestNoWait(t *testing.T, proxyAddr, request string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	b, _ := io.ReadAll(c)
	return string(b)
}

// E5: plain-forward gRPC-Web over HTTP/1.x — the Host header (first, or a
// duplicate second one) naming a denied vhost on an allowed absolute-form
// target never reaches the upstream.
func TestE2E_GRPCRequestScope_GRPCWebH1_DeniedHost(t *testing.T) {
	upstreamAddr, received, lastHead := byteCountingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)

	body := string(grpcweb.EncodeFrame(false, false, []byte("usk-1376")))
	request := func(hostLines string) string {
		return fmt.Sprintf("POST http://%s/pkg.Echo/Say HTTP/1.1\r\n%sContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			upstreamAddr, hostLines, len(body), body)
	}

	_ = writeProxyRequestNoWait(t, proxyAddr, request("Host: vhost.example\r\n"))
	deadline := time.Now().Add(3 * time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(lastHead(), "vhost.example") {
		t.Fatalf("non-denied Host did not reach the upstream (head %q)", lastHead())
	}

	for _, tc := range []struct{ name, hostLines string }{
		{"first Host denied", "Host: denied.example\r\n"},
		{"duplicate second host denied", "Host: " + upstreamAddr + "\r\nhost: denied.example\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := received.Load()
			_ = writeProxyRequestNoWait(t, proxyAddr, request(tc.hostLines))
			time.Sleep(200 * time.Millisecond)
			if got := received.Load() - before; got != 0 {
				t.Errorf("upstream received %d bytes (head %q), want 0 — the denied Host reached it", got, lastHead())
			}
			waitBlockedStream(t, h, "grpc-web")
		})
	}
}
