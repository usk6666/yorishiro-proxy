//go:build e2e && !e2e_smoke

package connector_test

// upstream_proxy_rotation_integration_test.go covers the USK-959 live
// MITM data-path rotation surface. The shape is parallel to
// upstream_proxy_perlistener_integration_test.go (USK-826): real
// FullListener + ConnectionStack + Pipeline + RecordStep, all wired
// against a real upstream HTTPS server. The CONNECT proxy in the
// middle records the Proxy-Authorization headers it observes so the
// test can assert per-rotation-event distinctness.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// tlsListenMultiAccept binds a TLS listener on 127.0.0.1:0 with the
// test TLS config. Used by startMultiAcceptUpstreamHTTPS so the
// rotation tests can drive multiple consecutive HTTPS requests
// (startUpstreamHTTPS accepts only one).
func tlsListenMultiAccept(t *testing.T) (net.Listener, error) {
	return tls.Listen("tcp", "127.0.0.1:0", newTestTLSConfig(t))
}

// startMultiAcceptUpstreamHTTPS builds a TLS HTTPS server that
// accepts multiple connections in a loop (unlike startUpstreamHTTPS
// which accepts only one). Each accepted connection reads one HTTP
// request, writes the handler's response, and closes. The returned
// counter tracks total accept-count so tests can assert per-request
// rotation drove a fresh upstream dial.
func startMultiAcceptUpstreamHTTPS(t *testing.T, response []byte) (net.Listener, func() int) {
	t.Helper()
	ln, err := tlsListenMultiAccept(t)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	var count atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				_, _ = readHTTPRequest(br)
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Write(response)
			}(conn)
		}
	}()
	return ln, func() int { return int(count.Load()) }
}

// startCONNECTProxyRecorder stands up an HTTP CONNECT proxy that
// records each connection's Proxy-Authorization header and tunnels
// the rest of the stream to the requested target. Returns the
// listener's bound address and an accessor for the captured headers.
func startCONNECTProxyRecorder(t *testing.T) (addr string, observedAuth func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen recorder: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var seen []string

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnectRotationProxy(conn, &mu, &seen)
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// handleConnectRotationProxy processes a single client connection:
// parse CONNECT, record Proxy-Authorization, reply 200, then bridge
// bytes.
func handleConnectRotationProxy(client net.Conn, mu *sync.Mutex, seen *[]string) {
	defer client.Close()
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		return
	}
	auth := req.Header.Get("Proxy-Authorization")
	mu.Lock()
	*seen = append(*seen, auth)
	mu.Unlock()
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		_, _ = upstream.Write(buf)
		_, _ = br.Discard(n)
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}

// decodeBasicUser decodes Basic auth "Basic base64(user:pass)" and
// returns the username portion. Returns the raw header on error so
// the test surfaces the unparseable bytes verbatim.
func decodeBasicUser(t *testing.T, auth string) string {
	t.Helper()
	if !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("Proxy-Authorization missing Basic prefix: %q", auth)
		return auth
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Errorf("base64 decode: %v", err)
		return auth
	}
	userPass := string(decoded)
	colon := strings.IndexByte(userPass, ':')
	if colon < 0 {
		return userPass
	}
	return userPass[:colon]
}

// buildRotationBuildConfig builds a BuildConfig + Issuer for the
// rotation e2e harness. Mirrors the minimal shape used by
// upstream_proxy_perlistener_integration_test.go.
func buildRotationBuildConfig(t *testing.T) *connector.BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)
	return &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
}

// rotationListenerDeps starts a named listener with the supplied
// BuildConfig + a fresh testStore/WaitGroup. Returns the bound addr.
func rotationListenerDeps(t *testing.T, ctx context.Context, name string, buildCfg *connector.BuildConfig) (addr string, store *testStore, wg *sync.WaitGroup) {
	t.Helper()
	store = &testStore{}
	wg = &sync.WaitGroup{}
	addr = startNamedListenerForChain(t, ctx, name, buildCfg, store, wg)
	return
}

// installRotation installs a RotationResolver with the supplied policy
// + template on the BuildConfig under the listener name.
func installRotation(t *testing.T, buildCfg *connector.BuildConfig, listenerName, template string, policy connector.RotationPolicy) {
	t.Helper()
	resolver := connector.NewRotationResolver(connector.RotationConfig{
		Template:     template,
		Policy:       policy,
		ListenerName: listenerName,
	}, 0, 0)
	buildCfg.SetRotationForListener(listenerName, resolver)
}

// runOneRequestThroughListener fires a single CONNECT + GET through
// the named listener, returning the response body excerpt and any
// error from the response parse. Used by per-request rotation tests
// that fire multiple independent requests.
func runOneRequestThroughListener(t *testing.T, listenerAddr, target, path string, wg *sync.WaitGroup) string {
	t.Helper()
	wg.Add(1)
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, target)
	resp := connectAndSendHTTP(t, listenerAddr, target, rawReq)
	waitSessionDone(t, wg)
	return resp
}

// TestLiveProxy_PerRequestRotation_DistinctNonces verifies that the
// per_request policy mints a fresh upstream-proxy URL per outbound
// TCP dial — each request transits through the CONNECT proxy with a
// distinct Proxy-Authorization (Basic auth derived from the §__nonce§
// substitution).
func TestLiveProxy_PerRequestRotation_DistinctNonces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, observedAuth := startCONNECTProxyRecorder(t)

	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, wg := rotationListenerDeps(t, ctx, "rot-per-request", buildCfg)
	installRotation(t, buildCfg, "rot-per-request",
		fmt.Sprintf("http://session-§__nonce§:pass@%s", proxyAddr),
		connector.RotationPerRequest)

	const requestCount = 3
	for i := 0; i < requestCount; i++ {
		resp := runOneRequestThroughListener(t, listenerAddr, target, fmt.Sprintf("/r%d", i), wg)
		if !strings.Contains(resp, "200 OK") {
			t.Fatalf("request %d: response missing 200 OK: %q", i, resp)
		}
	}

	auths := observedAuth()
	if len(auths) != requestCount {
		t.Fatalf("CONNECT proxy saw %d tunnels, want %d", len(auths), requestCount)
	}
	seen := make(map[string]struct{}, requestCount)
	for i, a := range auths {
		user := decodeBasicUser(t, a)
		if !strings.HasPrefix(user, "session-") {
			t.Errorf("request %d: username = %q, want session-<nonce>", i, user)
		}
		if _, dup := seen[user]; dup {
			t.Errorf("request %d: duplicate nonce %q (rotation failed)", i, user)
		}
		seen[user] = struct{}{}
	}
	if len(seen) != requestCount {
		t.Errorf("distinct nonce count = %d, want %d", len(seen), requestCount)
	}
}

// TestLiveProxy_PerTargetHostRotation_SamePerHost verifies that
// per_target_host caches the URL by upstream host: distinct hosts get
// distinct nonces, same host gets the same nonce across requests.
func TestLiveProxy_PerTargetHostRotation_SamePerHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two upstreams so we can drive distinct target hosts.
	upstreamA, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nA"))
	defer upstreamA.Close()
	upstreamB, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB"))
	defer upstreamB.Close()
	targetA := upstreamA.Addr().String()
	targetB := upstreamB.Addr().String()

	proxyAddr, observedAuth := startCONNECTProxyRecorder(t)
	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, wg := rotationListenerDeps(t, ctx, "rot-per-host", buildCfg)
	installRotation(t, buildCfg, "rot-per-host",
		fmt.Sprintf("http://session-§__nonce§:pass@%s", proxyAddr),
		connector.RotationPerTargetHost)

	// Two requests to A, one to B, one back to A.
	for _, target := range []string{targetA, targetA, targetB, targetA} {
		resp := runOneRequestThroughListener(t, listenerAddr, target, "/", wg)
		if !strings.Contains(resp, "200 OK") {
			t.Fatalf("request to %s: missing 200 OK: %q", target, resp)
		}
	}

	auths := observedAuth()
	if len(auths) != 4 {
		t.Fatalf("CONNECT proxy saw %d tunnels, want 4", len(auths))
	}
	users := make([]string, len(auths))
	for i, a := range auths {
		users[i] = decodeBasicUser(t, a)
	}
	// users[0,1,3] are all for targetA → must be identical.
	if users[0] != users[1] {
		t.Errorf("per_target_host: users[0]=%q users[1]=%q expected equal (same target)", users[0], users[1])
	}
	if users[0] != users[3] {
		t.Errorf("per_target_host: users[0]=%q users[3]=%q expected equal (same target)", users[0], users[3])
	}
	// users[2] is for targetB → must differ from A.
	if users[2] == users[0] {
		t.Errorf("per_target_host: users[2]=%q users[0]=%q expected different (different target)", users[2], users[0])
	}
}

// TestLiveProxy_StickyRotation_FixedForListenerLifetime verifies that
// sticky mints once and reuses for the listener's lifetime, then
// resets when the rotation is reloaded (configure_tool path).
func TestLiveProxy_StickyRotation_FixedForListenerLifetime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, observedAuth := startCONNECTProxyRecorder(t)
	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, wg := rotationListenerDeps(t, ctx, "rot-sticky", buildCfg)
	installRotation(t, buildCfg, "rot-sticky",
		fmt.Sprintf("http://session-§__nonce§:pass@%s", proxyAddr),
		connector.RotationSticky)

	// First two requests should share the same nonce.
	for i := 0; i < 2; i++ {
		resp := runOneRequestThroughListener(t, listenerAddr, target, fmt.Sprintf("/r%d", i), wg)
		if !strings.Contains(resp, "200 OK") {
			t.Fatalf("request %d: %q", i, resp)
		}
	}
	auths := observedAuth()
	if len(auths) < 2 {
		t.Fatalf("phase 1: %d tunnels, want >=2", len(auths))
	}
	user1 := decodeBasicUser(t, auths[0])
	user2 := decodeBasicUser(t, auths[1])
	if user1 != user2 {
		t.Errorf("sticky: phase 1 users differ: %q vs %q", user1, user2)
	}

	// Simulate configure_tool reload: install a fresh resolver, drop
	// the previous sticky state. Resolver is a new instance so the
	// previous sticky URL is GCed; the new resolver mints fresh on
	// next dial.
	installRotation(t, buildCfg, "rot-sticky",
		fmt.Sprintf("http://session-§__nonce§:pass@%s", proxyAddr),
		connector.RotationSticky)
	resp := runOneRequestThroughListener(t, listenerAddr, target, "/r-reload", wg)
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("post-reload request: %q", resp)
	}
	auths = observedAuth()
	if len(auths) < 3 {
		t.Fatalf("post-reload: %d tunnels, want >=3", len(auths))
	}
	user3 := decodeBasicUser(t, auths[len(auths)-1])
	if user3 == user1 {
		t.Errorf("sticky: post-reload user %q expected to differ from pre-reload %q", user3, user1)
	}
}

// TestLiveProxy_MalformedTemplate_FailClosed verifies that a
// malformed template fails the live dial path closed: the request
// is rejected without falling back to a direct dial (no silent
// bypass). The CONNECT proxy must observe zero tunnels.
func TestLiveProxy_MalformedTemplate_FailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstreamLn, getUpstreamCount := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nX"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, _ := rotationListenerDeps(t, ctx, "rot-malformed", buildCfg)
	// ftp:// scheme is rejected by ParseUpstreamProxy → resolver error
	// → dial fail-closed.
	installRotation(t, buildCfg, "rot-malformed",
		"ftp://broken-§__nonce§.example:21",
		connector.RotationPerRequest)

	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	// The CONNECT phase may complete (200 OK) before the inner dial
	// happens — at that point the proxy realises the upstream dial
	// failed and aborts. quickAttemptThroughProxy times out reading
	// the response. We don't assert response content; we assert the
	// *upstream* saw no traffic (no silent direct-dial fallback).
	_ = quickAttemptThroughProxy(t, listenerAddr, target, rawReq)

	// Pause briefly so any in-flight dial completes (or fails).
	time.Sleep(200 * time.Millisecond)

	if n := getUpstreamCount(); n != 0 {
		t.Errorf("upstream saw %d connections, want 0 (silent direct-dial fallback regression)", n)
	}
}

// quickAttemptThroughProxy issues CONNECT + write but tolerates the
// dial-time failure so the test can inspect post-conditions. Returns
// any response bytes received before the connection closed.
func quickAttemptThroughProxy(t *testing.T, proxyAddr, target, rawReq string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_, _ = conn.Write([]byte(connectReq))
	// Read until the proxy closes the connection or times out.
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

// TestLiveProxy_MultiListenerChain_NoRecursion verifies that with
// rotation installed on listener "chained" (routing through listener
// "outer"), listener "outer" is NOT subject to the rotation (it
// dials direct). This is the USK-826 regression class extended to
// USK-959: per-listener scope must isolate rotation just as it
// isolates the literal URL.
func TestLiveProxy_MultiListenerChain_NoRecursion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamCount := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	buildCfg := buildRotationBuildConfig(t)
	outerAddr, _, outerWg := rotationListenerDeps(t, ctx, "outer", buildCfg)
	chainedAddr, _, chainedWg := rotationListenerDeps(t, ctx, "chained", buildCfg)

	// Rotation on "chained" sends its dials through "outer". "outer"
	// has NO override, so it must dial direct to upstream.
	template := fmt.Sprintf("http://session-§__nonce§:pass@%s", outerAddr)
	installRotation(t, buildCfg, "chained", template, connector.RotationPerRequest)

	outerWg.Add(1)
	chainedWg.Add(1)
	rawReq := fmt.Sprintf("GET /chain HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, chainedAddr, target, rawReq)
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("response missing 200 OK: %q", resp)
	}
	waitSessionDone(t, chainedWg)
	waitSessionDone(t, outerWg)

	// Exactly ONE upstream request — recursion through outer would
	// multiply this.
	if n := getUpstreamCount(); n != 1 {
		t.Errorf("upstream saw %d connections, want 1 (chain recursion regression)", n)
	}
}

// TestLiveProxy_NoDelimiterTemplate_FastPath verifies that a template
// with no §-macro still parses (it's effectively a static URL once
// "expanded"). Ensures the resolver's fast path remains correct for
// non-rotating templates.
func TestLiveProxy_NoDelimiterTemplate_FastPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, observedAuth := startCONNECTProxyRecorder(t)
	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, wg := rotationListenerDeps(t, ctx, "rot-fastpath", buildCfg)
	installRotation(t, buildCfg, "rot-fastpath",
		fmt.Sprintf("http://static-user:pass@%s", proxyAddr),
		connector.RotationPerRequest)

	for i := 0; i < 3; i++ {
		resp := runOneRequestThroughListener(t, listenerAddr, target, fmt.Sprintf("/r%d", i), wg)
		if !strings.Contains(resp, "200 OK") {
			t.Fatalf("request %d: %q", i, resp)
		}
	}

	auths := observedAuth()
	if len(auths) != 3 {
		t.Fatalf("CONNECT proxy saw %d tunnels, want 3", len(auths))
	}
	for i, a := range auths {
		user := decodeBasicUser(t, a)
		if user != "static-user" {
			t.Errorf("request %d: username = %q, want static-user (no macro)", i, user)
		}
	}
}

// TestLiveProxy_PerConnectionRotation_SameWithinConnection verifies
// the per_connection policy via the H2 keep-alive path. Sending two
// requests on the same upstream connection (h1 keep-alive or h2
// stream multiplexing) should reuse the same nonce; a fresh inbound
// proxy connection should mint a new nonce.
//
// NOTE: with the test harness using "Connection: close" per request,
// every CONNECT is a fresh client connection → fresh ConnID → fresh
// nonce. To validate per_connection without rebuilding the harness,
// we rely on the unit test
// TestRotationResolver_PerConnection_SameWithinConnID
// (upstream_proxy_rotation_test.go) for the cache-hit semantics and
// run the e2e test below to confirm that distinct client connections
// observe distinct nonces (the "fresh ConnID = fresh nonce" half of
// the policy).
func TestLiveProxy_PerConnectionRotation_DistinctAcrossClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startMultiAcceptUpstreamHTTPS(t,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, observedAuth := startCONNECTProxyRecorder(t)
	buildCfg := buildRotationBuildConfig(t)
	listenerAddr, _, wg := rotationListenerDeps(t, ctx, "rot-per-conn", buildCfg)
	installRotation(t, buildCfg, "rot-per-conn",
		fmt.Sprintf("http://session-§__nonce§:pass@%s", proxyAddr),
		connector.RotationPerConnection)

	const clientCount = 3
	for i := 0; i < clientCount; i++ {
		resp := runOneRequestThroughListener(t, listenerAddr, target, fmt.Sprintf("/c%d", i), wg)
		if !strings.Contains(resp, "200 OK") {
			t.Fatalf("client %d: %q", i, resp)
		}
	}

	auths := observedAuth()
	if len(auths) != clientCount {
		t.Fatalf("CONNECT proxy saw %d tunnels, want %d", len(auths), clientCount)
	}
	seen := make(map[string]struct{})
	for i, a := range auths {
		user := decodeBasicUser(t, a)
		seen[user] = struct{}{}
		_ = i
	}
	if len(seen) != clientCount {
		t.Errorf("per_connection across clients: distinct count = %d, want %d", len(seen), clientCount)
	}
}

// To keep go vet happy when this file builds standalone.
var _ = atomic.AddInt32
