//go:build e2e

// Package mcptest_test holds USK-725's wiring scenarios for proxy_start.
//
// These tests boot the production MCP server assembly via mcptest.StartHarness
// and exercise four `proxy_start` paths (listen-addr validation, SOCKS5
// upstream auth, protocol-subset acceptance, mTLS client cert) over the
// same JSON-RPC-over-HTTP transport the WebUI / CLI client use. The intent
// (M46) is to catch transport-level / CLI-flag / boot-order divergences
// between the test harness and the production wiring — the same class
// of bug behind USK-717/718/719.
package mcptest_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyStart_ListenAddrValidation exercises the loopback / port
// checks performed by proxy_start before it hands off to
// proxybuild.Manager. The three sub-cases are:
//
//   - Valid loopback bind succeeds (sanity).
//   - Non-loopback bind is rejected with the documented error message.
//   - Re-using the same listener port races into a bind error and the
//     second proxy_start call surfaces it cleanly.
func TestE2E_ProxyStart_ListenAddrValidation(t *testing.T) {
	t.Run("loopback_succeeds", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
		if !strings.Contains(res.Text, "running") {
			t.Errorf("expected status running in result, got: %s", res.Text)
		}
	})

	t.Run("non_loopback_rejected", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// validateLoopbackAddr emits "only loopback addresses are
		// allowed" for non-loopback IPs — match a stable substring.
		h.ExpectError(t, "proxy_start",
			map[string]any{"listen_addr": "192.168.0.1:8080"},
			"loopback")
	})

	t.Run("port_conflict_surfaces_error", func(t *testing.T) {
		// Acquire a port we know is free, hold it (so the proxy's bind
		// will fail), and feed that fixed addr to proxy_start. Using
		// the listener-then-proxy_start ordering avoids the race where
		// :0 + a second :0 picks distinct ephemeral ports.
		blocker, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("acquire blocker port: %v", err)
		}
		defer blocker.Close()
		conflictAddr := blocker.Addr().String()

		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// The bind error is wrapped twice ("proxy start" -> "start
		// proxy") plus the OS error ("address already in use" on
		// Linux). Match a stable substring that appears across all
		// platforms.
		h.ExpectError(t, "proxy_start",
			map[string]any{"listen_addr": conflictAddr},
			"address already in use")
	})
}

// TestE2E_ProxyStart_SOCKS5UpstreamAuth verifies the JSON-RPC wiring
// contract for upstream_proxy=socks5://user:pass@host:port:
//
//   - proxy_start accepts the URL form and records it in the manager
//     (visible via query("config").upstream_proxy with redacted creds).
//   - Malformed values (unsupported scheme, parse failure) surface
//     errors at proxy_start time.
//   - Live transit (USK-734): once proxy_start succeeds, an HTTP
//     request through the proxy listener actually transits the
//     configured SOCKS5 server. RFC 1929 user/pass auth is exercised
//     when credentials are supplied in the URL.
func TestE2E_ProxyStart_SOCKS5UpstreamAuth(t *testing.T) {
	t.Run("socks5_upstream_url_stored_and_redacted", func(t *testing.T) {
		const wantUser, wantPass = "alice", "s3cret"
		// Acceptance-only sub-case: just a placeholder listener so the
		// URL is reachable. No traffic actually flows through it.
		socks5 := startPlaceholderSOCKS5Listener(t)

		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": fmt.Sprintf("socks5://%s:%s@%s", wantUser, wantPass, socks5.Addr()),
		})

		cfgRes := h.MustOK(t, "query", map[string]any{"resource": "config"})
		var cfg struct {
			UpstreamProxy string `json:"upstream_proxy"`
		}
		if err := json.Unmarshal([]byte(cfgRes.Text), &cfg); err != nil {
			t.Fatalf("decode config: %v", err)
		}
		if !strings.HasPrefix(cfg.UpstreamProxy, "socks5://") {
			t.Errorf("config.upstream_proxy = %q, want socks5:// prefix", cfg.UpstreamProxy)
		}
		if !strings.Contains(cfg.UpstreamProxy, socks5.Addr()) {
			t.Errorf("config.upstream_proxy = %q, want it to contain %q", cfg.UpstreamProxy, socks5.Addr())
		}
		// Credentials must be redacted so a config dump does not leak
		// secrets — the connector's RedactProxyURL is the canonical
		// helper. Assert the password is gone.
		if strings.Contains(cfg.UpstreamProxy, wantPass) {
			t.Errorf("config.upstream_proxy leaks password: %q", cfg.UpstreamProxy)
		}
	})

	t.Run("invalid_upstream_proxy_rejected", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// connector.ParseUpstreamProxy rejects unsupported schemes
		// with "unsupported upstream proxy scheme". Match the
		// "upstream_proxy" wrapper plus the scheme literal so the
		// assertion is unambiguous.
		h.ExpectError(t, "proxy_start", map[string]any{
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": "socks4://127.0.0.1:1080",
		}, "upstream_proxy")
	})

	// USK-734: live-transit sub-case. After proxy_start sets
	// upstream_proxy=socks5://user:pass@..., a CONNECT issued through
	// the proxy listener must transit the configured SOCKS5 server.
	t.Run("transit_through_socks5", func(t *testing.T) {
		const wantUser, wantPass = "alice", "s3cret"

		socks5 := startSOCKS5Server(t, wantUser, wantPass)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			UpstreamProto: "http/1.1",
		})

		startRes := h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": fmt.Sprintf("socks5://%s:%s@%s", wantUser, wantPass, socks5.Addr()),
		})
		proxyAddr, ok := startRes.Decoded["listen_addr"].(string)
		if !ok || proxyAddr == "" {
			t.Fatalf("proxy_start: missing listen_addr in result: %+v", startRes.Decoded)
		}

		// Drive an HTTPS request through the proxy. The proxy's
		// upstream-CONNECT path will dial the upstream test server's
		// loopback ip:port via the SOCKS5 server.
		client := proxyTLSClient(t, proxyAddr)
		resp, err := client.Get(h.UpstreamTLS.URL + "/")
		if err != nil {
			t.Fatalf("GET via proxy: %v", err)
		}
		_ = resp.Body.Close()

		if got := socks5.Connections(); got < 1 {
			t.Errorf("SOCKS5 saw %d successful CONNECT bridges, want >= 1", got)
		}
		// The SOCKS5 server's lastTarget should match the upstream
		// test server's address — sanity-check the proxy did not bypass
		// the SOCKS5 layer for any reason.
		upstreamHost := stripURLScheme(t, h.UpstreamTLS.URL)
		if got := socks5.LastTarget(); got != upstreamHost {
			t.Errorf("SOCKS5 last target = %q, want %q", got, upstreamHost)
		}
		if got := socks5.AuthFailures(); got != 0 {
			t.Errorf("SOCKS5 saw %d auth failures, want 0", got)
		}
	})

	// USK-734: bad-creds sub-case. If the SOCKS5 server rejects the
	// password, the proxy's upstream dial must fail with a clear error
	// and the SOCKS5 server's failure counter must increment.
	t.Run("transit_with_bad_creds_fails", func(t *testing.T) {
		const wantUser, wantPass = "alice", "s3cret"

		socks5 := startSOCKS5Server(t, wantUser, wantPass)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			UpstreamProto: "http/1.1",
		})

		// Wrong password — SOCKS5 server should reject with 0xFF.
		startRes := h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": fmt.Sprintf("socks5://%s:%s@%s", wantUser, "wrong", socks5.Addr()),
		})
		proxyAddr, ok := startRes.Decoded["listen_addr"].(string)
		if !ok || proxyAddr == "" {
			t.Fatalf("proxy_start: missing listen_addr in result: %+v", startRes.Decoded)
		}

		client := proxyTLSClient(t, proxyAddr)
		resp, err := client.Get(h.UpstreamTLS.URL + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET via proxy with bad SOCKS5 creds unexpectedly succeeded")
		}
		// The SOCKS5 server should record the auth failure even when
		// the proxy bubbles up the error to the HTTP client. Allow a
		// brief settle so the dial-side goroutine increments the
		// counter before the assertion.
		deadline := time.Now().Add(5 * time.Second)
		for socks5.AuthFailures() == 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if got := socks5.AuthFailures(); got < 1 {
			t.Errorf("SOCKS5 auth failures = %d, want >= 1", got)
		}
		if got := socks5.Connections(); got != 0 {
			t.Errorf("SOCKS5 successful connections = %d, want 0 with bad creds", got)
		}
	})
}

// proxyTLSClient builds an http.Client that issues HTTPS requests
// through the proxy at proxyAddr. The proxy MITMs the TLS connection
// (re-issuing a leaf from its ephemeral CA) so the client must skip
// verification; the transit assertion does not depend on cert
// validation, only on bytes flowing via SOCKS5.
func proxyTLSClient(t *testing.T, proxyAddr string) *gohttp.Client {
	t.Helper()
	pURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:             gohttp.ProxyURL(pURL),
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // proxy MITM: ephemeral CA, test only
			},
		},
		Timeout: 15 * time.Second,
	}
}

// stripURLScheme returns the host:port portion of a "https://host:port"
// URL string. Used to compare against socks5Server.LastTarget which
// stores the bridged dial address in host:port form.
func stripURLScheme(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse upstream URL %q: %v", raw, err)
	}
	host := u.Host
	// httptest.Server.URL always includes an explicit port for TLS
	// servers, so a missing port here would be a regression.
	if _, _, err := net.SplitHostPort(host); err != nil {
		t.Fatalf("upstream URL host %q missing port", host)
	}
	return host
}

// TestE2E_ProxyStart_RejectsUnknownProtocolsField is the USK-870
// regression guard for the removal of the `protocols` field
// (USK-865 Option A). After the deletion, any client that still sends
// `protocols` to proxy_start must be rejected with an unknown-field
// schema error rather than silently ignored — this prevents a stale
// caller from believing it has enforced a protocol allow-list when in
// fact every protocol is now always enabled.
//
// The MCP go-sdk generates `additionalProperties: false` for struct
// inputs (github.com/google/jsonschema-go infer.go: "Structs have
// schema type 'object', and disallow additionalProperties"), so the
// rejection comes from JSON-schema validation before the handler is
// ever invoked.
func TestE2E_ProxyStart_RejectsUnknownProtocolsField(t *testing.T) {
	cases := []struct {
		name      string
		protocols any
	}{
		{"single_protocol", []any{"HTTP/1.x"}},
		{"multiple_protocols", []any{"HTTP/1.x", "HTTPS"}},
		{"empty_slice", []any{}},
		{"null", nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
			// The schema validator emits a message that mentions the
			// offending property name. "protocols" is the stable
			// substring; the exact wording ("additional properties not
			// allowed", "unknown field", etc.) is SDK-version-specific
			// so we anchor on the field name only.
			h.ExpectError(t, "proxy_start", map[string]any{
				"listen_addr": "127.0.0.1:0",
				"protocols":   tc.protocols,
			}, "protocols")
		})
	}
}

// TestE2E_ProxyStart_MTLSClientCert verifies the client_cert /
// client_key arguments to proxy_start (a) are accepted and validated
// by the tool, (b) round-trip into the connector's HostTLSRegistry
// global slot, and (c) USK-733: the live MITM dial path consults the
// runtime-mutable HostTLSRegistry at handshake time, so the upstream
// observes the client cert installed by proxy_start.
//
// Negative cases (missing path, cert without key) exercise the live
// validation path in applyClientCert before the listener takes
// traffic.
func TestE2E_ProxyStart_MTLSClientCert(t *testing.T) {
	t.Run("client_cert_argument_accepted", func(t *testing.T) {
		// Acceptance + reachable-config wiring: proxy_start succeeds
		// with valid cert/key and query("config") reports the cert
		// path back. This proves the MCP→connector handoff works
		// even though the live data path doesn't yet consume the
		// registry update.
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			UpstreamProto: "http/1.1",
			EnableMTLS:    true,
		})
		if h.MTLS == nil {
			t.Fatal("EnableMTLS=true but Harness.MTLS is nil")
		}

		h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"client_cert": h.MTLS.ClientCertPath,
			"client_key":  h.MTLS.ClientKeyPath,
		})

		cfgRes := h.MustOK(t, "query", map[string]any{"resource": "config"})
		var cfg struct {
			ClientCert *struct {
				CertPath string `json:"cert_path"`
				KeyPath  string `json:"key_path"`
			} `json:"client_cert"`
		}
		if err := json.Unmarshal([]byte(cfgRes.Text), &cfg); err != nil {
			t.Fatalf("decode config: %v", err)
		}
		if cfg.ClientCert == nil {
			t.Fatalf("query config.client_cert is nil after proxy_start with client_cert/client_key set; full config: %s", cfgRes.Text)
		}
		if cfg.ClientCert.CertPath != h.MTLS.ClientCertPath {
			t.Errorf("config.client_cert.cert_path = %q, want %q", cfg.ClientCert.CertPath, h.MTLS.ClientCertPath)
		}
		if cfg.ClientCert.KeyPath != h.MTLS.ClientKeyPath {
			t.Errorf("config.client_cert.key_path = %q, want %q", cfg.ClientCert.KeyPath, h.MTLS.ClientKeyPath)
		}
	})

	t.Run("client_cert_presented_to_upstream", func(t *testing.T) {
		// USK-733: the live MITM dial path now consults the runtime
		// HostTLSRegistry at handshake time. proxy_start(client_cert=...)
		// writes the cert into the registry; the next outbound TLS
		// handshake to the upstream pulls the cert from there and
		// presents it. The upstream test handler echoes the verified
		// client CommonName when mTLS succeeds (see harness.buildUpstream),
		// so the assertion is "the response body contains client_cn=...".
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			UpstreamProto: "http/1.1",
			EnableMTLS:    true,
		})
		if h.MTLS == nil {
			t.Fatal("EnableMTLS=true but Harness.MTLS is nil")
		}

		startRes := h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"client_cert": h.MTLS.ClientCertPath,
			"client_key":  h.MTLS.ClientKeyPath,
		})

		proxyAddr := proxyListenAddrFromResult(t, startRes)
		upstreamHostPort := upstreamHostPortFromURL(t, h.UpstreamTLS.URL)

		// CONNECT through the proxy + GET / and assert the upstream
		// echoed the verified client CommonName. If the registry update
		// did not reach the dial path, the upstream's
		// RequireAndVerifyClientCert handshake fails before the request
		// is delivered (handshake error visible to the client).
		respBody := connectAndGetThroughProxy(t, proxyAddr, upstreamHostPort, "/")
		if !strings.Contains(respBody, "client_cn=") {
			t.Fatalf("upstream did not echo client CN; client cert was not presented (USK-733 wiring broken). body=%q", respBody)
		}
	})

	t.Run("missing_cert_path_surfaces_error", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// The path ends up flowing through tls.LoadX509KeyPair, which
		// returns an "open ...: no such file or directory" error.
		// Match the stable substring "client_cert" — that's the
		// wrapped section emitted by handleProxyStart.
		h.ExpectError(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"client_cert": "/nonexistent/path/to/client.crt",
			"client_key":  "/nonexistent/path/to/client.key",
		}, "client_cert")
	})

	t.Run("cert_without_key_rejected", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// applyClientCert requires both fields together. Validate the
		// "key is required" message.
		h.ExpectError(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"client_cert": "/anywhere",
		}, "client_key")
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// proxyListenAddrFromResult extracts the listen_addr field from a
// proxy_start ToolResult. The harness gives us a 127.0.0.1:0 placeholder
// in the request; the resolved port is what the test actually needs to
// dial.
func proxyListenAddrFromResult(t *testing.T, res mcptest.ToolResult) string {
	t.Helper()
	if res.Decoded != nil {
		if v, ok := res.Decoded["listen_addr"].(string); ok && v != "" {
			return v
		}
	}
	var parsed struct {
		ListenAddr string `json:"listen_addr"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode proxy_start result for listen_addr: %v (text=%q)", err, res.Text)
	}
	if parsed.ListenAddr == "" {
		t.Fatalf("proxy_start result missing listen_addr: %s", res.Text)
	}
	return parsed.ListenAddr
}

// upstreamHostPortFromURL parses an httptest server URL ("https://host:port")
// into a "host:port" string suitable for the proxy CONNECT target.
func upstreamHostPortFromURL(t *testing.T, rawURL string) string {
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

// connectAndGetThroughProxy connects to the proxy, issues a CONNECT to
// the given target, performs the (MITM) TLS handshake, sends a GET for
// path, and returns the response body. InsecureSkipVerify is set on the
// MITM TLS handshake because the proxy presents a freshly-issued cert
// from its ephemeral CA — the test does not pin against that CA.
func connectAndGetThroughProxy(t *testing.T, proxyAddr, target, path string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("unexpected CONNECT response: %q", got)
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target host: %v", err)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through proxy to %s: %v", target, err)
	}
	defer tlsConn.Close()

	getReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, target)
	if _, err := tlsConn.Write([]byte(getReq)); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	if err := tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set TLS read deadline: %v", err)
	}

	var respBuf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		m, rerr := tlsConn.Read(tmp)
		if m > 0 {
			respBuf.Write(tmp[:m])
		}
		if rerr != nil {
			break
		}
	}

	resp := respBuf.String()
	idx := strings.Index(resp, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("no header/body split in response: %q", resp)
	}
	body := resp[idx+4:]
	// Strip a leading chunked-size line if Transfer-Encoding: chunked.
	// httptest's HTTP/1.1 server commonly sends a single chunk; trim
	// the surrounding framing so callers can substring-match the
	// payload directly.
	headerLower := strings.ToLower(resp[:idx])
	if strings.Contains(headerLower, "transfer-encoding: chunked") {
		body = stripChunkedFraming(body)
	}
	return body
}

// stripChunkedFraming removes HTTP/1.1 chunked transfer-encoding
// framing from a response body. It is intentionally minimal — only
// expected to handle the small, single-chunk responses our test
// upstream sends.
func stripChunkedFraming(body string) string {
	var out bytes.Buffer
	rest := body
	for {
		nl := strings.Index(rest, "\r\n")
		if nl < 0 {
			break
		}
		sizeStr := rest[:nl]
		// Strip optional chunk extensions (";k=v").
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return body
		}
		if size == 0 {
			break
		}
		start := nl + 2
		end := start + int(size)
		if end > len(rest) {
			return body
		}
		out.WriteString(rest[start:end])
		// Skip trailing CRLF after the chunk payload.
		rest = rest[end:]
		if strings.HasPrefix(rest, "\r\n") {
			rest = rest[2:]
		}
	}
	return out.String()
}
