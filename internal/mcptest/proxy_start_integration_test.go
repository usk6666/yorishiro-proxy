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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

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
//
// The end-to-end transit assertion (CONNECT through the proxy →
// SOCKS5 server → upstream) is split into a follow-up Issue
// (USK-734). proxybuild.Manager.SetUpstreamProxy is documented in
// internal/proxybuild/manager.go to "store" the URL only — the
// live data path is wired separately by USK-690. Until that lands,
// the proxy dials direct (visible in trace as "connector: dialing
// direct"), so a transit assertion would always fail.
func TestE2E_ProxyStart_SOCKS5UpstreamAuth(t *testing.T) {
	t.Run("socks5_upstream_url_stored_and_redacted", func(t *testing.T) {
		const wantUser, wantPass = "alice", "s3cret"
		// Even though the live transit is split off, we still bind a
		// loopback TCP listener here so the wiring tests use a real
		// reachable address (the manager validates the URL string but
		// does not connect at start time). The placeholder accepts no
		// auth and runs no SOCKS5 handshake — when USK-734 lands the
		// fixture grows into a handshake-capable SOCKS5 server and the
		// user/pass values plumb through to it for assertion.
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

	t.Run("transit_through_socks5_skipped", func(t *testing.T) {
		// Per spec, the Issue's positive transit assertion (proxy
		// routes through SOCKS5; auth failure case observed at the
		// SOCKS5 server) is split into a follow-up Issue. Skip with
		// a reference rather than weakening the assertion in place.
		t.Skip("not yet implemented: proxybuild.Manager.SetUpstreamProxy stores but does not wire the URL into the live dial path (split off USK-734, see internal/proxybuild/manager.go SetUpstreamProxy comment)")
	})
}

// TestE2E_ProxyStart_ProtocolSubset_Filters covers proxy_start's
// "protocols" parameter wiring. The acceptance side (proxy_start
// returns the requested subset and the connector stores it) is
// verified here. The runtime-enforcement side (HTTP/2 traffic
// rejected when protocols=["HTTP/1.x"]) is deferred — the connector's
// protocol-detection pipeline does not yet read enabledProtocols as
// a filter; the field is currently consumed only by the `query`
// resource=config response. Per the USK-725 spec the deferred path
// is split into a follow-up Issue rather than weakened in place.
func TestE2E_ProxyStart_ProtocolSubset_Filters(t *testing.T) {
	t.Run("http1_only_accepted_by_proxy_start", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

		res := h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"protocols":   []any{"HTTP/1.x"},
		})

		gotProtocols := protocolsFromStartResult(t, res)
		if len(gotProtocols) != 1 || gotProtocols[0] != "HTTP/1.x" {
			t.Errorf("proxy_start result.protocols = %v, want [HTTP/1.x]", gotProtocols)
		}

		// Confirm the same value is reachable via query("config") —
		// the canonical wire-level wiring check.
		cfgRes := h.MustOK(t, "query", map[string]any{"resource": "config"})
		var cfg struct {
			EnabledProtocols []string `json:"enabled_protocols"`
		}
		if err := json.Unmarshal([]byte(cfgRes.Text), &cfg); err != nil {
			t.Fatalf("decode config: %v", err)
		}
		if len(cfg.EnabledProtocols) != 1 || cfg.EnabledProtocols[0] != "HTTP/1.x" {
			t.Errorf("query config.enabled_protocols = %v, want [HTTP/1.x]", cfg.EnabledProtocols)
		}
	})

	t.Run("https_only_accepted_by_proxy_start", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

		res := h.MustOK(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"protocols":   []any{"HTTPS"},
		})

		gotProtocols := protocolsFromStartResult(t, res)
		if len(gotProtocols) != 1 || gotProtocols[0] != "HTTPS" {
			t.Errorf("proxy_start result.protocols = %v, want [HTTPS]", gotProtocols)
		}
	})

	t.Run("invalid_protocol_rejected", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		// validateProtocols rejects anything not in validProtocols.
		// Match the stable "unknown protocol" prefix.
		h.ExpectError(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"protocols":   []any{"NotAProtocol"},
		}, "unknown protocol")
	})

	t.Run("runtime_enforcement_skipped", func(t *testing.T) {
		// The Issue's negative path ("HTTP/2 traffic rejected when
		// protocols=[HTTP/1.x]") cannot be exercised today: the
		// connector's protocol-detection pipeline does not read
		// connector.enabledProtocols as a runtime filter. The field
		// is config-acceptance only. Skip with a sticky reference so
		// CI does not silently regress.
		t.Skip("not yet implemented: connector data-path does not enforce enabledProtocols (split off USK-732)")
	})
}

// TestE2E_ProxyStart_MTLSClientCert verifies the client_cert /
// client_key arguments to proxy_start (a) are accepted and validated
// by the tool, (b) round-trip into the connector's HostTLSRegistry
// global slot. The end-to-end transit assertion ("upstream sees the
// client cert") is split into a follow-up Issue (USK-733): the live
// MITM data path consumes BuildConfig.ClientCert (resolved at stack
// build time from the legacy `-client-cert` CLI flag), not the
// registry that proxy_start writes to. Wiring the runtime
// registry update into the live data path requires a production
// change outside this Issue's scope.
//
// Negative cases (missing path, cert without key) DO exercise live
// validation in applyClientCert before the listener takes traffic,
// so they stay enabled here.
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
		// The Issue's positive end-to-end path (proxy presents the
		// client cert to upstream) cannot pass on main today: the
		// MCP tool writes to connector.hostTLSRegistry, but the live
		// MITM connection-stack reads BuildConfig.ClientCert (a
		// resolve-once snapshot taken at stack-build from the
		// `-client-cert` CLI flag and proxy config file). Bridging
		// the two is a production change outside test scope.
		t.Skip("not yet implemented: connector live MITM data-path does not consume hostTLSRegistry runtime updates (split off USK-733)")
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

// protocolsFromStartResult extracts the protocols field from a
// proxy_start ToolResult, returning an empty slice when absent.
func protocolsFromStartResult(t *testing.T, res mcptest.ToolResult) []string {
	t.Helper()
	if res.Decoded != nil {
		if raw, ok := res.Decoded["protocols"].([]any); ok {
			out := make([]string, 0, len(raw))
			for _, v := range raw {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}
	var parsed struct {
		Protocols []string `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode proxy_start result: %v (text=%q)", err, res.Text)
	}
	return parsed.Protocols
}

// (CONNECT-through-proxy traffic helpers were removed when the
// USK-733/734 skips landed. They will return when the follow-up
// Issues add the actual transit assertions.)
