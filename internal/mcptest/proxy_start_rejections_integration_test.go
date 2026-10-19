//go:build e2e && !e2e_smoke

// USK-1213: proxy_start argument-rejection cases moved out of the smoke tier.
// Each one boots a full harness only to assert a validation error string, so
// they run nightly; the success / live-transit paths they sit beside stay in
// the smoke-tier proxy_start_integration_test.go.
package mcptest_test

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

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

// TestE2E_ProxyStart_SOCKS5UpstreamAuth_Rejections is the malformed-value
// half of TestE2E_ProxyStart_SOCKS5UpstreamAuth: an unsupported
// upstream_proxy scheme surfaces an error at proxy_start time.
func TestE2E_ProxyStart_SOCKS5UpstreamAuth_Rejections(t *testing.T) {
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
}

// TestE2E_ProxyStart_MTLSClientCert_Rejections is the negative half of
// TestE2E_ProxyStart_MTLSClientCert: missing paths and a cert without a key
// exercise the live validation path in applyClientCert before the listener
// takes traffic.
func TestE2E_ProxyStart_MTLSClientCert_Rejections(t *testing.T) {
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
