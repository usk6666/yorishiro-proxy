//go:build e2e && !e2e_smoke

// USK-1275 characterization: the WS SafetyEngine evaluates only the frame
// payload (TargetBody aliased onto it) — url / query are deliberately NOT
// re-evaluated per frame, because the WebSocket Upgrade request is a
// Send-direction HTTP request that passes pipeline.SafetyStep's HTTP arm
// before the WS layer swap. This test pins that the handshake path already
// enforces the preset's url / query targets, which is why the WS engine
// does not need the Upgrade URL threaded into CheckInput.
package mcptest_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_SafetyFilter_DestructiveSQLPreset_WSUpgradeQueryBlocked(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterWSPresetOnlyConfig,
		UpstreamProto: "ws",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	upstreamHostPort := wsUpstreamHostPort(t, h.UpstreamTLS.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := openCONNECTTunnel(ctx, proxyAddr, upstreamHostPort)
	if err != nil {
		t.Fatalf("open CONNECT tunnel: %v", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         hostOnly(upstreamHostPort),
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	err = performClientWSHandshakePath(tlsConn, upstreamHostPort, "/ws?q=DROP/**/TABLE/**/x")
	if err == nil {
		t.Fatal("WS Upgrade with destructive query succeeded; want 403 from the HTTP SafetyFilter arm")
	}
	if !strings.Contains(err.Error(), "HTTP/1.1 403") {
		t.Errorf("WS Upgrade error = %v, want a 403 handshake response", err)
	}
	if got := h.WSObservedHits.Total(); got != 0 {
		t.Errorf("upstream WS frame hits = %d, want 0", got)
	}
}
