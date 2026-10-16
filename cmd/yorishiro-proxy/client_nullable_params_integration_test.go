//go:build e2e && !e2e_smoke

package main

// client_nullable_params_integration_test.go — USK-1140.
//
// Drives the real CLI entry (runClientTool) over Streamable HTTP against a
// production-wired MCP server (mcptest.StartHarness). Before the fix the
// CLI sent every optional (nullable) integer as a string, so
// `client proxy_start max_connections=N` was rejected by the server's
// input schema with `type: N has type "string", want one of "null, integer"`.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// harnessClientConnArgs returns the --server-addr / --token flags that point
// runClientTool at the harness's MCP endpoint.
func harnessClientConnArgs(t *testing.T, h *mcptest.Harness) []string {
	t.Helper()
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		t.Fatalf("parse harness BaseURL %q: %v", h.BaseURL, err)
	}
	return []string{"--server-addr=" + u.Host, "--token=" + h.Token, "--quiet"}
}

func TestE2E_ClientTool_NullableIntegerParam(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	defer h.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	conn := harnessClientConnArgs(t, h)

	// 777 is deliberately not any default value of max_connections.
	startArgs := append(append([]string{}, conn...), "listen_addr=127.0.0.1:0", "max_connections=777")
	if err := runClientTool(ctx, "proxy_start", startArgs); err != nil {
		t.Fatalf("client proxy_start max_connections=777: %v", err)
	}

	res := h.MustOK(t, "query", map[string]any{"resource": "status"})
	var status struct {
		Running        bool `json:"running"`
		MaxConnections int  `json:"max_connections"`
	}
	if err := json.Unmarshal([]byte(res.Text), &status); err != nil {
		t.Fatalf("decode query(status): %v (text=%q)", err, res.Text)
	}
	if !status.Running {
		t.Errorf("query(status).running = false after client proxy_start")
	}
	if status.MaxConnections != 777 {
		t.Errorf("query(status).max_connections = %d, want 777", status.MaxConnections)
	}

	// A non-numeric value is still passed through untouched and rejected
	// by the server's schema.
	badArgs := append(append([]string{}, conn...), "max_connections=lots")
	err := runClientTool(ctx, "configure", badArgs)
	if err == nil {
		t.Fatal("client configure max_connections=lots succeeded, want a schema error")
	}
	if !strings.Contains(err.Error(), `has type "string"`) {
		t.Errorf("client configure max_connections=lots error = %q, want it to contain %q", err, `has type "string"`)
	}
}
