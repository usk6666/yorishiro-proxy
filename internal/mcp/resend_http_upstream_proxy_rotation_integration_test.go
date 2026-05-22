//go:build e2e && !e2e_smoke

package mcp

// resend_http_upstream_proxy_rotation_integration_test.go — verifies
// that resend_http's upstream_proxy.url_template expansion drives the
// dial through the configured upstream HTTP CONNECT proxy. The
// Proxy-Authorization header observed by the proxy must match the
// userinfo of the expanded URL; the inner target must receive the
// resent payload.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestResendHTTP_UpstreamProxyTunneledViaCONNECT(t *testing.T) {
	cs, _, _, _ := setupResendHTTPSession(t)
	echo, getCaptured := startResendHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")
	proxyAddr, observedAuth := startCONNECTProxy(t)

	template := fmt.Sprintf("http://res-§__nonce§:pw@%s", proxyAddr)
	_ = callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/hello",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"upstream_proxy": map[string]any{
			"url_template": template,
		},
		"timeout_ms": 5000,
	})

	method, _, _ := getCaptured()
	if method != "GET" {
		t.Errorf("target observed method = %q, want GET", method)
	}

	auths := observedAuth()
	if len(auths) != 1 {
		t.Fatalf("CONNECT proxy saw %d tunnels, want 1", len(auths))
	}
	if !strings.HasPrefix(auths[0], "Basic ") {
		t.Fatalf("Proxy-Authorization = %q, want Basic prefix", auths[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auths[0], "Basic "))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	userPass := string(decoded)
	colon := strings.IndexByte(userPass, ':')
	if colon < 0 {
		t.Fatalf("userinfo missing ':' (got %q)", userPass)
	}
	if user := userPass[:colon]; !strings.HasPrefix(user, "res-") {
		t.Errorf("username = %q, want res-<nonce> prefix", user)
	}
}

func TestResendHTTP_UpstreamProxyMalformedTemplateRejected(t *testing.T) {
	cs, _, _, _ := setupResendHTTPSession(t)
	echo, _ := startResendHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/hello",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"upstream_proxy": map[string]any{
				"url_template": "ftp://nope.example:21",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool to surface the malformed-template error")
	}
}
