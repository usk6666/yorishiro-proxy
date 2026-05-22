package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

func TestUpstreamProxyConfig_NilReturnsCtxUnchanged(t *testing.T) {
	var cfg *UpstreamProxyConfig
	ctx := context.Background()
	got, err := cfg.ResolveForIteration(ctx, 0)
	if err != nil {
		t.Fatalf("nil config should not error: %v", err)
	}
	if got != ctx {
		t.Fatalf("nil config should return ctx unchanged")
	}
	if _, present := connector.UpstreamProxyOverrideFromContext(got); present {
		t.Fatalf("nil config must not attach an override to ctx")
	}
}

func TestUpstreamProxyConfig_EmptyTemplateReturnsCtxUnchanged(t *testing.T) {
	cfg := &UpstreamProxyConfig{}
	ctx := context.Background()
	got, err := cfg.ResolveForIteration(ctx, 0)
	if err != nil {
		t.Fatalf("empty template should not error: %v", err)
	}
	if got != ctx {
		t.Fatalf("empty template should return ctx unchanged")
	}
}

func TestUpstreamProxyConfig_ExpandsTemplateAndAttachesOverride(t *testing.T) {
	cfg := &UpstreamProxyConfig{
		URLTemplate: "http://user-§__iteration§:pass@proxy.example:8080",
	}
	ctx, err := cfg.ResolveForIteration(context.Background(), 7)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	u, present := connector.UpstreamProxyOverrideFromContext(ctx)
	if !present || u == nil {
		t.Fatalf("expected override attached, got present=%v u=%v", present, u)
	}
	if u.Scheme != "http" {
		t.Errorf("scheme = %q, want http", u.Scheme)
	}
	if u.Host != "proxy.example:8080" {
		t.Errorf("host = %q, want proxy.example:8080", u.Host)
	}
	if u.User.Username() != "user-7" {
		t.Errorf("username = %q, want user-7 (iteration substitution)", u.User.Username())
	}
}

func TestUpstreamProxyConfig_NonceIsFreshPerIteration(t *testing.T) {
	cfg := &UpstreamProxyConfig{
		URLTemplate: "http://session-§__nonce§:pass@proxy.example:8080",
	}
	ctxA, err := cfg.ResolveForIteration(context.Background(), 0)
	if err != nil {
		t.Fatalf("iteration 0: %v", err)
	}
	ctxB, err := cfg.ResolveForIteration(context.Background(), 0)
	if err != nil {
		t.Fatalf("iteration 0 (second call): %v", err)
	}
	uA, _ := connector.UpstreamProxyOverrideFromContext(ctxA)
	uB, _ := connector.UpstreamProxyOverrideFromContext(ctxB)
	if uA.User.Username() == uB.User.Username() {
		t.Fatalf("expected distinct nonces, both got %q", uA.User.Username())
	}
}

func TestUpstreamProxyConfig_InvalidSchemeRejected(t *testing.T) {
	cfg := &UpstreamProxyConfig{
		URLTemplate: "ftp://proxy.example:8080",
	}
	_, err := cfg.ResolveForIteration(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
	if !strings.Contains(err.Error(), "upstream_proxy.url_template") {
		t.Errorf("error missing user-facing prefix: %v", err)
	}
}

func TestUpstreamProxyConfig_MissingPortRejected(t *testing.T) {
	cfg := &UpstreamProxyConfig{
		URLTemplate: "http://proxy.example",
	}
	_, err := cfg.ResolveForIteration(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected error for missing port")
	}
}

func TestUpstreamProxyConfig_CRLFGuard(t *testing.T) {
	// CWE-93: a §__nonce§-like substitution containing CR/LF must be
	// rejected before reaching the CONNECT request builder so the bytes
	// cannot smuggle a Proxy-Authorization injection. We simulate by
	// placing a literal CR/LF in the template directly — the guard
	// fires at the post-expansion checkpoint.
	cfg := &UpstreamProxyConfig{
		URLTemplate: "http://user\r\nInjected: yes@proxy.example:8080",
	}
	_, err := cfg.ResolveForIteration(context.Background(), 0)
	if err == nil {
		t.Fatalf("expected CRLF guard to reject the URL")
	}
	if !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("error did not mention CR/LF: %v", err)
	}
}

func TestUpstreamProxyConfig_SOCKS5SchemeAllowed(t *testing.T) {
	cfg := &UpstreamProxyConfig{
		URLTemplate: "socks5://user-§__iteration§:pass@proxy.example:1080",
	}
	ctx, err := cfg.ResolveForIteration(context.Background(), 3)
	if err != nil {
		t.Fatalf("socks5: %v", err)
	}
	u, _ := connector.UpstreamProxyOverrideFromContext(ctx)
	if u == nil || u.Scheme != "socks5" {
		t.Fatalf("expected socks5 scheme, got %v", u)
	}
	if u.User.Username() != "user-3" {
		t.Errorf("username = %q, want user-3", u.User.Username())
	}
}
