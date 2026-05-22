package connector

import (
	"context"
	"net/url"
	"testing"
)

func TestUpstreamProxyOverride_AbsentByDefault(t *testing.T) {
	ctx := context.Background()
	u, present := UpstreamProxyOverrideFromContext(ctx)
	if present {
		t.Fatalf("expected no override on plain ctx, got url=%v", u)
	}
	if u != nil {
		t.Fatalf("expected nil url when present=false, got %v", u)
	}
}

func TestUpstreamProxyOverride_RoundTrip(t *testing.T) {
	target, err := url.Parse("http://user:pass@proxy.example:8080")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	ctx := ContextWithUpstreamProxyOverride(context.Background(), target)
	got, present := UpstreamProxyOverrideFromContext(ctx)
	if !present {
		t.Fatalf("expected present=true after override attached")
	}
	if got == nil || got.String() != target.String() {
		t.Fatalf("expected %q, got %v", target.String(), got)
	}
}

func TestUpstreamProxyOverride_ExplicitNilIsDirectDial(t *testing.T) {
	// A present-but-nil override signals "direct dial; skip upstream proxy"
	// — distinct from "no override at all" (present=false).
	ctx := ContextWithUpstreamProxyOverride(context.Background(), nil)
	got, present := UpstreamProxyOverrideFromContext(ctx)
	if !present {
		t.Fatalf("expected present=true even for nil URL")
	}
	if got != nil {
		t.Fatalf("expected nil url override, got %v", got)
	}
}

// TestBuildConfig_EffectiveUpstreamProxyForCtx_PerFlowOverride verifies the
// resolution priority: ctx override (USK residential-proxy rotation) wins
// over per-listener (USK-826) over global (USK-734) over boot-time.
func TestBuildConfig_EffectiveUpstreamProxyForCtx_PerFlowOverride(t *testing.T) {
	boot, _ := url.Parse("http://boot.example:1000")
	global, _ := url.Parse("http://global.example:2000")
	perListener, _ := url.Parse("http://listener.example:3000")
	perFlow, _ := url.Parse("http://flow.example:4000")

	t.Run("per-flow wins over listener+global+boot", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		cfg.SetUpstreamProxyForListener("L", perListener)

		ctx := ContextWithListenerName(context.Background(), "L")
		ctx = ContextWithUpstreamProxyOverride(ctx, perFlow)

		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != perFlow.String() {
			t.Fatalf("expected per-flow=%s, got %v", perFlow, got)
		}
	})

	t.Run("explicit nil per-flow override forces direct dial", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		cfg.SetUpstreamProxyForListener("L", perListener)

		ctx := ContextWithListenerName(context.Background(), "L")
		ctx = ContextWithUpstreamProxyOverride(ctx, nil)

		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got != nil {
			t.Fatalf("expected nil (direct dial) override, got %v", got)
		}
	})

	t.Run("no per-flow override falls through to per-listener", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		cfg.SetUpstreamProxyForListener("L", perListener)

		ctx := ContextWithListenerName(context.Background(), "L")

		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != perListener.String() {
			t.Fatalf("expected per-listener=%s, got %v", perListener, got)
		}
	})
}
