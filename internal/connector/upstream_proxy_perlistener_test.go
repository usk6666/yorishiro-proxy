package connector

import (
	"context"
	"net/url"
	"sync"
	"testing"
)

// TestBuildConfig_UpstreamProxyForListener_Roundtrip verifies the
// SetUpstreamProxyForListener / UpstreamProxyForListener pair on
// BuildConfig (USK-826). Set installs an entry; UpstreamProxyForListener
// returns it; passing nil clears the entry.
func TestBuildConfig_UpstreamProxyForListener_Roundtrip(t *testing.T) {
	cfg := &BuildConfig{}

	if got := cfg.UpstreamProxyForListener("foo"); got != nil {
		t.Errorf("initial UpstreamProxyForListener(foo) = %v, want nil", got)
	}

	u1, _ := url.Parse("http://127.0.0.1:8080")
	cfg.SetUpstreamProxyForListener("foo", u1)
	if got := cfg.UpstreamProxyForListener("foo"); got == nil || got.String() != "http://127.0.0.1:8080" {
		t.Errorf("after Set(foo, %s), got = %v", u1, got)
	}

	// Distinct listener is independent.
	if got := cfg.UpstreamProxyForListener("bar"); got != nil {
		t.Errorf("UpstreamProxyForListener(bar) = %v, want nil (independent)", got)
	}

	u2, _ := url.Parse("socks5://10.0.0.1:1080")
	cfg.SetUpstreamProxyForListener("bar", u2)
	if got := cfg.UpstreamProxyForListener("bar"); got == nil || got.String() != "socks5://10.0.0.1:1080" {
		t.Errorf("after Set(bar, %s), got = %v", u2, got)
	}

	// Clear by passing nil.
	cfg.SetUpstreamProxyForListener("foo", nil)
	if got := cfg.UpstreamProxyForListener("foo"); got != nil {
		t.Errorf("after Set(foo, nil), got = %v, want nil", got)
	}

	// bar is unaffected by foo's clear.
	if got := cfg.UpstreamProxyForListener("bar"); got == nil {
		t.Errorf("Set(foo, nil) cleared bar; got nil, want %s", u2)
	}
}

// TestBuildConfig_UpstreamProxyForListener_EmptyName ensures the empty
// listener name normalises to "default" (USK-826) so callers that have
// not yet adopted explicit naming hit the same slot as the implicit
// default listener.
func TestBuildConfig_UpstreamProxyForListener_EmptyName(t *testing.T) {
	cfg := &BuildConfig{}
	u, _ := url.Parse("http://proxy.example.com:8888")
	cfg.SetUpstreamProxyForListener("", u)

	if got := cfg.UpstreamProxyForListener(""); got == nil || got.String() != u.String() {
		t.Errorf("empty-name Get = %v, want %v", got, u)
	}
	if got := cfg.UpstreamProxyForListener("default"); got == nil || got.String() != u.String() {
		t.Errorf("default Get = %v, want %v (empty-name normalises to 'default')", got, u)
	}
}

// TestBuildConfig_EffectiveUpstreamProxyForCtx verifies the resolution
// order (USK-826): per-listener override → global override → boot-time
// field. When the ctx carries no listener name, falls back to the
// existing EffectiveUpstreamProxy chain.
func TestBuildConfig_EffectiveUpstreamProxyForCtx(t *testing.T) {
	boot, _ := url.Parse("http://boot.example.com:8080")
	global, _ := url.Parse("http://global.example.com:9090")
	perListener, _ := url.Parse("http://perlistener.example.com:7070")

	t.Run("ctx_without_name_falls_back_to_global", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		if got := cfg.EffectiveUpstreamProxyForCtx(context.Background()); got.String() != global.String() {
			t.Errorf("got %v, want %v", got, global)
		}
	})

	t.Run("ctx_with_name_no_perlistener_falls_back_to_global", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		ctx := ContextWithListenerName(context.Background(), "foo")
		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != global.String() {
			t.Errorf("got %v, want %v", got, global)
		}
	})

	t.Run("perlistener_takes_precedence_over_global", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxy(global)
		cfg.SetUpstreamProxyForListener("foo", perListener)
		ctx := ContextWithListenerName(context.Background(), "foo")
		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != perListener.String() {
			t.Errorf("got %v, want %v", got, perListener)
		}
	})

	t.Run("perlistener_only_applies_to_that_listener", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxyForListener("foo", perListener)
		ctx := ContextWithListenerName(context.Background(), "bar")
		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != boot.String() {
			t.Errorf("got %v, want %v (bar has no override → boot)", got, boot)
		}
	})

	t.Run("nil_perlistener_entry_falls_back", func(t *testing.T) {
		cfg := &BuildConfig{UpstreamProxy: boot}
		cfg.SetUpstreamProxyForListener("foo", perListener)
		cfg.SetUpstreamProxyForListener("foo", nil) // clear
		ctx := ContextWithListenerName(context.Background(), "foo")
		if got := cfg.EffectiveUpstreamProxyForCtx(ctx); got.String() != boot.String() {
			t.Errorf("got %v, want %v (cleared → boot)", got, boot)
		}
	})

	t.Run("nil_receiver_safe", func(t *testing.T) {
		var cfg *BuildConfig
		if got := cfg.EffectiveUpstreamProxyForCtx(context.Background()); got != nil {
			t.Errorf("nil receiver got %v, want nil", got)
		}
	})
}

// TestBuildConfig_SetUpstreamProxyForListener_NilReceiver tolerates a nil
// BuildConfig (USK-826 design parity with SetUpstreamProxy's nil
// tolerance).
func TestBuildConfig_SetUpstreamProxyForListener_NilReceiver(t *testing.T) {
	var cfg *BuildConfig
	u, _ := url.Parse("http://127.0.0.1:8080")
	cfg.SetUpstreamProxyForListener("foo", u) // must not panic
	if got := cfg.UpstreamProxyForListener("foo"); got != nil {
		t.Errorf("nil-receiver Get = %v, want nil", got)
	}
}

// TestBuildConfig_UpstreamProxyForListener_ConcurrentReadWrite verifies
// that the RWMutex protects concurrent dial-path reads against MCP-tool
// writes (USK-826). Race detector enforces correctness.
func TestBuildConfig_UpstreamProxyForListener_ConcurrentReadWrite(t *testing.T) {
	cfg := &BuildConfig{}
	u, _ := url.Parse("http://127.0.0.1:8080")
	cfg.SetUpstreamProxyForListener("foo", u)
	ctx := ContextWithListenerName(context.Background(), "foo")

	const writers = 4
	const readers = 8
	const iters = 200

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if j%2 == 0 {
					cfg.SetUpstreamProxyForListener("foo", u)
				} else {
					cfg.SetUpstreamProxyForListener("foo", nil)
				}
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = cfg.EffectiveUpstreamProxyForCtx(ctx)
			}
		}()
	}
	wg.Wait()
}

// TestPoolKeyForH2_PerListener_Distinct verifies the USK-826 critical
// invariant: two contexts carrying different listener names with
// different per-listener upstream proxies produce distinct H2 pool
// keys. Without this, pooled H2 layers minted for listener A would be
// reused for listener B and recurse through listener A.
func TestPoolKeyForH2_PerListener_Distinct(t *testing.T) {
	cfg := &BuildConfig{}
	a, _ := url.Parse("http://127.0.0.1:8080")
	b, _ := url.Parse("http://127.0.0.1:9090")
	cfg.SetUpstreamProxyForListener("a", a)
	cfg.SetUpstreamProxyForListener("b", b)

	ctxA := ContextWithListenerName(context.Background(), "a")
	ctxB := ContextWithListenerName(context.Background(), "b")

	target := "example.com:443"
	keyA := poolKeyForH2(ctxA, target, cfg, nil)
	keyB := poolKeyForH2(ctxB, target, cfg, nil)

	if keyA == keyB {
		t.Errorf("per-listener upstream_proxy did not distinguish pool key: %+v == %+v", keyA, keyB)
	}
}

// TestPoolKeyForH2_PerListener_SameOverride keys identically for two
// contexts that resolve to the same effective upstream URL (sanity that
// the discriminant is the URL, not the listener name).
func TestPoolKeyForH2_PerListener_SameOverride(t *testing.T) {
	cfg := &BuildConfig{}
	u, _ := url.Parse("http://127.0.0.1:8080")
	cfg.SetUpstreamProxyForListener("a", u)
	cfg.SetUpstreamProxyForListener("b", u)

	ctxA := ContextWithListenerName(context.Background(), "a")
	ctxB := ContextWithListenerName(context.Background(), "b")

	target := "example.com:443"
	keyA := poolKeyForH2(ctxA, target, cfg, nil)
	keyB := poolKeyForH2(ctxB, target, cfg, nil)

	if keyA != keyB {
		t.Errorf("same effective upstream_proxy minted distinct keys: %+v != %+v", keyA, keyB)
	}
}

// TestPoolKeyForH2_PerListener_FallbackToGlobal verifies that when a
// listener has no per-listener entry, the pool key incorporates the
// global override URL (legacy USK-734 semantics preserved on top of
// USK-826).
func TestPoolKeyForH2_PerListener_FallbackToGlobal(t *testing.T) {
	cfg := &BuildConfig{}
	global, _ := url.Parse("http://global.example.com:9090")
	cfg.SetUpstreamProxy(global)

	ctxFoo := ContextWithListenerName(context.Background(), "foo")
	ctxNoName := context.Background()

	target := "example.com:443"
	keyFoo := poolKeyForH2(ctxFoo, target, cfg, nil)
	keyNoName := poolKeyForH2(ctxNoName, target, cfg, nil)

	if keyFoo != keyNoName {
		t.Errorf("global override should yield identical keys regardless of ctx name: %+v != %+v",
			keyFoo, keyNoName)
	}

	// Per-listener override on a different name does not affect "foo".
	other, _ := url.Parse("http://other.example.com:7070")
	cfg.SetUpstreamProxyForListener("bar", other)
	keyFoo2 := poolKeyForH2(ctxFoo, target, cfg, nil)
	if keyFoo != keyFoo2 {
		t.Errorf("per-listener override on bar perturbed foo's key: %+v != %+v",
			keyFoo, keyFoo2)
	}
}
