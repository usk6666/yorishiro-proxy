package socks5

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestDispatchOnSOCKS5Connect(t *testing.T) {
	t.Run("nil engine is no-op", func(t *testing.T) {
		h := NewHandler(nil)
		// Should not panic with nil engine.
		h.dispatchOnSOCKS5Connect(context.Background(), "example.com:443", "none", "", nil)
	})

	t.Run("dispatches hook with correct data", func(t *testing.T) {
		engine := plugin.NewEngine(nil)

		// Register a handler that captures the hook data.
		var capturedData map[string]any
		engine.Registry().Register("test-plugin", plugin.HookOnSOCKS5Connect, func(_ context.Context, data map[string]any) (*plugin.HookResult, error) {
			capturedData = data
			return &plugin.HookResult{Action: plugin.ActionContinue}, nil
		}, plugin.OnErrorSkip)

		h := NewHandler(nil)
		h.SetPluginEngine(engine)

		ctx := proxy.ContextWithClientAddr(context.Background(), "192.168.1.100:12345")
		h.dispatchOnSOCKS5Connect(ctx, "example.com:443", "username_password", "testuser", nil)

		if capturedData == nil {
			t.Fatal("hook was not dispatched")
		}

		// Verify all expected fields.
		if v, ok := capturedData["event"].(string); !ok || v != "socks5_connect" {
			t.Errorf("event = %v, want %q", capturedData["event"], "socks5_connect")
		}
		if v, ok := capturedData["target_host"].(string); !ok || v != "example.com" {
			t.Errorf("target_host = %v, want %q", capturedData["target_host"], "example.com")
		}
		if v, ok := capturedData["target_port"].(int); !ok || v != 443 {
			t.Errorf("target_port = %v, want %d", capturedData["target_port"], 443)
		}
		if v, ok := capturedData["target"].(string); !ok || v != "example.com:443" {
			t.Errorf("target = %v, want %q", capturedData["target"], "example.com:443")
		}
		if v, ok := capturedData["auth_method"].(string); !ok || v != "username_password" {
			t.Errorf("auth_method = %v, want %q", capturedData["auth_method"], "username_password")
		}
		if v, ok := capturedData["auth_user"].(string); !ok || v != "testuser" {
			t.Errorf("auth_user = %v, want %q", capturedData["auth_user"], "testuser")
		}
		if v, ok := capturedData["client_addr"].(string); !ok || v != "192.168.1.100:12345" {
			t.Errorf("client_addr = %v, want %q", capturedData["client_addr"], "192.168.1.100:12345")
		}
	})

	t.Run("no auth dispatches with auth_method=none", func(t *testing.T) {
		engine := plugin.NewEngine(nil)

		var capturedData map[string]any
		engine.Registry().Register("test-plugin", plugin.HookOnSOCKS5Connect, func(_ context.Context, data map[string]any) (*plugin.HookResult, error) {
			capturedData = data
			return &plugin.HookResult{Action: plugin.ActionContinue}, nil
		}, plugin.OnErrorSkip)

		h := NewHandler(nil)
		h.SetPluginEngine(engine)

		h.dispatchOnSOCKS5Connect(context.Background(), "10.0.0.1:80", "none", "", nil)

		if capturedData == nil {
			t.Fatal("hook was not dispatched")
		}
		if v, ok := capturedData["auth_method"].(string); !ok || v != "none" {
			t.Errorf("auth_method = %v, want %q", capturedData["auth_method"], "none")
		}
		if v, ok := capturedData["auth_user"].(string); !ok || v != "" {
			t.Errorf("auth_user = %v, want empty string", capturedData["auth_user"])
		}
	})
}

func TestSOCKS5ContextFunctions(t *testing.T) {
	t.Run("auth method round-trip", func(t *testing.T) {
		ctx := context.Background()
		if got := proxy.SOCKS5AuthMethodFromContext(ctx); got != "" {
			t.Errorf("empty context: got %q, want empty", got)
		}

		ctx = proxy.ContextWithSOCKS5AuthMethod(ctx, "username_password")
		if got := proxy.SOCKS5AuthMethodFromContext(ctx); got != "username_password" {
			t.Errorf("got %q, want %q", got, "username_password")
		}
	})

	t.Run("auth user round-trip", func(t *testing.T) {
		ctx := context.Background()
		if got := proxy.SOCKS5AuthUserFromContext(ctx); got != "" {
			t.Errorf("empty context: got %q, want empty", got)
		}

		ctx = proxy.ContextWithSOCKS5AuthUser(ctx, "admin")
		if got := proxy.SOCKS5AuthUserFromContext(ctx); got != "admin" {
			t.Errorf("got %q, want %q", got, "admin")
		}
	})

	t.Run("target round-trip via proxy", func(t *testing.T) {
		ctx := context.Background()
		if got := proxy.SOCKS5TargetFromContext(ctx); got != "" {
			t.Errorf("empty context: got %q, want empty", got)
		}

		ctx = proxy.ContextWithSOCKS5Target(ctx, "example.com:443")
		if got := proxy.SOCKS5TargetFromContext(ctx); got != "example.com:443" {
			t.Errorf("got %q, want %q", got, "example.com:443")
		}
	})

	t.Run("SOCKS5TargetFromContext reads proxy context", func(t *testing.T) {
		// Verify that the socks5 package's SOCKS5TargetFromContext
		// reads the same value as proxy.SOCKS5TargetFromContext.
		ctx := proxy.ContextWithSOCKS5Target(context.Background(), "test:8080")
		if got := SOCKS5TargetFromContext(ctx); got != "test:8080" {
			t.Errorf("got %q, want %q", got, "test:8080")
		}
	})
}
