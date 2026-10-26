package connector

import (
	"testing"
	"time"
)

// TestBuildConfig_EffectiveRequestHeaderTimeout pins the USK-1162 accessor
// precedence: dynamic override > static field > DefaultRequestHeaderTimeout,
// with 0 / negative meaning "unset" at every level.
func TestBuildConfig_EffectiveRequestHeaderTimeout(t *testing.T) {
	tests := []struct {
		name    string
		static  time.Duration
		dynamic time.Duration
		want    time.Duration
	}{
		{"all unset → default", 0, 0, DefaultRequestHeaderTimeout},
		{"static only", 3 * time.Second, 0, 3 * time.Second},
		{"dynamic overrides static", 3 * time.Second, 7 * time.Second, 7 * time.Second},
		{"dynamic only", 0, 7 * time.Second, 7 * time.Second},
		{"negative dynamic clears", 3 * time.Second, -1, 3 * time.Second},
		{"negative static → default", -1, 0, DefaultRequestHeaderTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &BuildConfig{RequestHeaderTimeout: tt.static}
			c.SetRequestHeaderTimeout(tt.dynamic)
			if got := c.EffectiveRequestHeaderTimeout(); got != tt.want {
				t.Errorf("EffectiveRequestHeaderTimeout = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildConfig_RequestHeaderTimeout_ClearOverride(t *testing.T) {
	c := &BuildConfig{RequestHeaderTimeout: 3 * time.Second}
	c.SetRequestHeaderTimeout(9 * time.Second)
	c.SetRequestHeaderTimeout(0)
	if got := c.EffectiveRequestHeaderTimeout(); got != 3*time.Second {
		t.Errorf("after clear = %v, want static 3s", got)
	}
}

func TestBuildConfig_RequestHeaderTimeout_NilSafe(t *testing.T) {
	var c *BuildConfig
	c.SetRequestHeaderTimeout(time.Second) // must not panic
	if got := c.EffectiveRequestHeaderTimeout(); got != DefaultRequestHeaderTimeout {
		t.Errorf("nil BuildConfig = %v, want default %v", got, DefaultRequestHeaderTimeout)
	}
}

// USK-1185: request_timeout_ms: 0 disables the client request-head bound.
// "Disabled" is a separate state from the internal 0 ("unset / default"),
// resolved by ClientRequestHeadDeadline.
func TestBuildConfig_ClientRequestHeadDeadline(t *testing.T) {
	t.Run("default enabled", func(t *testing.T) {
		c := &BuildConfig{}
		if d, ok := c.ClientRequestHeadDeadline(); !ok || d != DefaultRequestHeaderTimeout {
			t.Errorf("ClientRequestHeadDeadline = (%v, %v), want (%v, true)", d, ok, DefaultRequestHeaderTimeout)
		}
	})
	t.Run("static enabled", func(t *testing.T) {
		c := &BuildConfig{RequestHeaderTimeout: 3 * time.Second}
		if d, ok := c.ClientRequestHeadDeadline(); !ok || d != 3*time.Second {
			t.Errorf("ClientRequestHeadDeadline = (%v, %v), want (3s, true)", d, ok)
		}
	})
	t.Run("disabled overrides static", func(t *testing.T) {
		c := &BuildConfig{RequestHeaderTimeout: 3 * time.Second}
		c.DisableRequestHeaderTimeout()
		if _, ok := c.ClientRequestHeadDeadline(); ok {
			t.Error("ClientRequestHeadDeadline reports enabled after DisableRequestHeaderTimeout")
		}
	})
	t.Run("positive set re-enables", func(t *testing.T) {
		c := &BuildConfig{RequestHeaderTimeout: 3 * time.Second}
		c.DisableRequestHeaderTimeout()
		c.SetRequestHeaderTimeout(7 * time.Second)
		if d, ok := c.ClientRequestHeadDeadline(); !ok || d != 7*time.Second {
			t.Errorf("ClientRequestHeadDeadline = (%v, %v), want (7s, true)", d, ok)
		}
	})
	t.Run("set zero clears override and disabled", func(t *testing.T) {
		c := &BuildConfig{RequestHeaderTimeout: 3 * time.Second}
		c.SetRequestHeaderTimeout(9 * time.Second)
		c.DisableRequestHeaderTimeout()
		c.SetRequestHeaderTimeout(0)
		if d, ok := c.ClientRequestHeadDeadline(); !ok || d != 3*time.Second {
			t.Errorf("ClientRequestHeadDeadline = (%v, %v), want static (3s, true)", d, ok)
		}
	})
	t.Run("nil receiver", func(t *testing.T) {
		var c *BuildConfig
		c.DisableRequestHeaderTimeout() // must not panic
		if d, ok := c.ClientRequestHeadDeadline(); !ok || d != DefaultRequestHeaderTimeout {
			t.Errorf("nil ClientRequestHeadDeadline = (%v, %v), want (%v, true)", d, ok, DefaultRequestHeaderTimeout)
		}
	})
}

// USK-1185: client_idle_timeout_ms — the keep-alive wait for the first byte
// of the next request. Default 120s; 0 on the MCP surface disables it.
func TestBuildConfig_ClientIdleDeadline(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		c := &BuildConfig{}
		if d, ok := c.ClientIdleDeadline(); !ok || d != DefaultClientIdleTimeout {
			t.Errorf("ClientIdleDeadline = (%v, %v), want (%v, true)", d, ok, DefaultClientIdleTimeout)
		}
		if DefaultClientIdleTimeout != 120*time.Second {
			t.Errorf("DefaultClientIdleTimeout = %v, want 120s", DefaultClientIdleTimeout)
		}
	})
	t.Run("set value", func(t *testing.T) {
		c := &BuildConfig{}
		c.SetClientIdleTimeout(5 * time.Second)
		if d, ok := c.ClientIdleDeadline(); !ok || d != 5*time.Second {
			t.Errorf("ClientIdleDeadline = (%v, %v), want (5s, true)", d, ok)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		c := &BuildConfig{}
		c.SetClientIdleTimeout(5 * time.Second)
		c.DisableClientIdleTimeout()
		if _, ok := c.ClientIdleDeadline(); ok {
			t.Error("ClientIdleDeadline reports enabled after DisableClientIdleTimeout")
		}
	})
	t.Run("positive set re-enables", func(t *testing.T) {
		c := &BuildConfig{}
		c.DisableClientIdleTimeout()
		c.SetClientIdleTimeout(2 * time.Second)
		if d, ok := c.ClientIdleDeadline(); !ok || d != 2*time.Second {
			t.Errorf("ClientIdleDeadline = (%v, %v), want (2s, true)", d, ok)
		}
	})
	t.Run("set zero restores default", func(t *testing.T) {
		c := &BuildConfig{}
		c.SetClientIdleTimeout(2 * time.Second)
		c.DisableClientIdleTimeout()
		c.SetClientIdleTimeout(0)
		if d, ok := c.ClientIdleDeadline(); !ok || d != DefaultClientIdleTimeout {
			t.Errorf("ClientIdleDeadline = (%v, %v), want default (%v, true)", d, ok, DefaultClientIdleTimeout)
		}
	})
	t.Run("nil receiver", func(t *testing.T) {
		var c *BuildConfig
		c.SetClientIdleTimeout(time.Second) // must not panic
		c.DisableClientIdleTimeout()        // must not panic
		if d, ok := c.ClientIdleDeadline(); !ok || d != DefaultClientIdleTimeout {
			t.Errorf("nil ClientIdleDeadline = (%v, %v), want (%v, true)", d, ok, DefaultClientIdleTimeout)
		}
	})
}
