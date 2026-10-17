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

func TestDefaultRequestHeaderTimeout_MatchesConfigDefault(t *testing.T) {
	if DefaultRequestHeaderTimeout != 60*time.Second {
		t.Errorf("DefaultRequestHeaderTimeout = %v, want 60s (config.Default().RequestTimeout)", DefaultRequestHeaderTimeout)
	}
}
