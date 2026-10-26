package mcpserver

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

func msPtr(v int) *int { return &v }

func newBootTimeoutManager(t *testing.T) *proxybuild.Manager {
	t.Helper()
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		StackFactory: func(context.Context, string, string) (*proxybuild.Stack, error) {
			return nil, errors.New("not used")
		},
		BuildConfig: &connector.BuildConfig{},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// TestApplyBootClientTimeouts is USK-1186 T4: the config file's
// request_timeout_ms / client_idle_timeout_ms seed the Manager at boot,
// keeping omitted (default), 0 (disabled) and a value distinct.
func TestApplyBootClientTimeouts(t *testing.T) {
	tests := []struct {
		name         string
		cfg          config.ProxyConfig
		wantReq      time.Duration
		wantReqOff   bool
		wantIdle     time.Duration
		wantIdleOff  bool
		wantDepsReq  time.Duration
		checkReqDur  bool
		checkIdleDur bool
	}{
		{
			name:         "omitted keeps defaults",
			cfg:          config.ProxyConfig{},
			wantReq:      60 * time.Second,
			wantIdle:     120 * time.Second,
			wantDepsReq:  60 * time.Second,
			checkReqDur:  true,
			checkIdleDur: true,
		},
		{
			name:        "zero disables both",
			cfg:         config.ProxyConfig{RequestTimeoutMs: msPtr(0), ClientIdleTimeoutMs: msPtr(0)},
			wantReqOff:  true,
			wantIdleOff: true,
			wantDepsReq: 0,
		},
		{
			name:         "values applied",
			cfg:          config.ProxyConfig{RequestTimeoutMs: msPtr(5000), ClientIdleTimeoutMs: msPtr(3000)},
			wantReq:      5 * time.Second,
			wantIdle:     3 * time.Second,
			wantDepsReq:  5 * time.Second,
			checkReqDur:  true,
			checkIdleDur: true,
		},
		{
			name:         "request only leaves idle default",
			cfg:          config.ProxyConfig{RequestTimeoutMs: msPtr(300)},
			wantReq:      300 * time.Millisecond,
			wantIdle:     120 * time.Second,
			wantDepsReq:  300 * time.Millisecond,
			checkReqDur:  true,
			checkIdleDur: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newBootTimeoutManager(t)
			applyBootClientTimeouts(mgr, &tc.cfg)

			if got := mgr.RequestTimeoutDisabled(); got != tc.wantReqOff {
				t.Errorf("RequestTimeoutDisabled() = %v, want %v", got, tc.wantReqOff)
			}
			if tc.checkReqDur {
				if got := mgr.RequestTimeout(); got != tc.wantReq {
					t.Errorf("RequestTimeout() = %v, want %v", got, tc.wantReq)
				}
			}
			if got := mgr.ClientIdleTimeoutDisabled(); got != tc.wantIdleOff {
				t.Errorf("ClientIdleTimeoutDisabled() = %v, want %v", got, tc.wantIdleOff)
			}
			if tc.checkIdleDur {
				if got := mgr.ClientIdleTimeout(); got != tc.wantIdle {
					t.Errorf("ClientIdleTimeout() = %v, want %v", got, tc.wantIdle)
				}
			}
			if got := bootRequestTimeout(&tc.cfg); got != tc.wantDepsReq {
				t.Errorf("bootRequestTimeout() = %v, want %v", got, tc.wantDepsReq)
			}
		})
	}
}

// TestRun_RejectsOutOfRangeClientTimeouts is USK-1186 T3: an out-of-range
// client timeout in the -config file stops Run at startup.
//
// -no-http-mcp without -stdio-mcp makes Run return on its own when the file
// is accepted, so a missing check shows up as the wrong error, not a hang.
func TestRun_RejectsOutOfRangeClientTimeouts(t *testing.T) {
	tests := []struct {
		name string
		json string
		key  string
	}{
		{"request below minimum", `{"request_timeout_ms": 50}`, "request_timeout_ms"},
		{"request negative", `{"request_timeout_ms": -1}`, "request_timeout_ms"},
		{"idle above maximum", `{"client_idle_timeout_ms": 700000}`, "client_idle_timeout_ms"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(cfgPath, []byte(tc.json), 0o644); err != nil {
				t.Fatalf("write config file: %v", err)
			}
			fs := flag.NewFlagSet("smoke-client-timeouts", flag.ContinueOnError)
			fs.SetOutput(discardWriter{})
			args := []string{
				"-config", cfgPath,
				"-db", filepath.Join(dir, "smoke.db"),
				"-ca-ephemeral",
				"-no-http-mcp",
			}
			err := Run(ctx, fs, args, RunOptions{Version: "smoke"})
			if err == nil {
				t.Fatal("Run with out-of-range client timeout: expected error, got nil")
			}
			for _, want := range []string{"invalid proxy config", tc.key} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Run error = %q, want substring %q", err.Error(), want)
				}
			}
		})
	}
}
