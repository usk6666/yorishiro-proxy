package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInterceptQueue(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *ProxyConfig
		wantErr string
	}{
		{name: "nil config OK", cfg: nil},
		{name: "nil intercept_queue OK", cfg: &ProxyConfig{}},
		{name: "empty intercept_queue OK", cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{}}},
		{
			name: "valid global",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				TimeoutMs:       30000,
				TimeoutBehavior: "auto_release",
			}},
		},
		{
			name: "valid protocol_overrides",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				TimeoutMs: 60000,
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"ws":   {TimeoutMs: 2000, TimeoutBehavior: "auto_release"},
					"sse":  {TimeoutMs: 5000},
					"grpc": {TimeoutBehavior: "auto_drop"},
				},
			}},
		},
		{
			name: "global timeout sub-floor rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				TimeoutMs: 500,
			}},
			wantErr: "intercept_queue.timeout_ms must be >= 1000",
		},
		{
			name: "global timeout negative rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				TimeoutMs: -1,
			}},
			wantErr: "intercept_queue.timeout_ms must be >= 0",
		},
		{
			name: "global behavior invalid rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				TimeoutBehavior: "auto_explode",
			}},
			wantErr: `intercept_queue.timeout_behavior "auto_explode" is not valid`,
		},
		{
			name: "unknown protocol key rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"http2": {TimeoutMs: 5000},
				},
			}},
			wantErr: `intercept_queue.protocol_overrides["http2"]: unknown protocol key`,
		},
		{
			name: "unknown protocol key lists valid set",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"http2": {TimeoutMs: 5000},
				},
			}},
			wantErr: "valid keys:",
		},
		{
			name: "protocol override sub-floor rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"ws": {TimeoutMs: 500},
				},
			}},
			wantErr: `intercept_queue.protocol_overrides["ws"].timeout_ms must be >= 1000`,
		},
		{
			name: "protocol override negative rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"ws": {TimeoutMs: -1},
				},
			}},
			wantErr: `intercept_queue.protocol_overrides["ws"].timeout_ms must be >= 0`,
		},
		{
			name: "protocol override invalid behavior rejected",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"ws": {TimeoutBehavior: "auto_explode"},
				},
			}},
			wantErr: `intercept_queue.protocol_overrides["ws"].timeout_behavior "auto_explode" is not valid`,
		},
		{
			name: "null protocol override entry tolerated",
			cfg: &ProxyConfig{InterceptQueue: &InterceptQueueConfig{
				ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
					"ws": nil,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.cfg != nil {
				err = tt.cfg.validateInterceptQueue()
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestProxyConfigValidate_ChainsInterceptQueue confirms that the
// ProxyConfig.Validate() chain surfaces the intercept_queue validator
// errors. Without this guard, a sub-floor / unknown-key payload could
// load silently when callers go through Validate() rather than the
// dedicated helper.
func TestProxyConfigValidate_ChainsInterceptQueue(t *testing.T) {
	cfg := &ProxyConfig{
		InterceptQueue: &InterceptQueueConfig{
			ProtocolOverrides: map[string]*InterceptQueueProtocolOverride{
				"http2": {TimeoutMs: 5000}, // not a valid envelope.Protocol
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate() to reject unknown protocol key, got nil")
	} else if !strings.Contains(err.Error(), "unknown protocol key") {
		t.Errorf("err = %q, want substring %q", err.Error(), "unknown protocol key")
	}
}

// TestLoadFile_InterceptQueue verifies that LoadFile parses the new
// top-level "intercept_queue" section into the corresponding pointer
// field on ProxyConfig.
func TestLoadFile_InterceptQueue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	body := `{
  "listen_addr": "127.0.0.1:9999",
  "intercept_queue": {
    "timeout_ms": 60000,
    "timeout_behavior": "auto_release",
    "protocol_overrides": {
      "ws":  {"timeout_ms": 8000},
      "sse": {"timeout_ms": 8000},
      "grpc": {"timeout_ms": 60000, "timeout_behavior": "auto_release"}
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.InterceptQueue == nil {
		t.Fatal("InterceptQueue: got nil, want non-nil")
	}
	if cfg.InterceptQueue.TimeoutMs != 60000 {
		t.Errorf("TimeoutMs = %d, want 60000", cfg.InterceptQueue.TimeoutMs)
	}
	if cfg.InterceptQueue.TimeoutBehavior != "auto_release" {
		t.Errorf("TimeoutBehavior = %q, want auto_release", cfg.InterceptQueue.TimeoutBehavior)
	}
	if got := cfg.InterceptQueue.ProtocolOverrides["ws"]; got == nil || got.TimeoutMs != 8000 {
		t.Errorf("ProtocolOverrides[ws] = %+v, want TimeoutMs=8000", got)
	}
	if got := cfg.InterceptQueue.ProtocolOverrides["grpc"]; got == nil || got.TimeoutMs != 60000 || got.TimeoutBehavior != "auto_release" {
		t.Errorf("ProtocolOverrides[grpc] = %+v, want TimeoutMs=60000 + behavior", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: unexpected error %v", err)
	}
}

// TestLoadFile_NoInterceptQueue_BackwardCompat verifies that a config
// file without the new key parses successfully and leaves the
// InterceptQueue pointer nil — built-in defaults must apply.
func TestLoadFile_NoInterceptQueue_BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	body := `{"listen_addr": "127.0.0.1:9999"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.InterceptQueue != nil {
		t.Errorf("InterceptQueue = %+v, want nil", cfg.InterceptQueue)
	}
}

// TestInterceptQueue_JSONRoundTrip_Omitempty ensures the new field
// honours omitempty so existing serialized configs round-trip without
// gaining a new key.
func TestInterceptQueue_JSONRoundTrip_Omitempty(t *testing.T) {
	cfg := ProxyConfig{ListenAddr: "127.0.0.1:8080"}
	out, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"intercept_queue"`) {
		t.Errorf("Marshal output unexpectedly contains intercept_queue: %s", out)
	}
	cfg.InterceptQueue = &InterceptQueueConfig{TimeoutMs: 30000}
	out, err = json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"intercept_queue"`) {
		t.Errorf("Marshal output missing intercept_queue: %s", out)
	}
}
