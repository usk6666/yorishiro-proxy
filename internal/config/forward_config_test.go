package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestProxyConfig_UnmarshalJSON_LegacyStringFormat(t *testing.T) {
	data := `{"tcp_forwards": {"3306": "db:3306", "6379": "redis:6379"}}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(cfg.TCPForwards) != 2 {
		t.Fatalf("len(TCPForwards) = %d, want 2", len(cfg.TCPForwards))
	}
	fc := cfg.TCPForwards["3306"]
	if fc == nil {
		t.Fatal("TCPForwards[3306] is nil")
	}
	if fc.Target != "db:3306" {
		t.Errorf("Target = %q, want db:3306", fc.Target)
	}
	if fc.Protocol != "raw" {
		t.Errorf("Protocol = %q, want raw", fc.Protocol)
	}
	if fc.TLS {
		t.Error("TLS should be false for legacy format")
	}
}

func TestProxyConfig_UnmarshalJSON_StructuredFormat(t *testing.T) {
	data := `{"tcp_forwards": {"50051": {"target": "api:50051", "protocol": "grpc", "tls": true}}}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	fc := cfg.TCPForwards["50051"]
	if fc == nil {
		t.Fatal("TCPForwards[50051] is nil")
	}
	if fc.Target != "api:50051" {
		t.Errorf("Target = %q, want api:50051", fc.Target)
	}
	if fc.Protocol != "grpc" {
		t.Errorf("Protocol = %q, want grpc", fc.Protocol)
	}
	if !fc.TLS {
		t.Error("TLS should be true")
	}
}

func TestProxyConfig_UnmarshalJSON_MixedFormat(t *testing.T) {
	data := `{"tcp_forwards": {"3306": "db:3306", "50051": {"target": "api:50051", "protocol": "grpc", "tls": true}}}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(cfg.TCPForwards) != 2 {
		t.Fatalf("len(TCPForwards) = %d, want 2", len(cfg.TCPForwards))
	}

	// Legacy entry.
	legacy := cfg.TCPForwards["3306"]
	if legacy == nil || legacy.Target != "db:3306" || legacy.Protocol != "raw" {
		t.Errorf("legacy entry: %+v", legacy)
	}

	// Structured entry.
	structured := cfg.TCPForwards["50051"]
	if structured == nil || structured.Target != "api:50051" || structured.Protocol != "grpc" || !structured.TLS {
		t.Errorf("structured entry: %+v", structured)
	}
}

func TestProxyConfig_UnmarshalJSON_EmptyTCPForwards(t *testing.T) {
	data := `{"listen_addr": "127.0.0.1:8080"}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.TCPForwards != nil {
		t.Errorf("TCPForwards should be nil, got %v", cfg.TCPForwards)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8080", cfg.ListenAddr)
	}
}

func TestProxyConfig_UnmarshalJSON_OtherFieldsPreserved(t *testing.T) {
	data := `{
		"listen_addr": "127.0.0.1:9090",
		"upstream_proxy": "http://proxy:8080",
		"tcp_forwards": {"3306": "db:3306"},
		"tls_passthrough": ["example.com"]
	}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9090", cfg.ListenAddr)
	}
	if cfg.UpstreamProxy != "http://proxy:8080" {
		t.Errorf("UpstreamProxy = %q", cfg.UpstreamProxy)
	}
	if len(cfg.TLSPassthrough) != 1 || cfg.TLSPassthrough[0] != "example.com" {
		t.Errorf("TLSPassthrough = %v", cfg.TLSPassthrough)
	}
}

func TestProxyConfig_UnmarshalJSON_InvalidValue(t *testing.T) {
	data := `{"tcp_forwards": {"3306": 12345}}`
	var cfg ProxyConfig
	err := json.Unmarshal([]byte(data), &cfg)
	if err == nil {
		t.Fatal("expected error for non-string, non-object value")
	}
}

func TestProxyConfig_MarshalJSON_RoundTrip(t *testing.T) {
	cfg := ProxyConfig{
		ListenAddr: "127.0.0.1:8080",
		TCPForwards: map[string]*ForwardConfig{
			"3306":  {Target: "db:3306", Protocol: "raw"},
			"50051": {Target: "api:50051", Protocol: "grpc", TLS: true},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var cfg2 ProxyConfig
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(cfg2.TCPForwards) != 2 {
		t.Fatalf("round-trip: len(TCPForwards) = %d, want 2", len(cfg2.TCPForwards))
	}
	if fc := cfg2.TCPForwards["50051"]; fc == nil || fc.Target != "api:50051" || fc.Protocol != "grpc" || !fc.TLS {
		t.Errorf("round-trip: 50051 = %+v", fc)
	}
}

func TestProxyConfig_UnmarshalJSON_StructuredWithDefaults(t *testing.T) {
	// Protocol defaults to empty, which means "auto".
	data := `{"tcp_forwards": {"8080": {"target": "web:8080"}}}`
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	fc := cfg.TCPForwards["8080"]
	if fc == nil {
		t.Fatal("nil")
	}
	if fc.Protocol != "" {
		t.Errorf("Protocol = %q, want empty (auto)", fc.Protocol)
	}
	if fc.TLS {
		t.Error("TLS should default to false")
	}
}

func TestValidateForwardConfig(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		fc      *ForwardConfig
		wantErr string
	}{
		{
			name: "valid raw",
			port: "3306",
			fc:   &ForwardConfig{Target: "db:3306", Protocol: "raw"},
		},
		{
			name: "valid auto (empty protocol)",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080"},
		},
		{
			name: "valid grpc with tls",
			port: "50051",
			fc:   &ForwardConfig{Target: "api:50051", Protocol: "grpc", TLS: true},
		},
		{
			name: "valid auto explicit",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080", Protocol: "auto"},
		},
		{
			name:    "nil config",
			port:    "3306",
			fc:      nil,
			wantErr: "nil",
		},
		{
			name:    "empty target",
			port:    "3306",
			fc:      &ForwardConfig{Target: "", Protocol: "raw"},
			wantErr: "target cannot be empty",
		},
		{
			name:    "invalid protocol",
			port:    "3306",
			fc:      &ForwardConfig{Target: "db:3306", Protocol: "ftp"},
			wantErr: "invalid protocol",
		},
		{
			name: "tls with raw emits warning but no error",
			port: "3306",
			fc:   &ForwardConfig{Target: "db:3306", Protocol: "raw", TLS: true},
		},
		{
			name: "valid http",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080", Protocol: "http"},
		},
		{
			name: "valid http2",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080", Protocol: "http2"},
		},
		{
			name: "valid websocket",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080", Protocol: "websocket"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateForwardConfig(tt.port, tt.fc)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidForwardProtocols(t *testing.T) {
	expected := []string{"", "auto", "raw", "http", "http2", "grpc", "websocket"}
	for _, p := range expected {
		if !ValidForwardProtocols[p] {
			t.Errorf("protocol %q should be valid", p)
		}
	}
	invalid := []string{"ftp", "ssh", "HTTP", "HTTP2", "GRPC"}
	for _, p := range invalid {
		if ValidForwardProtocols[p] {
			t.Errorf("protocol %q should be invalid", p)
		}
	}
}

func TestLoadFile_WithForwardConfig(t *testing.T) {
	dir := t.TempDir()

	// Write a config file with mixed tcp_forwards format.
	configPath := dir + "/config.json"
	data := `{
		"tcp_forwards": {
			"3306": "db:3306",
			"50051": {"target": "api:50051", "protocol": "grpc", "tls": true}
		}
	}`
	if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(configPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if len(cfg.TCPForwards) != 2 {
		t.Fatalf("len(TCPForwards) = %d, want 2", len(cfg.TCPForwards))
	}

	legacy := cfg.TCPForwards["3306"]
	if legacy == nil || legacy.Target != "db:3306" || legacy.Protocol != "raw" {
		t.Errorf("legacy = %+v", legacy)
	}

	structured := cfg.TCPForwards["50051"]
	if structured == nil || structured.Target != "api:50051" || structured.Protocol != "grpc" || !structured.TLS {
		t.Errorf("structured = %+v", structured)
	}
}
