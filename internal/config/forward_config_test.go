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
	if fc.UpstreamTLS {
		t.Error("UpstreamTLS should default to false when omitted")
	}
}

// TestForwardConfig_UnmarshalJSON_TLSUpstreamTLSMatrix exercises every
// combination of (tls, upstream_tls) across the JSON unmarshal path so
// the four scenarios described in the ForwardConfig godoc are
// independently verified. USK-911.
func TestForwardConfig_UnmarshalJSON_TLSUpstreamTLSMatrix(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		wantTLS  bool
		wantUTLS bool
	}{
		{
			name:     "both false (default raw forwarding)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "raw"}}}`,
			wantTLS:  false,
			wantUTLS: false,
		},
		{
			name:     "tls only (client-side termination)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "tls": true}}}`,
			wantTLS:  true,
			wantUTLS: false,
		},
		{
			name:     "upstream_tls only (plaintext client to TLS upstream)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "upstream_tls": true}}}`,
			wantTLS:  false,
			wantUTLS: true,
		},
		{
			name:     "both true (full MITM with re-encryption)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "tls": true, "upstream_tls": true}}}`,
			wantTLS:  true,
			wantUTLS: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg ProxyConfig
			if err := json.Unmarshal([]byte(tc.json), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			fc := cfg.TCPForwards["9000"]
			if fc == nil {
				t.Fatal("TCPForwards[9000] is nil")
			}
			if fc.TLS != tc.wantTLS {
				t.Errorf("TLS = %v, want %v", fc.TLS, tc.wantTLS)
			}
			if fc.UpstreamTLS != tc.wantUTLS {
				t.Errorf("UpstreamTLS = %v, want %v", fc.UpstreamTLS, tc.wantUTLS)
			}
		})
	}
}

// TestForwardConfig_MarshalJSON_OmitEmptyDefaults verifies that the
// omitempty tag on UpstreamTLS prevents the field from leaking false
// defaults into the serialized output, matching the existing TLS
// behavior. USK-911.
//
// USK-918: also asserts that the *bool UpstreamInsecureSkipVerify is
// omitted when nil but emitted (including the explicit `false`) when
// non-nil. The tri-state distinguishes "inherit global" from
// "explicitly enforce" — the explicit false MUST survive Marshal.
func TestForwardConfig_MarshalJSON_OmitEmptyDefaults(t *testing.T) {
	fc := &ForwardConfig{Target: "h:9000", Protocol: "raw"}
	data, err := json.Marshal(fc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "upstream_tls") {
		t.Errorf("Marshal output should omit upstream_tls when false, got %s", s)
	}
	if strings.Contains(s, `"tls"`) {
		t.Errorf("Marshal output should omit tls when false, got %s", s)
	}
	if strings.Contains(s, "upstream_insecure_skip_verify") {
		t.Errorf("Marshal output should omit upstream_insecure_skip_verify when nil, got %s", s)
	}

	fc2 := &ForwardConfig{Target: "h:9000", Protocol: "raw", UpstreamTLS: true}
	data2, err := json.Marshal(fc2)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data2), `"upstream_tls":true`) {
		t.Errorf("Marshal output should include upstream_tls=true, got %s", string(data2))
	}

	// USK-918: *bool=true must Marshal to "upstream_insecure_skip_verify":true.
	skip := true
	fc3 := &ForwardConfig{Target: "h:9000", Protocol: "raw", UpstreamInsecureSkipVerify: &skip}
	data3, err := json.Marshal(fc3)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data3), `"upstream_insecure_skip_verify":true`) {
		t.Errorf("Marshal output should include upstream_insecure_skip_verify=true, got %s", string(data3))
	}

	// USK-918: *bool=false MUST also Marshal (NOT be omitted) — it
	// distinguishes "explicitly enforce" from "inherit global".
	enforce := false
	fc4 := &ForwardConfig{Target: "h:9000", Protocol: "raw", UpstreamInsecureSkipVerify: &enforce}
	data4, err := json.Marshal(fc4)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data4), `"upstream_insecure_skip_verify":false`) {
		t.Errorf("Marshal output should include upstream_insecure_skip_verify=false (tri-state preserves explicit enforce), got %s", string(data4))
	}
}

// TestForwardConfig_MarshalJSON_RoundTrip_AllCombinations confirms the
// (tls, upstream_tls, upstream_insecure_skip_verify) bits survive a
// Marshal → Unmarshal cycle in every combination. USK-911 / USK-918.
func TestForwardConfig_MarshalJSON_RoundTrip_AllCombinations(t *testing.T) {
	skip := true
	enforce := false
	cases := []struct {
		name string
		fc   ForwardConfig
	}{
		{"both false", ForwardConfig{Target: "h:9000", Protocol: "raw"}},
		{"tls only", ForwardConfig{Target: "h:9000", Protocol: "http", TLS: true}},
		{"upstream_tls only", ForwardConfig{Target: "h:9000", Protocol: "http", UpstreamTLS: true}},
		{"both true", ForwardConfig{Target: "h:9000", Protocol: "http", TLS: true, UpstreamTLS: true}},
		// USK-918: tri-state UpstreamInsecureSkipVerify must round-trip.
		{"upstream_tls + skip true", ForwardConfig{Target: "h:9000", Protocol: "http", UpstreamTLS: true, UpstreamInsecureSkipVerify: &skip}},
		{"upstream_tls + skip false (enforce)", ForwardConfig{Target: "h:9000", Protocol: "http", UpstreamTLS: true, UpstreamInsecureSkipVerify: &enforce}},
		{"both true + skip true", ForwardConfig{Target: "h:9000", Protocol: "http", TLS: true, UpstreamTLS: true, UpstreamInsecureSkipVerify: &skip}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.fc)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var got ForwardConfig
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got.TLS != tc.fc.TLS {
				t.Errorf("TLS round-trip = %v, want %v (json=%s)", got.TLS, tc.fc.TLS, string(data))
			}
			if got.UpstreamTLS != tc.fc.UpstreamTLS {
				t.Errorf("UpstreamTLS round-trip = %v, want %v (json=%s)", got.UpstreamTLS, tc.fc.UpstreamTLS, string(data))
			}
			// USK-918: pointer-aware comparison so nil round-trips to nil
			// (inherit) and explicit true/false survive.
			switch {
			case tc.fc.UpstreamInsecureSkipVerify == nil && got.UpstreamInsecureSkipVerify != nil:
				t.Errorf("UpstreamInsecureSkipVerify round-trip = %v, want nil (json=%s)", *got.UpstreamInsecureSkipVerify, string(data))
			case tc.fc.UpstreamInsecureSkipVerify != nil && got.UpstreamInsecureSkipVerify == nil:
				t.Errorf("UpstreamInsecureSkipVerify round-trip = nil, want %v (json=%s)", *tc.fc.UpstreamInsecureSkipVerify, string(data))
			case tc.fc.UpstreamInsecureSkipVerify != nil && got.UpstreamInsecureSkipVerify != nil:
				if *got.UpstreamInsecureSkipVerify != *tc.fc.UpstreamInsecureSkipVerify {
					t.Errorf("UpstreamInsecureSkipVerify round-trip = %v, want %v (json=%s)",
						*got.UpstreamInsecureSkipVerify, *tc.fc.UpstreamInsecureSkipVerify, string(data))
				}
			}
		})
	}
}

// TestForwardConfig_UnmarshalJSON_UpstreamInsecureSkipVerify pins the
// JSON-unmarshal handling of the USK-918 tri-state field across nil/true/
// false inputs.
func TestForwardConfig_UnmarshalJSON_UpstreamInsecureSkipVerify(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		wantNil  bool
		wantBool bool
	}{
		{
			name:    "omitted -> nil (inherit global)",
			json:    `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "upstream_tls": true}}}`,
			wantNil: true,
		},
		{
			name:     "true -> *true (skip verify)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "upstream_tls": true, "upstream_insecure_skip_verify": true}}}`,
			wantNil:  false,
			wantBool: true,
		},
		{
			name:     "false -> *false (enforce verify)",
			json:     `{"tcp_forwards": {"9000": {"target": "h:9000", "protocol": "http", "upstream_tls": true, "upstream_insecure_skip_verify": false}}}`,
			wantNil:  false,
			wantBool: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg ProxyConfig
			if err := json.Unmarshal([]byte(tc.json), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			fc := cfg.TCPForwards["9000"]
			if fc == nil {
				t.Fatal("TCPForwards[9000] is nil")
			}
			if tc.wantNil {
				if fc.UpstreamInsecureSkipVerify != nil {
					t.Errorf("UpstreamInsecureSkipVerify = %v (non-nil), want nil", *fc.UpstreamInsecureSkipVerify)
				}
				return
			}
			if fc.UpstreamInsecureSkipVerify == nil {
				t.Fatal("UpstreamInsecureSkipVerify = nil, want non-nil")
			}
			if *fc.UpstreamInsecureSkipVerify != tc.wantBool {
				t.Errorf("UpstreamInsecureSkipVerify = %v, want %v", *fc.UpstreamInsecureSkipVerify, tc.wantBool)
			}
		})
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
			name: "upstream_tls with raw is accepted (warn happens at MCP layer)",
			port: "3306",
			fc:   &ForwardConfig{Target: "db:3306", Protocol: "raw", UpstreamTLS: true},
		},
		{
			name: "tls and upstream_tls both true is valid (full MITM re-encrypt)",
			port: "443",
			fc:   &ForwardConfig{Target: "h:443", Protocol: "http", TLS: true, UpstreamTLS: true},
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
		{
			// USK-913: "sse" is the operator-declared expectation that the
			// upstream returns a streaming text/event-stream response; the
			// proxybuild forward dispatch refuses the connection when the
			// expectation is unmet (symmetric with "websocket").
			name: "valid sse",
			port: "8080",
			fc:   &ForwardConfig{Target: "web:8080", Protocol: "sse"},
		},
		{
			// USK-918: the per-entry verify-skip override is structurally
			// validated by JSON schema and does not affect
			// ValidateForwardConfig. Any *bool value is accepted; the
			// MCP layer warns on the meaningless combination
			// (skip=true && upstream_tls=false).
			name: "valid upstream_tls + skip true",
			port: "8443",
			fc: func() *ForwardConfig {
				b := true
				return &ForwardConfig{Target: "h:8443", Protocol: "http", UpstreamTLS: true, UpstreamInsecureSkipVerify: &b}
			}(),
		},
		{
			name: "valid upstream_tls + skip false (enforce)",
			port: "8443",
			fc: func() *ForwardConfig {
				b := false
				return &ForwardConfig{Target: "h:8443", Protocol: "http", UpstreamTLS: true, UpstreamInsecureSkipVerify: &b}
			}(),
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
	validProtocols := []string{"", "auto", "raw", "http", "http2", "grpc", "websocket", "sse"}
	for _, p := range validProtocols {
		fc := &ForwardConfig{Target: "host:1234", Protocol: p}
		if err := ValidateForwardConfig("9999", fc); err != nil {
			t.Errorf("protocol %q should be valid, got error: %v", p, err)
		}
	}
	invalidProtocols := []string{"ftp", "ssh", "HTTP", "HTTP2", "GRPC"}
	for _, p := range invalidProtocols {
		fc := &ForwardConfig{Target: "host:1234", Protocol: p}
		if err := ValidateForwardConfig("9999", fc); err == nil {
			t.Errorf("protocol %q should be invalid, but no error returned", p)
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
