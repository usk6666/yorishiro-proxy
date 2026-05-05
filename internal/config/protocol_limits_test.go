package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWSMaxFrameSize(t *testing.T) {
	tests := []struct {
		name string
		in   *WebSocketLimits
		want int64
	}{
		{name: "nil substruct → default", in: nil, want: MaxWebSocketFrameSize},
		{name: "zero → default", in: &WebSocketLimits{MaxFrameSize: 0}, want: MaxWebSocketFrameSize},
		{name: "positive → input", in: &WebSocketLimits{MaxFrameSize: 1024}, want: 1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveWSMaxFrameSize(tt.in); got != tt.want {
				t.Errorf("ResolveWSMaxFrameSize(%+v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveWSDeflateEnabled(t *testing.T) {
	yes := true
	no := false
	tests := []struct {
		name string
		in   *WebSocketLimits
		want bool
	}{
		{name: "nil substruct → default true", in: nil, want: true},
		{name: "nil DeflateEnabled → default true", in: &WebSocketLimits{DeflateEnabled: nil}, want: true},
		{name: "explicit true", in: &WebSocketLimits{DeflateEnabled: &yes}, want: true},
		{name: "explicit false", in: &WebSocketLimits{DeflateEnabled: &no}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveWSDeflateEnabled(tt.in); got != tt.want {
				t.Errorf("ResolveWSDeflateEnabled(%+v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveGRPCMaxMessageSize(t *testing.T) {
	tests := []struct {
		name string
		in   *GRPCLimits
		want uint32
	}{
		{name: "nil substruct → default", in: nil, want: MaxGRPCMessageSize},
		{name: "zero → default", in: &GRPCLimits{MaxMessageSize: 0}, want: MaxGRPCMessageSize},
		{name: "positive → input", in: &GRPCLimits{MaxMessageSize: 4096}, want: 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveGRPCMaxMessageSize(tt.in); got != tt.want {
				t.Errorf("ResolveGRPCMaxMessageSize(%+v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveSSEMaxEventSize(t *testing.T) {
	tests := []struct {
		name string
		in   *SSELimits
		want int
	}{
		{name: "nil substruct → default", in: nil, want: MaxSSEEventSize},
		{name: "zero → default", in: &SSELimits{MaxEventSize: 0}, want: MaxSSEEventSize},
		{name: "positive → input", in: &SSELimits{MaxEventSize: 2048}, want: 2048},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveSSEMaxEventSize(tt.in); got != tt.want {
				t.Errorf("ResolveSSEMaxEventSize(%+v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateProtocolLimits(t *testing.T) {
	zero := int64(0)
	posWS := &WebSocketLimits{MaxFrameSize: 1024}
	zeroWS := &WebSocketLimits{MaxFrameSize: zero}
	negWS := &WebSocketLimits{MaxFrameSize: -1}
	posGRPC := &GRPCLimits{MaxMessageSize: 4096}
	zeroGRPC := &GRPCLimits{}
	posSSE := &SSELimits{MaxEventSize: 2048}
	zeroSSE := &SSELimits{}
	negSSE := &SSELimits{MaxEventSize: -1}

	tests := []struct {
		name    string
		ws      *WebSocketLimits
		grpc    *GRPCLimits
		sse     *SSELimits
		wantErr string
	}{
		{name: "all nil OK"},
		{name: "all zero OK", ws: zeroWS, grpc: zeroGRPC, sse: zeroSSE},
		{name: "all positive OK", ws: posWS, grpc: posGRPC, sse: posSSE},
		{name: "negative ws frame size rejected", ws: negWS, wantErr: "web_socket.max_frame_size"},
		{name: "negative sse event size rejected", sse: negSSE, wantErr: "sse.max_event_size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolLimits(tt.ws, tt.grpc, tt.sse)
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

// TestLoadFile_NewProtocolLimitsFields verifies that LoadFile parses the
// new top-level "web_socket" / "grpc" / "sse" sections into the
// corresponding pointer fields on ProxyConfig. The presence of the
// substructs is what enables the resolver helpers to surface
// user-configured values; absence (nil) routes to defaults.
func TestLoadFile_NewProtocolLimitsFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	yes := true
	body := `{
  "listen_addr": "127.0.0.1:9999",
  "web_socket": {"max_frame_size": 8192, "deflate_enabled": true},
  "grpc": {"max_message_size": 1048576},
  "sse": {"max_event_size": 16384}
}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.WebSocket == nil {
		t.Fatal("WebSocket: got nil, want non-nil")
	}
	if cfg.WebSocket.MaxFrameSize != 8192 {
		t.Errorf("WebSocket.MaxFrameSize = %d, want 8192", cfg.WebSocket.MaxFrameSize)
	}
	if cfg.WebSocket.DeflateEnabled == nil || *cfg.WebSocket.DeflateEnabled != yes {
		t.Errorf("WebSocket.DeflateEnabled = %v, want pointer to true", cfg.WebSocket.DeflateEnabled)
	}
	if cfg.GRPC == nil || cfg.GRPC.MaxMessageSize != 1048576 {
		t.Errorf("GRPC.MaxMessageSize = %v, want 1048576", cfg.GRPC)
	}
	if cfg.SSE == nil || cfg.SSE.MaxEventSize != 16384 {
		t.Errorf("SSE.MaxEventSize = %v, want 16384", cfg.SSE)
	}
}

// TestLoadFile_NoNewFields_BackwardCompat verifies that a config file
// without the new keys parses successfully and leaves the new fields nil.
// Resolve* helpers should then return the package defaults.
func TestLoadFile_NoNewFields_BackwardCompat(t *testing.T) {
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
	if cfg.WebSocket != nil {
		t.Errorf("WebSocket = %+v, want nil", cfg.WebSocket)
	}
	if cfg.GRPC != nil {
		t.Errorf("GRPC = %+v, want nil", cfg.GRPC)
	}
	if cfg.SSE != nil {
		t.Errorf("SSE = %+v, want nil", cfg.SSE)
	}
	// Resolvers must surface defaults when the substructs are nil.
	if got := ResolveWSMaxFrameSize(cfg.WebSocket); got != MaxWebSocketFrameSize {
		t.Errorf("ResolveWSMaxFrameSize = %d, want default %d", got, MaxWebSocketFrameSize)
	}
	if got := ResolveWSDeflateEnabled(cfg.WebSocket); got != true {
		t.Errorf("ResolveWSDeflateEnabled = %v, want default true", got)
	}
	if got := ResolveGRPCMaxMessageSize(cfg.GRPC); got != MaxGRPCMessageSize {
		t.Errorf("ResolveGRPCMaxMessageSize = %d, want default %d", got, MaxGRPCMessageSize)
	}
	if got := ResolveSSEMaxEventSize(cfg.SSE); got != MaxSSEEventSize {
		t.Errorf("ResolveSSEMaxEventSize = %d, want default %d", got, MaxSSEEventSize)
	}
}

// TestProtocolLimits_JSONRoundTrip_Omitempty verifies that a ProxyConfig
// with no protocol-limit substructs marshals back to JSON without the
// new keys (omitempty). This is the backward-compatibility guarantee:
// existing serialized configs round-trip unchanged.
func TestProtocolLimits_JSONRoundTrip_Omitempty(t *testing.T) {
	cfg := ProxyConfig{ListenAddr: "127.0.0.1:8080"}
	out, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, key := range []string{`"web_socket"`, `"grpc"`, `"sse"`} {
		if strings.Contains(got, key) {
			t.Errorf("Marshal output unexpectedly contains %s: %s", key, got)
		}
	}

	// With substructs, the keys appear.
	cfg.WebSocket = &WebSocketLimits{MaxFrameSize: 1024}
	cfg.GRPC = &GRPCLimits{MaxMessageSize: 2048}
	cfg.SSE = &SSELimits{MaxEventSize: 4096}
	out, err = json.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	got = string(out)
	for _, key := range []string{`"web_socket"`, `"grpc"`, `"sse"`} {
		if !strings.Contains(got, key) {
			t.Errorf("Marshal output missing %s: %s", key, got)
		}
	}
}
