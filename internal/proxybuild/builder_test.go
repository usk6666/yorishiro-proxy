package proxybuild

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// silentLogger returns a logger that drops everything; tests only assert
// builder behavior, not log output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// noopFlowStore is a flow.Writer test double that records nothing.
type noopFlowStore struct{}

func (noopFlowStore) SaveStream(_ context.Context, _ *flow.Stream) error                  { return nil }
func (noopFlowStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error { return nil }
func (noopFlowStore) SaveFlow(_ context.Context, _ *flow.Flow) error                      { return nil }

// newTestDeps returns a Deps populated with the minimum required fields.
// Optional engines are left nil so the canonical Pipeline degrades to
// no-op Steps.
func newTestDeps(t *testing.T) Deps {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("cert.CA.Generate: %v", err)
	}
	return Deps{
		Logger:       silentLogger(),
		ListenerName: "test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    noopFlowStore{},
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	}
}

// TestBuildLiveStack_Success verifies the happy path: required fields
// supplied, all Stack fields populated, listener accessible without
// engine when PluginV2Engine is nil.
func TestBuildLiveStack_Success(t *testing.T) {
	deps := newTestDeps(t)

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack == nil {
		t.Fatal("Stack is nil")
	}
	if stack.Listener == nil {
		t.Error("Stack.Listener is nil")
	}
	if stack.Pipeline == nil {
		t.Error("Stack.Pipeline is nil")
	}
	if stack.WireEncoderRegistry == nil {
		t.Error("Stack.WireEncoderRegistry is nil")
	}
	if stack.BuildConfig == nil {
		t.Error("Stack.BuildConfig is nil")
	}
	if got := stack.Listener.Name(); got != "test" {
		t.Errorf("Listener.Name = %q, want %q", got, "test")
	}
	if got := stack.Listener.PluginV2Engine(); got != nil {
		t.Errorf("Listener.PluginV2Engine = %v, want nil", got)
	}
}

// TestBuildLiveStack_DefaultName ensures an empty ListenerName resolves
// to DefaultListenerName.
func TestBuildLiveStack_DefaultName(t *testing.T) {
	deps := newTestDeps(t)
	deps.ListenerName = ""

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if got := stack.Listener.Name(); got != DefaultListenerName {
		t.Errorf("Listener.Name = %q, want %q", got, DefaultListenerName)
	}
}

// TestBuildLiveStack_PluginV2EngineReachable ensures
// Stack.Listener.PluginV2Engine() returns the engine threaded through Deps,
// satisfying the USK-688 acceptance criterion.
func TestBuildLiveStack_PluginV2EngineReachable(t *testing.T) {
	deps := newTestDeps(t)
	engine := pluginv2.NewEngine(silentLogger())
	deps.PluginV2Engine = engine

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if got := stack.Listener.PluginV2Engine(); got != engine {
		t.Errorf("Listener.PluginV2Engine returned %v, want %v", got, engine)
	}
	if got := stack.PluginV2Engine; got != engine {
		t.Errorf("Stack.PluginV2Engine = %v, want %v", got, engine)
	}
	// Verify the engine was also threaded into BuildConfig so the
	// existing tls.on_handshake hook fires.
	if got := stack.BuildConfig.PluginV2Engine; got != engine {
		t.Errorf("BuildConfig.PluginV2Engine = %v, want %v", got, engine)
	}
}

// TestBuildLiveStack_DefaultEncodersRegistered verifies the default
// WireEncoderRegistry registers the four non-conflicting protocol
// encoders (ws / grpc / grpc-web / sse) plus a route-appropriate HTTP
// encoder. USK-690 finalised the HTTP encoder strategy: the non-h2 (h1)
// registry holds http1.EncodeWireBytes and the h2 registry holds
// httpaggregator.EncodeWireBytes. Both encoders register against
// envelope.ProtocolHTTP and are mutually exclusive in a single registry,
// hence the dual-registry split.
func TestBuildLiveStack_DefaultEncodersRegistered(t *testing.T) {
	deps := newTestDeps(t)
	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	shared := []envelope.Protocol{
		envelope.ProtocolWebSocket,
		envelope.ProtocolGRPC,
		envelope.ProtocolGRPCWeb,
		envelope.ProtocolSSE,
	}
	for _, p := range shared {
		if _, ok := stack.WireEncoderRegistry.Lookup(p); !ok {
			t.Errorf("h1 registry missing encoder for %s", p)
		}
		if _, ok := stack.WireEncoderRegistryH2.Lookup(p); !ok {
			t.Errorf("h2 registry missing encoder for %s", p)
		}
	}
	if _, ok := stack.WireEncoderRegistry.Lookup(envelope.ProtocolHTTP); !ok {
		t.Error("h1 registry must register HTTP encoder (http1.EncodeWireBytes)")
	}
	if _, ok := stack.WireEncoderRegistryH2.Lookup(envelope.ProtocolHTTP); !ok {
		t.Error("h2 registry must register HTTP encoder (httpaggregator.EncodeWireBytes)")
	}
}

// TestBuildLiveStack_CustomRegistryHonored ensures a caller-supplied
// registry is used verbatim instead of the default.
func TestBuildLiveStack_CustomRegistryHonored(t *testing.T) {
	deps := newTestDeps(t)
	custom := pipeline.NewWireEncoderRegistry()
	deps.WireEncoderRegistry = custom

	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack.WireEncoderRegistry != custom {
		t.Error("Stack.WireEncoderRegistry should match the caller-supplied registry pointer")
	}
}

// TestBuildLiveStack_MissingRequired enumerates each required field and
// confirms BuildLiveStack rejects with a helpful error.
func TestBuildLiveStack_MissingRequired(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Deps)
		want string
	}{
		{
			name: "logger",
			mut:  func(d *Deps) { d.Logger = nil },
			want: "Logger",
		},
		{
			name: "listen_addr",
			mut:  func(d *Deps) { d.ListenAddr = "" },
			want: "ListenAddr",
		},
		{
			name: "build_config",
			mut:  func(d *Deps) { d.BuildConfig = nil },
			want: "BuildConfig",
		},
		{
			name: "build_config_proxy_config",
			mut:  func(d *Deps) { d.BuildConfig.ProxyConfig = nil },
			want: "ProxyConfig",
		},
		{
			name: "build_config_issuer",
			mut:  func(d *Deps) { d.BuildConfig.Issuer = nil },
			want: "Issuer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTestDeps(t)
			tc.mut(&deps)
			_, err := BuildLiveStack(context.Background(), deps)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err.Error(), tc.want)
			}
		})
	}
}

var _ = errors.Is // sentinel for future errors.Is assertions on package errors
