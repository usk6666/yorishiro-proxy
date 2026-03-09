package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// mockTLSFingerprintSetter implements tlsFingerprintSetter for testing.
type mockTLSFingerprintSetter struct {
	profile string
}

func (m *mockTLSFingerprintSetter) SetTLSFingerprint(profile string) {
	m.profile = profile
}

func (m *mockTLSFingerprintSetter) TLSFingerprint() string {
	return m.profile
}

// setupTLSFingerprintTestSession creates an MCP client session with TLS fingerprint setter.
func setupTLSFingerprintTestSession(t *testing.T, store flow.Store, manager *proxy.Manager, setter *mockTLSFingerprintSetter, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	allOpts := []ServerOption{
		WithTLSFingerprintSetter(setter),
	}
	allOpts = append(allOpts, opts...)

	s := NewServer(ctx, ca, store, manager, allOpts...)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

func TestConfigure_TLSFingerprint_ValidProfiles(t *testing.T) {
	profiles := []string{"chrome", "firefox", "safari", "edge", "random", "none"}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			setter := &mockTLSFingerprintSetter{}
			cs := setupTLSFingerprintTestSession(t, nil, nil, setter)

			input := configureInput{
				TLSFingerprint: &profile,
			}
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var args map[string]json.RawMessage
			if err := json.Unmarshal(data, &args); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name:      "configure",
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out configureResult
			configureUnmarshalResult(t, result, &out)

			if out.TLSFingerprint == nil {
				t.Fatal("tls_fingerprint is nil in result")
			}
			if *out.TLSFingerprint != profile {
				t.Errorf("tls_fingerprint = %q, want %q", *out.TLSFingerprint, profile)
			}
			if setter.profile != profile {
				t.Errorf("setter.profile = %q, want %q", setter.profile, profile)
			}
		})
	}
}

func TestConfigure_TLSFingerprint_InvalidProfile(t *testing.T) {
	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, nil, nil, setter)

	invalid := "invalid-browser"
	input := configureInput{
		TLSFingerprint: &invalid,
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid profile, got success")
	}
}

func TestConfigure_TLSFingerprint_OmittedDoesNotChange(t *testing.T) {
	setter := &mockTLSFingerprintSetter{profile: "firefox"}
	cs := setupTLSFingerprintTestSession(t, nil, nil, setter)

	// Configure without tls_fingerprint (omitted).
	input := configureInput{}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.TLSFingerprint != nil {
		t.Errorf("tls_fingerprint should be nil when omitted, got %q", *out.TLSFingerprint)
	}
	if setter.profile != "firefox" {
		t.Errorf("setter.profile changed to %q, want unchanged firefox", setter.profile)
	}
}

func TestProxyStart_TLSFingerprint_ValidProfile(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, nil, manager, setter)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "firefox",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if setter.profile != "firefox" {
		t.Errorf("setter.profile = %q, want firefox", setter.profile)
	}
}

func TestProxyStart_TLSFingerprint_InvalidProfile(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, nil, manager, setter)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "netscape",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid profile, got success")
	}
}

func TestProxyStart_TLSFingerprint_None(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, nil, manager, setter)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "none",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if setter.profile != "none" {
		t.Errorf("setter.profile = %q, want none", setter.profile)
	}
}

func TestProxyStart_TLSFingerprint_ConfigDefault(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockTLSFingerprintSetter{}
	ctx := context.Background()

	ca := newTestCA(t)
	proxyCfg := &config.ProxyConfig{
		TLSFingerprint: "safari",
	}
	s := NewServer(ctx, ca, nil, manager,
		WithTLSFingerprintSetter(setter),
		WithProxyDefaults(proxyCfg),
	)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// proxy_start without explicit tls_fingerprint should inherit from config default.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if setter.profile != "safari" {
		t.Errorf("setter.profile = %q, want safari (config default)", setter.profile)
	}
}

func TestQuery_Status_TLSFingerprint_Default(t *testing.T) {
	store := newTestStore(t)
	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, store, nil, setter)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	// Default is "chrome" when no profile is set.
	if out.TLSFingerprint != "chrome" {
		t.Errorf("tls_fingerprint = %q, want chrome (default)", out.TLSFingerprint)
	}
}

func TestQuery_Status_TLSFingerprint_AfterSet(t *testing.T) {
	store := newTestStore(t)
	setter := &mockTLSFingerprintSetter{profile: "edge"}
	cs := setupTLSFingerprintTestSession(t, store, nil, setter)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	if out.TLSFingerprint != "edge" {
		t.Errorf("tls_fingerprint = %q, want edge", out.TLSFingerprint)
	}
}

func TestValidTLSFingerprints(t *testing.T) {
	valid := []string{"chrome", "firefox", "safari", "edge", "random", "none"}
	for _, name := range valid {
		if !validTLSFingerprints[name] {
			t.Errorf("%q should be valid", name)
		}
	}

	invalid := []string{"", "Chrome", "CHROME", "opera", "ie", "netscape"}
	for _, name := range invalid {
		if validTLSFingerprints[name] {
			t.Errorf("%q should be invalid", name)
		}
	}
}
