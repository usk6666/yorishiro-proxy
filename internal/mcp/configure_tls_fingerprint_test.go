package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// mockTLSFingerprintSetter implements tlsFingerprintSetter for testing.
type mockTLSFingerprintSetter struct {
	profile   string
	transport transport.TLSTransport
}

func (m *mockTLSFingerprintSetter) SetTLSFingerprint(profile string) {
	m.profile = profile
}

func (m *mockTLSFingerprintSetter) TLSFingerprint() string {
	return m.profile
}

func (m *mockTLSFingerprintSetter) SetTLSTransport(t transport.TLSTransport) {
	m.transport = t
}

// setupTLSFingerprintTestSession creates an MCP client session with TLS fingerprint setter.
func setupTLSFingerprintTestSession(t *testing.T, store flow.Store, manager proxyManager, setter *mockTLSFingerprintSetter, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	allOpts := []ServerOption{
		WithTLSFingerprintSetter(setter),
	}
	allOpts = append(allOpts, opts...)

	s := newServer(ctx, ca, store, manager, allOpts...)
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

func TestConfigure_TLSFingerprint_CaseInsensitive(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"Chrome", "chrome"},
		{"FIREFOX", "firefox"},
		{"Safari", "safari"},
		{"EDGE", "edge"},
		{"Random", "random"},
		{"NONE", "none"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			setter := &mockTLSFingerprintSetter{}
			cs := setupTLSFingerprintTestSession(t, nil, nil, setter)

			input := configureInput{
				TLSFingerprint: &tc.input,
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
				t.Fatalf("expected success for %q, got error: %v", tc.input, result.Content)
			}

			if setter.profile != tc.expected {
				t.Errorf("setter.profile = %q, want %q", setter.profile, tc.expected)
			}
		})
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
	manager := newTestProxybuildManager(t)

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
	manager := newTestProxybuildManager(t)

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
	manager := newTestProxybuildManager(t)

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
	manager := newTestProxybuildManager(t)

	setter := &mockTLSFingerprintSetter{}
	ctx := context.Background()

	ca := newTestCA(t)
	proxyCfg := &config.ProxyConfig{
		TLSFingerprint: "safari",
	}
	s := newServer(ctx, ca, nil, manager,
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

func TestConfigure_TLSFingerprint_TransportRebuilt(t *testing.T) {
	tests := []struct {
		profile       string
		wantUTLS      bool // true → UTLSTransport, false → StandardTransport
		wantProfileBP transport.BrowserProfile
	}{
		{"chrome", true, transport.ProfileChrome},
		{"firefox", true, transport.ProfileFirefox},
		{"safari", true, transport.ProfileSafari},
		{"edge", true, transport.ProfileEdge},
		{"random", true, transport.ProfileRandom},
		{"none", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			setter := &mockTLSFingerprintSetter{}
			// Provide an initial transport so InsecureSkipVerify can be read.
			initialTransport := &transport.UTLSTransport{
				Profile:            transport.ProfileChrome,
				InsecureSkipVerify: true,
			}
			cs := setupTLSFingerprintTestSession(t, nil, nil, setter,
				WithTLSTransport(initialTransport),
			)

			input := configureInput{TLSFingerprint: &tt.profile}
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var args map[string]json.RawMessage
			if err := json.Unmarshal(data, &args); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
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

			// Verify transport was set on the setter.
			if setter.transport == nil {
				t.Fatal("transport was not set on setter")
			}

			if tt.wantUTLS {
				ut, ok := setter.transport.(*transport.UTLSTransport)
				if !ok {
					t.Fatalf("transport type = %T, want *transport.UTLSTransport", setter.transport)
				}
				if ut.Profile != tt.wantProfileBP {
					t.Errorf("transport profile = %v, want %v", ut.Profile, tt.wantProfileBP)
				}
				if !ut.InsecureSkipVerify {
					t.Error("InsecureSkipVerify not inherited from initial transport")
				}
			} else {
				st, ok := setter.transport.(*transport.StandardTransport)
				if !ok {
					t.Fatalf("transport type = %T, want *transport.StandardTransport", setter.transport)
				}
				if !st.InsecureSkipVerify {
					t.Error("InsecureSkipVerify not inherited from initial transport")
				}
			}
		})
	}
}

func TestProxyStart_TLSFingerprint_TransportRebuilt(t *testing.T) {
	manager := newTestProxybuildManager(t)

	setter := &mockTLSFingerprintSetter{}
	initialTransport := &transport.UTLSTransport{
		Profile:            transport.ProfileChrome,
		InsecureSkipVerify: true,
	}
	cs := setupTLSFingerprintTestSession(t, nil, manager, setter,
		WithTLSTransport(initialTransport),
	)

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

	if setter.transport == nil {
		t.Fatal("transport was not set on setter")
	}
	ut, ok := setter.transport.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("transport type = %T, want *transport.UTLSTransport", setter.transport)
	}
	if ut.Profile != transport.ProfileFirefox {
		t.Errorf("transport profile = %v, want ProfileFirefox", ut.Profile)
	}
}

func TestProxyStart_TLSFingerprint_NoneUsesStandardTransport(t *testing.T) {
	manager := newTestProxybuildManager(t)

	setter := &mockTLSFingerprintSetter{}
	cs := setupTLSFingerprintTestSession(t, nil, manager, setter,
		WithTLSTransport(&transport.StandardTransport{}),
	)

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

	if setter.transport == nil {
		t.Fatal("transport was not set on setter")
	}
	if _, ok := setter.transport.(*transport.StandardTransport); !ok {
		t.Fatalf("transport type = %T, want *transport.StandardTransport", setter.transport)
	}
}

func TestResetSettingsToDefaults_RebuildsTLSTransport(t *testing.T) {
	setter := &mockTLSFingerprintSetter{profile: "firefox"}
	initialTransport := &transport.UTLSTransport{
		Profile:            transport.ProfileFirefox,
		InsecureSkipVerify: true,
	}

	ctx := context.Background()
	ca := newTestCA(t)
	s := newServer(ctx, ca, nil, nil,
		WithTLSFingerprintSetter(setter),
		WithTLSTransport(initialTransport),
	)

	// Reset to defaults.
	s.resetSettingsToDefaults()

	// Profile should be reset to "chrome".
	if setter.profile != "chrome" {
		t.Errorf("setter.profile = %q, want chrome", setter.profile)
	}

	// Transport should be rebuilt as UTLSTransport with Chrome profile.
	if setter.transport == nil {
		t.Fatal("transport was not set after reset")
	}
	ut, ok := setter.transport.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("transport type = %T, want *transport.UTLSTransport", setter.transport)
	}
	if ut.Profile != transport.ProfileChrome {
		t.Errorf("transport profile = %v, want ProfileChrome", ut.Profile)
	}
	if !ut.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be inherited from initial transport")
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
