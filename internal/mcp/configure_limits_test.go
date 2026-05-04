package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupConfigureTestSessionWithManager creates a connected MCP client flow
// with a running proxy manager for testing configure tool limits/timeouts.
func setupConfigureTestSessionWithManager(t *testing.T, manager proxyManager, extraOpts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	pl := proxy.NewPassthroughList()

	opts := []ServerOption{
		WithPassthroughList(pl),
	}
	opts = append(opts, extraOpts...)

	s := newServer(ctx, nil, nil, manager, opts...)
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

func TestConfigure_MergeMaxConnections(t *testing.T) {
	manager := newTestProxybuildManager(t)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cs := setupConfigureTestSessionWithManager(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "merge",
			MaxConnections: intPtr(2048),
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.Status != "configured" {
		t.Errorf("status = %q, want %q", out.Status, "configured")
	}
	if out.MaxConnections == nil || *out.MaxConnections != 2048 {
		t.Errorf("max_connections = %v, want 2048", out.MaxConnections)
	}

	// Verify the manager was updated.
	if got := manager.MaxConnections(); got != 2048 {
		t.Errorf("manager.MaxConnections() = %d, want 2048", got)
	}
}

func TestConfigure_MergePeekTimeoutMs(t *testing.T) {
	manager := newTestProxybuildManager(t)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cs := setupConfigureTestSessionWithManager(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:     "merge",
			PeekTimeoutMs: intPtr(15000),
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.PeekTimeoutMs == nil || *out.PeekTimeoutMs != 15000 {
		t.Errorf("peek_timeout_ms = %v, want 15000", out.PeekTimeoutMs)
	}

	// Verify the manager was updated.
	if got := manager.PeekTimeout(); got != 15*time.Second {
		t.Errorf("manager.PeekTimeout() = %v, want 15s", got)
	}
}

func TestConfigure_MergeRequestTimeoutMs(t *testing.T) {
	manager := newTestProxybuildManager(t)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	setter := &mockRequestTimeoutSetter{}
	cs := setupConfigureTestSessionWithManager(t, manager, WithRequestTimeoutSetters(setter))

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:        "merge",
			RequestTimeoutMs: intPtr(90000),
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.RequestTimeoutMs == nil || *out.RequestTimeoutMs != 90000 {
		t.Errorf("request_timeout_ms = %v, want 90000", out.RequestTimeoutMs)
	}

	// Verify the setter was updated.
	if got := setter.RequestTimeout(); got != 90*time.Second {
		t.Errorf("setter.RequestTimeout() = %v, want 90s", got)
	}
}

func TestConfigure_MaxConnections_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "valid min", value: 1, wantErr: false},
		{name: "valid max", value: 100000, wantErr: false},
		{name: "below min", value: 0, wantErr: true},
		{name: "above max", value: 100001, wantErr: true},
		{name: "negative", value: -1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			ctx := context.Background()
			if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { manager.Stop(context.Background()) })

			cs := setupConfigureTestSessionWithManager(t, manager)

			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "configure",
				Arguments: configureMarshal(t, configureInput{
					Operation:      "merge",
					MaxConnections: intPtr(tt.value),
				}),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for max_connections=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for max_connections=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestConfigure_PeekTimeoutMs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "valid min", value: 100, wantErr: false},
		{name: "valid max", value: 600000, wantErr: false},
		{name: "below min", value: 99, wantErr: true},
		{name: "above max", value: 600001, wantErr: true},
		{name: "zero", value: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			ctx := context.Background()
			if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { manager.Stop(context.Background()) })

			cs := setupConfigureTestSessionWithManager(t, manager)

			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "configure",
				Arguments: configureMarshal(t, configureInput{
					Operation:     "merge",
					PeekTimeoutMs: intPtr(tt.value),
				}),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for peek_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for peek_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestConfigure_RequestTimeoutMs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "valid min", value: 100, wantErr: false},
		{name: "valid max", value: 600000, wantErr: false},
		{name: "below min", value: 99, wantErr: true},
		{name: "above max", value: 600001, wantErr: true},
		{name: "zero", value: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			ctx := context.Background()
			if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { manager.Stop(context.Background()) })

			setter := &mockRequestTimeoutSetter{}
			cs := setupConfigureTestSessionWithManager(t, manager, WithRequestTimeoutSetters(setter))

			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "configure",
				Arguments: configureMarshal(t, configureInput{
					Operation:        "merge",
					RequestTimeoutMs: intPtr(tt.value),
				}),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for request_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for request_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestConfigure_NilManager_MaxConnections(t *testing.T) {
	// Configure with max_connections when manager is nil should error.
	cs := setupConfigureTestSessionWithManager(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "merge",
			MaxConnections: intPtr(500),
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil manager, got success")
	}
}

func TestConfigure_ReplaceLimits(t *testing.T) {
	// Verify that replace operation also applies limits/timeouts.
	manager := newTestProxybuildManager(t)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	setter := &mockRequestTimeoutSetter{}
	cs := setupConfigureTestSessionWithManager(t, manager, WithRequestTimeoutSetters(setter))

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:        "replace",
			MaxConnections:   intPtr(4096),
			PeekTimeoutMs:    intPtr(20000),
			RequestTimeoutMs: intPtr(120000),
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.MaxConnections == nil || *out.MaxConnections != 4096 {
		t.Errorf("max_connections = %v, want 4096", out.MaxConnections)
	}
	if out.PeekTimeoutMs == nil || *out.PeekTimeoutMs != 20000 {
		t.Errorf("peek_timeout_ms = %v, want 20000", out.PeekTimeoutMs)
	}
	if out.RequestTimeoutMs == nil || *out.RequestTimeoutMs != 120000 {
		t.Errorf("request_timeout_ms = %v, want 120000", out.RequestTimeoutMs)
	}

	if got := manager.MaxConnections(); got != 4096 {
		t.Errorf("manager.MaxConnections() = %d, want 4096", got)
	}
	if got := manager.PeekTimeout(); got != 20*time.Second {
		t.Errorf("manager.PeekTimeout() = %v, want 20s", got)
	}
	if got := setter.RequestTimeout(); got != 120*time.Second {
		t.Errorf("setter.RequestTimeout() = %v, want 120s", got)
	}
}

func TestConfigure_OmittedLimits_NoChange(t *testing.T) {
	// When limits are omitted, they should not appear in the result.
	manager := newTestProxybuildManager(t)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cs := setupConfigureTestSessionWithManager(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.MaxConnections != nil {
		t.Errorf("max_connections should be nil when not specified, got %v", out.MaxConnections)
	}
	if out.PeekTimeoutMs != nil {
		t.Errorf("peek_timeout_ms should be nil when not specified, got %v", out.PeekTimeoutMs)
	}
	if out.RequestTimeoutMs != nil {
		t.Errorf("request_timeout_ms should be nil when not specified, got %v", out.RequestTimeoutMs)
	}
}

// --- Query status tests for limits/timeouts ---

func TestQuery_Status_ShowsLimitsAndTimeouts(t *testing.T) {
	store := newTestStore(t)
	manager := newTestProxybuildManager(t)

	// Set custom values before starting.
	manager.SetMaxConnections(512)
	manager.SetPeekTimeout(10 * time.Second)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	setter := &mockRequestTimeoutSetter{}
	setter.SetRequestTimeout(90 * time.Second)

	cs := setupQueryStatusTestSession(t, store, manager, WithRequestTimeoutSetters(setter))

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	if !out.Running {
		t.Error("running = false, want true")
	}
	if out.MaxConnections != 512 {
		t.Errorf("max_connections = %d, want 512", out.MaxConnections)
	}
	if out.PeekTimeoutMs != 10000 {
		t.Errorf("peek_timeout_ms = %d, want 10000", out.PeekTimeoutMs)
	}
	if out.RequestTimeoutMs != 90000 {
		t.Errorf("request_timeout_ms = %d, want 90000", out.RequestTimeoutMs)
	}
}

func TestQuery_Status_DefaultLimitsAndTimeouts(t *testing.T) {
	store := newTestStore(t)
	manager := newTestProxybuildManager(t)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cs := setupQueryStatusTestSession(t, store, manager)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	// Default values.
	if out.MaxConnections != 128 {
		t.Errorf("max_connections = %d, want 128 (default)", out.MaxConnections)
	}
	if out.PeekTimeoutMs != 30000 {
		t.Errorf("peek_timeout_ms = %d, want 30000 (default)", out.PeekTimeoutMs)
	}
	if out.RequestTimeoutMs != 60000 {
		t.Errorf("request_timeout_ms = %d, want 60000 (default)", out.RequestTimeoutMs)
	}
}

func TestQuery_Status_NoManager_ShowsDefaults(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	if out.Running {
		t.Error("running = true, want false")
	}
	// When no manager is set, max_connections and peek_timeout_ms should be 0 (unset).
	if out.MaxConnections != 0 {
		t.Errorf("max_connections = %d, want 0 (no manager)", out.MaxConnections)
	}
	if out.PeekTimeoutMs != 0 {
		t.Errorf("peek_timeout_ms = %d, want 0 (no manager)", out.PeekTimeoutMs)
	}
	// Default request timeout should still be reported.
	if out.RequestTimeoutMs != 60000 {
		t.Errorf("request_timeout_ms = %d, want 60000 (default)", out.RequestTimeoutMs)
	}
}

// setupQueryStatusTestSession creates an MCP client flow with a manager for query status tests.
func setupQueryStatusTestSession(t *testing.T, store flow.Store, manager proxyManager, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	allOpts := make([]ServerOption, 0, len(opts))
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

// --- helper ---

// intPtr returns a pointer to the given int.
func intPtr(n int) *int {
	return &n
}

// mockRequestTimeoutSetter implements the requestTimeoutSetter interface for testing.
type mockRequestTimeoutSetter struct {
	timeout time.Duration
}

func (m *mockRequestTimeoutSetter) SetRequestTimeout(d time.Duration) {
	m.timeout = d
}

func (m *mockRequestTimeoutSetter) RequestTimeout() time.Duration {
	if m.timeout > 0 {
		return m.timeout
	}
	return 60 * time.Second // default
}
