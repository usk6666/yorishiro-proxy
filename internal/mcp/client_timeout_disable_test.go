package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// USK-1185: request_timeout_ms: 0 disables the client request-head bound,
// and client_idle_timeout_ms (0 = disabled, 100-600000, default 120000)
// sets the HTTP/1.x keep-alive wait for the next request.

var clientIdleTimeoutValidation = []struct {
	name    string
	value   int
	wantErr bool
}{
	{name: "zero disables", value: 0, wantErr: false},
	{name: "valid min", value: 100, wantErr: false},
	{name: "valid max", value: 600000, wantErr: false},
	{name: "one", value: 1, wantErr: true},
	{name: "below min", value: 99, wantErr: true},
	{name: "negative", value: -1, wantErr: true},
	{name: "above max", value: 600001, wantErr: true},
}

func TestConfigure_ClientIdleTimeoutMs_Validation(t *testing.T) {
	for _, tt := range clientIdleTimeoutValidation {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			if err := manager.Start(context.Background(), "127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { manager.Stop(context.Background()) })

			setter := &mockRequestTimeoutSetter{}
			cs := setupConfigureTestSessionWithManager(t, manager, WithRequestTimeoutSetters(setter))
			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "configure",
				Arguments: configureMarshal(t, configureInput{
					Operation:           "merge",
					ClientIdleTimeoutMs: intPtr(tt.value),
				}),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for client_idle_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for client_idle_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
			if tt.wantErr {
				return
			}
			if tt.value == 0 {
				if !setter.ClientIdleTimeoutDisabled() {
					t.Error("client_idle_timeout_ms=0 did not disable the idle bound")
				}
			} else if got := setter.ClientIdleTimeout(); got != time.Duration(tt.value)*time.Millisecond {
				t.Errorf("ClientIdleTimeout = %v, want %dms", got, tt.value)
			}
		})
	}
}

func TestProxyStart_ClientIdleTimeoutMs_Validation(t *testing.T) {
	for _, tt := range clientIdleTimeoutValidation {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			t.Cleanup(func() { manager.Stop(context.Background()) })

			setter := &mockRequestTimeoutSetter{}
			cs := setupProxyStartTestSessionWithOptions(t, manager, nil, WithRequestTimeoutSetters(setter))
			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr":            "127.0.0.1:0",
				"client_idle_timeout_ms": tt.value,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for client_idle_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for client_idle_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
			if tt.wantErr {
				return
			}
			if tt.value == 0 {
				if !setter.ClientIdleTimeoutDisabled() {
					t.Error("client_idle_timeout_ms=0 did not disable the idle bound")
				}
			} else if got := setter.ClientIdleTimeout(); got != time.Duration(tt.value)*time.Millisecond {
				t.Errorf("ClientIdleTimeout = %v, want %dms", got, tt.value)
			}
		})
	}
}

func TestConfigure_RequestTimeoutMsZero_Disables(t *testing.T) {
	manager := newTestProxybuildManager(t)
	if err := manager.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockRequestTimeoutSetter{}
	setter.SetRequestTimeout(90 * time.Second)
	cs := setupConfigureTestSessionWithManager(t, manager, WithRequestTimeoutSetters(setter))
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:        "merge",
			RequestTimeoutMs: intPtr(0),
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("configure { request_timeout_ms: 0 } failed: %v", result.Content)
	}
	if !setter.RequestTimeoutDisabled() {
		t.Error("request_timeout_ms=0 did not disable the request-head bound")
	}
	var out configureResult
	unmarshalQueryResult(t, result, &out)
	if out.RequestTimeoutMs == nil || *out.RequestTimeoutMs != 0 {
		t.Errorf("configure result request_timeout_ms = %v, want 0", out.RequestTimeoutMs)
	}
}

func TestProxyStart_RequestTimeoutMsZero_Disables(t *testing.T) {
	manager := newTestProxybuildManager(t)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockRequestTimeoutSetter{}
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, WithRequestTimeoutSetters(setter))
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"request_timeout_ms": 0,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("proxy_start { request_timeout_ms: 0 } failed: %v", result.Content)
	}
	if !setter.RequestTimeoutDisabled() {
		t.Error("request_timeout_ms=0 did not disable the request-head bound")
	}
}

// Omitted request_timeout_ms / client_idle_timeout_ms leave the values a
// previous configure set — including the disabled state.
func TestProxyStart_OmittedClientTimeoutsKept(t *testing.T) {
	manager := newTestProxybuildManager(t)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	setter := &mockRequestTimeoutSetter{}
	setter.DisableRequestTimeout()
	setter.SetClientIdleTimeout(5 * time.Second)
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, WithRequestTimeoutSetters(setter))
	result, err := callProxyStart(t, cs, map[string]any{"listen_addr": "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("proxy_start failed: %v", result.Content)
	}
	if !setter.RequestTimeoutDisabled() {
		t.Errorf("proxy_start without request_timeout_ms re-enabled the bound (timeout=%v)", setter.RequestTimeout())
	}
	if setter.ClientIdleTimeoutDisabled() || setter.ClientIdleTimeout() != 5*time.Second {
		t.Errorf("proxy_start without client_idle_timeout_ms changed it: %v (disabled=%v), want 5s",
			setter.ClientIdleTimeout(), setter.ClientIdleTimeoutDisabled())
	}
}

func TestQuery_ReportsClientTimeouts(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*mockRequestTimeoutSetter)
		wantReq  int64
		wantIdle int64
	}{
		{name: "defaults", setup: func(*mockRequestTimeoutSetter) {}, wantReq: 60000, wantIdle: 120000},
		{name: "set", setup: func(m *mockRequestTimeoutSetter) {
			m.SetRequestTimeout(90 * time.Second)
			m.SetClientIdleTimeout(5 * time.Second)
		}, wantReq: 90000, wantIdle: 5000},
		{name: "disabled", setup: func(m *mockRequestTimeoutSetter) {
			m.DisableRequestTimeout()
			m.DisableClientIdleTimeout()
		}, wantReq: 0, wantIdle: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setter := &mockRequestTimeoutSetter{}
			tt.setup(setter)
			cs := setupQueryStatusTestSession(t, newTestStore(t), newTestProxybuildManager(t), WithRequestTimeoutSetters(setter))

			res := callQuery(t, cs, queryInput{Resource: "status"})
			if res.IsError {
				t.Fatalf("query status: %v", res.Content)
			}
			var status queryStatusResult
			unmarshalQueryResult(t, res, &status)
			if status.RequestTimeoutMs != tt.wantReq || status.ClientIdleTimeoutMs != tt.wantIdle {
				t.Errorf("status request_timeout_ms=%d client_idle_timeout_ms=%d, want %d / %d",
					status.RequestTimeoutMs, status.ClientIdleTimeoutMs, tt.wantReq, tt.wantIdle)
			}

			res = callQuery(t, cs, queryInput{Resource: "config"})
			if res.IsError {
				t.Fatalf("query config: %v", res.Content)
			}
			var cfg queryConfigResult
			unmarshalQueryResult(t, res, &cfg)
			if cfg.RequestTimeoutMs != tt.wantReq || cfg.ClientIdleTimeoutMs != tt.wantIdle {
				t.Errorf("config request_timeout_ms=%d client_idle_timeout_ms=%d, want %d / %d",
					cfg.RequestTimeoutMs, cfg.ClientIdleTimeoutMs, tt.wantReq, tt.wantIdle)
			}
		})
	}
}
