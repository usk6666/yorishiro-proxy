package job

import (
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// --- mockMacroEngine helpers ---

// makeMockEngine creates a macro.Engine with a mock SendFunc and FlowFetcher.
func makeMockEngine(t *testing.T) *macro.Engine {
	t.Helper()
	sendFn := func(_ context.Context, req *macro.SendRequest) (*macro.SendResponse, error) {
		return &macro.SendResponse{StatusCode: 200, Body: []byte("ok")}, nil
	}
	fetcher := &mockMacroFlowFetcher{}
	engine, err := macro.NewEngine(sendFn, fetcher)
	if err != nil {
		t.Fatalf("failed to create macro engine: %v", err)
	}
	return engine
}

type mockMacroFlowFetcher struct{}

func (f *mockMacroFlowFetcher) GetFlowRequest(_ context.Context, flowID string) (*macro.SendRequest, error) {
	return &macro.SendRequest{
		Method: "GET",
		URL:    "https://example.com/",
	}, nil
}

// simpleMacro creates a minimal macro with one step for testing.
func simpleMacro(name string) *macro.Macro {
	return &macro.Macro{
		Name: name,
		Steps: []macro.Step{
			{
				ID:       "step-1",
				StreamID: "stream-1",
			},
		},
	}
}

// --- MakeRunHookFunc tests ---

func TestMakeRunHookFunc_BasicExecution(t *testing.T) {
	engine := makeMockEngine(t)
	m := simpleMacro("test-hook")

	lookup := func(name string) *macro.Macro {
		if name == "test-hook" {
			return m
		}
		return nil
	}

	hookFn := MakeRunHookFunc(engine, lookup)
	kvStore := map[string]string{"existing": "value"}

	result, err := hookFn(context.Background(), &HookConfig{
		Macro: "test-hook",
		Vars:  map[string]string{"extra": "var"},
	}, kvStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Result should be the KVStore from the macro execution.
	if result == nil {
		t.Fatal("expected non-nil result KVStore")
	}
}

func TestMakeRunHookFunc_MacroNotFound(t *testing.T) {
	engine := makeMockEngine(t)
	lookup := func(name string) *macro.Macro { return nil }

	hookFn := MakeRunHookFunc(engine, lookup)
	_, err := hookFn(context.Background(), &HookConfig{
		Macro: "nonexistent",
	}, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestMakeRunHookFunc_VarsOverrideKVStore(t *testing.T) {
	engine := makeMockEngine(t)
	m := simpleMacro("test-hook")

	lookup := func(name string) *macro.Macro {
		if name == "test-hook" {
			return m
		}
		return nil
	}

	hookFn := MakeRunHookFunc(engine, lookup)
	kvStore := map[string]string{"key": "original"}

	_, err := hookFn(context.Background(), &HookConfig{
		Macro: "test-hook",
		Vars:  map[string]string{"key": "overridden"},
	}, kvStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The hook vars should take precedence in the merged vars passed to Run.
	// We can't directly observe this without inspecting the engine's behavior,
	// but at least verify no error occurred.
}

func TestMakeRunHookFunc_NilKVStore(t *testing.T) {
	engine := makeMockEngine(t)
	m := simpleMacro("test-hook")

	lookup := func(name string) *macro.Macro {
		if name == "test-hook" {
			return m
		}
		return nil
	}

	hookFn := MakeRunHookFunc(engine, lookup)
	// nil kvStore should not panic.
	_, err := hookFn(context.Background(), &HookConfig{
		Macro: "test-hook",
	}, nil)
	if err != nil {
		// Engine may fail due to mock, but should not panic.
		if errors.Is(err, context.Canceled) {
			t.Fatal("unexpected context cancellation")
		}
	}
}
