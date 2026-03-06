package plugin

import (
	"context"
	"errors"
	"testing"
)

func TestRegistry_Register_And_Dispatch(t *testing.T) {
	r := NewRegistry()

	callCount := 0
	handler := func(ctx context.Context, data map[string]any) (*HookResult, error) {
		callCount++
		data["modified"] = true
		return &HookResult{Action: ActionContinue, Data: data}, nil
	}

	r.Register("test-plugin", HookOnReceiveFromClient, handler, OnErrorSkip)

	if !r.HasHandlers(HookOnReceiveFromClient) {
		t.Error("expected HasHandlers to return true after registration")
	}
	if r.HasHandlers(HookOnConnect) {
		t.Error("expected HasHandlers to return false for unregistered hook")
	}

	data := map[string]any{"key": "value"}
	result, err := r.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil {
		t.Fatal("Dispatch() returned nil result")
	}
	if result.Action != ActionContinue {
		t.Errorf("Dispatch() action = %v, want CONTINUE", result.Action)
	}
	if callCount != 1 {
		t.Errorf("handler called %d times, want 1", callCount)
	}
	if data["modified"] != true {
		t.Error("expected data to be modified by handler")
	}
}

func TestRegistry_Dispatch_NoHandlers(t *testing.T) {
	r := NewRegistry()

	result, err := r.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result != nil {
		t.Errorf("Dispatch() = %v, want nil for no handlers", result)
	}
}

func TestRegistry_Dispatch_MultipleHandlers_Order(t *testing.T) {
	r := NewRegistry()

	var order []string
	makeHandler := func(name string) HookHandler {
		return func(ctx context.Context, data map[string]any) (*HookResult, error) {
			order = append(order, name)
			return &HookResult{Action: ActionContinue}, nil
		}
	}

	r.Register("plugin-a", HookOnConnect, makeHandler("a"), OnErrorSkip)
	r.Register("plugin-b", HookOnConnect, makeHandler("b"), OnErrorSkip)
	r.Register("plugin-c", HookOnConnect, makeHandler("c"), OnErrorSkip)

	_, err := r.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if len(order) != 3 || order[0] != "a" || order[1] != "b" || order[2] != "c" {
		t.Errorf("handlers called in order %v, want [a b c]", order)
	}
}

func TestRegistry_Dispatch_Drop_StopsChain(t *testing.T) {
	r := NewRegistry()

	var order []string
	r.Register("plugin-a", HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		order = append(order, "a")
		return &HookResult{Action: ActionDrop}, nil
	}, OnErrorSkip)
	r.Register("plugin-b", HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		order = append(order, "b")
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	result, err := r.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Action != ActionDrop {
		t.Errorf("Dispatch() action = %v, want DROP", result.Action)
	}
	if len(order) != 1 {
		t.Errorf("expected chain to stop after DROP, but %d handlers called", len(order))
	}
}

func TestRegistry_Dispatch_Respond_StopsChain(t *testing.T) {
	r := NewRegistry()

	respData := map[string]any{"status": int64(403)}
	r.Register("plugin-a", HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		return &HookResult{Action: ActionRespond, ResponseData: respData}, nil
	}, OnErrorSkip)
	r.Register("plugin-b", HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		t.Error("second handler should not be called after RESPOND")
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	result, err := r.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Action != ActionRespond {
		t.Errorf("Dispatch() action = %v, want RESPOND", result.Action)
	}
}

func TestRegistry_Dispatch_Error_Skip(t *testing.T) {
	r := NewRegistry()

	callCount := 0
	r.Register("bad-plugin", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		return nil, errors.New("plugin error")
	}, OnErrorSkip)
	r.Register("good-plugin", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		callCount++
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	result, err := r.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() should not return error with skip, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("good-plugin called %d times, want 1", callCount)
	}
	if result.Action != ActionContinue {
		t.Errorf("Dispatch() action = %v, want CONTINUE", result.Action)
	}
}

func TestRegistry_Dispatch_Error_Abort(t *testing.T) {
	r := NewRegistry()

	r.Register("bad-plugin", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		return nil, errors.New("plugin error")
	}, OnErrorAbort)
	r.Register("good-plugin", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		t.Error("second handler should not be called after abort")
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	_, err := r.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err == nil {
		t.Fatal("Dispatch() should return error with abort")
	}

	var de *DispatchError
	if !errors.As(err, &de) {
		t.Fatalf("expected DispatchError, got %T", err)
	}
	if de.PluginName != "bad-plugin" {
		t.Errorf("DispatchError.PluginName = %q, want %q", de.PluginName, "bad-plugin")
	}
	if de.Hook != HookOnConnect {
		t.Errorf("DispatchError.Hook = %q, want %q", de.Hook, HookOnConnect)
	}
}

func TestRegistry_Clear(t *testing.T) {
	r := NewRegistry()

	r.Register("p", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	if !r.HasHandlers(HookOnConnect) {
		t.Fatal("expected handler before clear")
	}

	r.Clear()

	if r.HasHandlers(HookOnConnect) {
		t.Error("expected no handlers after clear")
	}
}

func TestRegistry_Dispatch_DataPassedBetweenHandlers(t *testing.T) {
	r := NewRegistry()

	r.Register("plugin-a", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		data["from_a"] = "hello"
		return &HookResult{Action: ActionContinue, Data: data}, nil
	}, OnErrorSkip)
	r.Register("plugin-b", HookOnConnect, func(ctx context.Context, data map[string]any) (*HookResult, error) {
		if data["from_a"] != "hello" {
			t.Errorf("plugin-b did not receive data from plugin-a: %v", data)
		}
		return &HookResult{Action: ActionContinue}, nil
	}, OnErrorSkip)

	_, err := r.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
}
