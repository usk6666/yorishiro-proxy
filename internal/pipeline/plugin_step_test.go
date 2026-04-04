package pipeline

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

func TestPluginStep_NilEngine(t *testing.T) {
	step := NewPluginStep(nil, PhaseRecv, nil)
	ex := &exchange.Exchange{Direction: exchange.Send}
	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Fatalf("expected Continue, got %v", result.Action)
	}
}

func TestPluginStep_ResolveHook(t *testing.T) {
	tests := []struct {
		name     string
		phase    HookPhase
		dir      exchange.Direction
		wantHook plugin.Hook
	}{
		{
			name:     "PhaseRecv+Send -> on_receive_from_client",
			phase:    PhaseRecv,
			dir:      exchange.Send,
			wantHook: plugin.HookOnReceiveFromClient,
		},
		{
			name:     "PhaseRecv+Receive -> on_receive_from_server",
			phase:    PhaseRecv,
			dir:      exchange.Receive,
			wantHook: plugin.HookOnReceiveFromServer,
		},
		{
			name:     "PhaseSend+Send -> on_before_send_to_server",
			phase:    PhaseSend,
			dir:      exchange.Send,
			wantHook: plugin.HookOnBeforeSendToServer,
		},
		{
			name:     "PhaseSend+Receive -> on_before_send_to_client",
			phase:    PhaseSend,
			dir:      exchange.Receive,
			wantHook: plugin.HookOnBeforeSendToClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &PluginStep{phase: tt.phase}
			got := step.resolveHook(tt.dir)
			if got != tt.wantHook {
				t.Fatalf("expected hook %q, got %q", tt.wantHook, got)
			}
		})
	}
}

func TestExchangeToMap_Send(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       u,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
			{Name: "Accept", Value: "text/html"},
		},
		Body:     []byte("hello"),
		Protocol: exchange.HTTP1,
	}

	m := exchangeToMap(ex)

	if m["method"] != "GET" {
		t.Errorf("method = %v, want GET", m["method"])
	}
	if m["url"] != "http://example.com/path" {
		t.Errorf("url = %v, want http://example.com/path", m["url"])
	}
	if m["protocol"] != "HTTP/1.x" {
		t.Errorf("protocol = %v, want HTTP/1.x", m["protocol"])
	}
	if _, ok := m["status_code"]; ok {
		t.Error("status_code should not be set for Send direction")
	}
	headers := m["headers"].([]any)
	if len(headers) != 2 {
		t.Fatalf("headers length = %d, want 2", len(headers))
	}
	h0 := headers[0].(map[string]any)
	if h0["name"] != "Host" || h0["value"] != "example.com" {
		t.Errorf("headers[0] = %v, want Host: example.com", h0)
	}
}

func TestExchangeToMap_Receive(t *testing.T) {
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    404,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
		},
		Body:     []byte("not found"),
		Protocol: exchange.HTTP2,
	}

	m := exchangeToMap(ex)

	if m["status_code"] != 404 {
		t.Errorf("status_code = %v, want 404", m["status_code"])
	}
}

func TestExchangeToMap_NilURL(t *testing.T) {
	ex := &exchange.Exchange{Direction: exchange.Send}
	m := exchangeToMap(ex)
	if m["url"] != "" {
		t.Errorf("url = %v, want empty string", m["url"])
	}
}

func TestExchangeToMap_Metadata(t *testing.T) {
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "POST",
		Protocol:  exchange.GRPC,
		Metadata: map[string]any{
			"service":    "greeter.Greeter",
			"method":     "SayHello",
			"irrelevant": "ignored",
		},
	}

	m := exchangeToMap(ex)

	// Metadata keys are prefixed with "meta_" to avoid collision with
	// top-level Exchange fields.
	if m["meta_service"] != "greeter.Greeter" {
		t.Errorf("meta_service = %v, want greeter.Greeter", m["meta_service"])
	}
	if m["meta_method"] != "SayHello" {
		t.Errorf("meta_method = %v, want SayHello", m["meta_method"])
	}
	// Top-level method must remain the HTTP method, not the gRPC method.
	if m["method"] != "POST" {
		t.Errorf("method = %v, want POST (HTTP method must not be overwritten by metadata)", m["method"])
	}
	if _, ok := m["irrelevant"]; ok {
		t.Error("irrelevant metadata key should not be exposed")
	}
}

func TestExchangeToMap_Trailers(t *testing.T) {
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Trailers: []exchange.KeyValue{
			{Name: "grpc-status", Value: "0"},
		},
	}

	m := exchangeToMap(ex)

	trailers, ok := m["trailers"]
	if !ok {
		t.Fatal("trailers key missing")
	}
	list := trailers.([]any)
	if len(list) != 1 {
		t.Fatalf("trailers length = %d, want 1", len(list))
	}
}

func TestExchangeToMap_NoTrailers(t *testing.T) {
	ex := &exchange.Exchange{Direction: exchange.Send}
	m := exchangeToMap(ex)
	if _, ok := m["trailers"]; ok {
		t.Error("trailers should not be set when empty")
	}
}

func TestHeadrsToListOfPairs_Nil(t *testing.T) {
	list := headersToListOfPairs(nil)
	if list == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(list) != 0 {
		t.Errorf("length = %d, want 0", len(list))
	}
}

func TestPairsToHeaders(t *testing.T) {
	input := []any{
		map[string]any{"name": "Content-Type", "value": "text/html"},
		map[string]any{"name": "X-Custom", "value": "val"},
	}

	result := pairsToHeaders(input)
	if len(result) != 2 {
		t.Fatalf("length = %d, want 2", len(result))
	}
	if result[0].Name != "Content-Type" || result[0].Value != "text/html" {
		t.Errorf("result[0] = %v", result[0])
	}
}

func TestPairsToHeaders_SkipsEmptyName(t *testing.T) {
	input := []any{
		map[string]any{"name": "", "value": "val"},
		map[string]any{"name": "X-Valid", "value": "ok"},
	}

	result := pairsToHeaders(input)
	if len(result) != 1 {
		t.Fatalf("length = %d, want 1", len(result))
	}
	if result[0].Name != "X-Valid" {
		t.Errorf("result[0].Name = %q, want X-Valid", result[0].Name)
	}
}

func TestPairsToHeaders_InvalidType(t *testing.T) {
	result := pairsToHeaders("not a list")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestApplyPluginChanges_Method(t *testing.T) {
	ex := &exchange.Exchange{Method: "GET"}
	applyPluginChanges(ex, map[string]any{"method": "POST"})
	if ex.Method != "POST" {
		t.Errorf("Method = %q, want POST", ex.Method)
	}
}

func TestApplyPluginChanges_URL(t *testing.T) {
	ex := &exchange.Exchange{}
	applyPluginChanges(ex, map[string]any{"url": "http://new.example.com/path"})
	if ex.URL == nil || ex.URL.String() != "http://new.example.com/path" {
		t.Errorf("URL = %v, want http://new.example.com/path", ex.URL)
	}
}

func TestApplyPluginChanges_StatusCode(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want int
	}{
		{"int", 404, 404},
		{"int64", int64(500), 500},
		{"float64", float64(301), 301},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &exchange.Exchange{Status: 200}
			applyPluginChanges(ex, map[string]any{"status_code": tt.val})
			if ex.Status != tt.want {
				t.Errorf("Status = %d, want %d", ex.Status, tt.want)
			}
		})
	}
}

func TestApplyPluginChanges_Headers(t *testing.T) {
	ex := &exchange.Exchange{
		Headers: []exchange.KeyValue{{Name: "Old", Value: "val"}},
	}
	applyPluginChanges(ex, map[string]any{
		"headers": []any{
			map[string]any{"name": "New", "value": "newval"},
		},
	})
	if len(ex.Headers) != 1 || ex.Headers[0].Name != "New" {
		t.Errorf("Headers = %v, want [{New newval}]", ex.Headers)
	}
}

func TestApplyPluginChanges_Body(t *testing.T) {
	ex := &exchange.Exchange{Body: []byte("old")}

	t.Run("bytes", func(t *testing.T) {
		applyPluginChanges(ex, map[string]any{"body": []byte("new")})
		if string(ex.Body) != "new" {
			t.Errorf("Body = %q, want new", ex.Body)
		}
	})

	t.Run("string", func(t *testing.T) {
		applyPluginChanges(ex, map[string]any{"body": "str"})
		if string(ex.Body) != "str" {
			t.Errorf("Body = %q, want str", ex.Body)
		}
	})
}

func TestApplyPluginChanges_Trailers(t *testing.T) {
	ex := &exchange.Exchange{}
	applyPluginChanges(ex, map[string]any{
		"trailers": []any{
			map[string]any{"name": "grpc-status", "value": "0"},
		},
	})
	if len(ex.Trailers) != 1 || ex.Trailers[0].Name != "grpc-status" {
		t.Errorf("Trailers = %v", ex.Trailers)
	}
}

func TestBuildResponseFromPlugin_Nil(t *testing.T) {
	resp := buildResponseFromPlugin(nil)
	if resp.Status != 200 {
		t.Errorf("Status = %d, want 200", resp.Status)
	}
	if resp.Direction != exchange.Receive {
		t.Errorf("Direction = %v, want Receive", resp.Direction)
	}
}

func TestBuildResponseFromPlugin_Full(t *testing.T) {
	data := map[string]any{
		"status_code": 403,
		"headers": []any{
			map[string]any{"name": "X-Blocked", "value": "true"},
		},
		"body": "forbidden",
	}
	resp := buildResponseFromPlugin(data)
	if resp.Status != 403 {
		t.Errorf("Status = %d, want 403", resp.Status)
	}
	if len(resp.Headers) != 1 || resp.Headers[0].Name != "X-Blocked" {
		t.Errorf("Headers = %v", resp.Headers)
	}
	if string(resp.Body) != "forbidden" {
		t.Errorf("Body = %q, want forbidden", string(resp.Body))
	}
}

func TestHookPhase_String(t *testing.T) {
	if PhaseRecv.String() != "PhaseRecv" {
		t.Errorf("PhaseRecv.String() = %q", PhaseRecv.String())
	}
	if PhaseSend.String() != "PhaseSend" {
		t.Errorf("PhaseSend.String() = %q", PhaseSend.String())
	}
	if HookPhase(99).String() != "Unknown" {
		t.Errorf("HookPhase(99).String() = %q", HookPhase(99).String())
	}
}

// TestPluginStep_DispatchDrop verifies that ActionDrop from the plugin engine
// is translated to pipeline.Drop.
func TestPluginStep_DispatchDrop(t *testing.T) {
	engine := setupTestEngine(t, `
def on_receive_from_client(data):
    return {"action": "DROP"}
`, plugin.HookOnReceiveFromClient)

	step := NewPluginStep(engine, PhaseRecv, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
	}

	result := step.Process(context.Background(), ex)
	if result.Action != Drop {
		t.Fatalf("expected Drop, got %v", result.Action)
	}
}

// TestPluginStep_DispatchRespond verifies that ActionRespond produces a
// Respond result with the custom response Exchange.
func TestPluginStep_DispatchRespond(t *testing.T) {
	engine := setupTestEngine(t, `
def on_receive_from_client(data):
    return {
        "action": "RESPOND",
        "response": {
            "status_code": 403,
            "headers": [{"name": "X-Blocked", "value": "true"}],
            "body": "blocked",
        },
    }
`, plugin.HookOnReceiveFromClient)

	step := NewPluginStep(engine, PhaseRecv, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "POST",
	}

	result := step.Process(context.Background(), ex)
	if result.Action != Respond {
		t.Fatalf("expected Respond, got %v", result.Action)
	}
	if result.Response == nil {
		t.Fatal("expected non-nil Response")
	}
	if result.Response.Status != 403 {
		t.Errorf("Response.Status = %d, want 403", result.Response.Status)
	}
	if string(result.Response.Body) != "blocked" {
		t.Errorf("Response.Body = %q, want blocked", string(result.Response.Body))
	}
}

// TestPluginStep_DispatchContinueWithModification verifies that in-place
// modifications from the plugin are applied to the Exchange.
func TestPluginStep_DispatchContinueWithModification(t *testing.T) {
	engine := setupTestEngine(t, `
def on_receive_from_client(data):
    return {
        "action": "CONTINUE",
        "data": {
            "method": "PUT",
            "headers": [{"name": "X-Added", "value": "by-plugin"}],
        },
    }
`, plugin.HookOnReceiveFromClient)

	step := NewPluginStep(engine, PhaseRecv, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
	}

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Fatalf("expected Continue, got %v", result.Action)
	}

	// Verify in-place changes on the original Exchange.
	if ex.Method != "PUT" {
		t.Errorf("Method = %q, want PUT", ex.Method)
	}
	if len(ex.Headers) != 1 || ex.Headers[0].Name != "X-Added" {
		t.Errorf("Headers = %v, want [{X-Added by-plugin}]", ex.Headers)
	}
}

// TestPluginStep_DispatchContinueNoModification verifies that Continue with
// no data does not change the Exchange.
func TestPluginStep_DispatchContinueNoModification(t *testing.T) {
	engine := setupTestEngine(t, `
def on_before_send_to_server(data):
    return None
`, plugin.HookOnBeforeSendToServer)

	step := NewPluginStep(engine, PhaseSend, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
	}

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Fatalf("expected Continue, got %v", result.Action)
	}
	if ex.Method != "GET" {
		t.Errorf("Method changed unexpectedly to %q", ex.Method)
	}
}

// TestPluginStep_PhaseRecvReceive verifies PhaseRecv + Receive dispatches
// on_receive_from_server.
func TestPluginStep_PhaseRecvReceive(t *testing.T) {
	engine := setupTestEngine(t, `
def on_receive_from_server(data):
    return {
        "action": "CONTINUE",
        "data": {"status_code": 999},
    }
`, plugin.HookOnReceiveFromServer)

	step := NewPluginStep(engine, PhaseRecv, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
	}

	step.Process(context.Background(), ex)
	if ex.Status != 999 {
		t.Errorf("Status = %d, want 999", ex.Status)
	}
}

// TestPluginStep_PhaseSendReceive verifies PhaseSend + Receive dispatches
// on_before_send_to_client.
func TestPluginStep_PhaseSendReceive(t *testing.T) {
	engine := setupTestEngine(t, `
def on_before_send_to_client(data):
    return {
        "action": "CONTINUE",
        "data": {"status_code": 418},
    }
`, plugin.HookOnBeforeSendToClient)

	step := NewPluginStep(engine, PhaseSend, nil)
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
	}

	step.Process(context.Background(), ex)
	if ex.Status != 418 {
		t.Errorf("Status = %d, want 418", ex.Status)
	}
}

// setupTestEngine creates a plugin.Engine with a single Starlark script
// loaded from the provided source. The script is written to a temp file.
func setupTestEngine(t *testing.T, script string, hooks ...plugin.Hook) *plugin.Engine {
	t.Helper()

	dir := t.TempDir()
	path := dir + "/test_plugin.star"

	hookNames := make([]string, len(hooks))
	for i, h := range hooks {
		hookNames[i] = string(h)
	}

	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatalf("write test script: %v", err)
	}

	engine := plugin.NewEngine(nil)
	cfg := plugin.PluginConfig{
		Path:     path,
		Protocol: "any",
		Hooks:    hookNames,
	}

	if err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{cfg}); err != nil {
		t.Fatalf("load plugins: %v", err)
	}

	return engine
}
