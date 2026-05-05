package pipeline

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

func newTestInterceptEngine(rules ...httprules.InterceptRule) *httprules.InterceptEngine {
	e := httprules.NewInterceptEngine()
	e.SetRules(rules)
	return e
}

func newCatchAllRequestRule() httprules.InterceptRule {
	return httprules.InterceptRule{
		ID:        "catch-all",
		Enabled:   true,
		Direction: httprules.DirectionRequest,
	}
}

func newCatchAllResponseRule() httprules.InterceptRule {
	return httprules.InterceptRule{
		ID:        "catch-all-resp",
		Enabled:   true,
		Direction: httprules.DirectionResponse,
	}
}

func TestInterceptStep_Release(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		// Wait for the entry to appear in the queue.
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("Release: got action %v, want Continue", result.Action)
	}
	if result.Envelope != nil {
		t.Error("Release: expected nil Envelope in result")
	}
}

func TestInterceptStep_Drop(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("Drop: got action %v, want Drop", result.Action)
	}
}

func TestInterceptStep_ModifyAndForward(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/original",
		},
	}

	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/modified",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				action := &common.HoldAction{
					Type:     common.ActionModifyAndForward,
					Modified: modifiedEnv,
				}
				if err := queue.Release(entries[0].ID, action); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("ModifyAndForward: got action %v, want Continue", result.Action)
	}
	if result.Envelope == nil {
		t.Fatal("ModifyAndForward: expected non-nil Envelope in result")
	}
	msg, ok := result.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("ModifyAndForward: expected HTTPMessage")
	}
	if msg.Path != "/modified" {
		t.Errorf("ModifyAndForward: path = %q, want /modified", msg.Path)
	}
}

func TestInterceptStep_NoMatch(t *testing.T) {
	// Rule only matches /api/ paths.
	engine := newTestInterceptEngine(httprules.InterceptRule{
		ID:          "api-only",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/api/`),
	})
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/web/index.html",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NoMatch: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("NoMatch: queue should be empty, got %d items", queue.Len())
	}
}

func TestInterceptStep_RawMessage_PassThrough(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("hello")},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("RawMessage: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_NilEngine(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilEngine: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_NilQueue(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	step := NewInterceptStep(engine, nil, nil, nil, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilQueue: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_ContextCancellation(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		// Wait for the entry to appear, then cancel context.
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			if queue.Len() > 0 {
				cancel()
				return
			}
		}
		cancel()
	}()

	result := step.Process(ctx, env)
	if result.Action != Drop {
		t.Errorf("ContextCancellation: got action %v, want Drop", result.Action)
	}
}

func TestInterceptStep_ResponseMatch(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllResponseRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("ResponseMatch: got action %v, want Continue", result.Action)
	}
}

// ---------------------------------------------------------------------------
// WS / gRPC dispatch tests (USK-648).
// ---------------------------------------------------------------------------

func newTestWSInterceptEngine(rules ...wsrules.InterceptRule) *wsrules.InterceptEngine {
	e := wsrules.NewInterceptEngine()
	e.SetRules(rules)
	return e
}

func newCatchAllWSRule() wsrules.InterceptRule {
	return wsrules.InterceptRule{
		ID:        "ws-catch-all",
		Enabled:   true,
		Direction: wsrules.DirectionBoth,
	}
}

func newTestGRPCInterceptEngine(rules ...grpcrules.InterceptRule) *grpcrules.InterceptEngine {
	e := grpcrules.NewInterceptEngine()
	e.SetRules(rules)
	return e
}

func newCatchAllGRPCRule() grpcrules.InterceptRule {
	return grpcrules.InterceptRule{
		ID:        "grpc-catch-all",
		Enabled:   true,
		Direction: grpcrules.DirectionBoth,
	}
}

// releaseFirst is a goroutine helper that waits for the first held entry to
// appear in queue and applies action.
func releaseFirst(t *testing.T, queue *common.HoldQueue, action *common.HoldAction) {
	t.Helper()
	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, action); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()
}

func TestInterceptStep_WS_Release(t *testing.T) {
	wsEngine := newTestWSInterceptEngine(newCatchAllWSRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, wsEngine, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Payload: []byte(`{"hello":"world"}`),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_Release: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_WS_Drop(t *testing.T) {
	wsEngine := newTestWSInterceptEngine(newCatchAllWSRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, wsEngine, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte("attack"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionDrop})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("WS_Drop: got action %v, want Drop", result.Action)
	}
}

func TestInterceptStep_WS_ModifyAndForward(t *testing.T) {
	wsEngine := newTestWSInterceptEngine(newCatchAllWSRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, wsEngine, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte("original"),
		},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte("modified"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_Modify: got action %v, want Continue", result.Action)
	}
	if result.Envelope == nil {
		t.Fatal("WS_Modify: expected non-nil Envelope in result")
	}
	msg, ok := result.Envelope.Message.(*envelope.WSMessage)
	if !ok {
		t.Fatal("WS_Modify: expected WSMessage")
	}
	if string(msg.Payload) != "modified" {
		t.Errorf("WS_Modify: payload = %q, want %q", msg.Payload, "modified")
	}
}

func TestInterceptStep_WS_NilEngine(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte("payload"),
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("WS_NilEngine: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("WS_NilEngine: queue should be empty, got %d", queue.Len())
	}
}

func TestInterceptStep_GRPCStart_Release(t *testing.T) {
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, grpcEngine, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service: "Greeter",
			Method:  "SayHello",
		},
	}

	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCStart_Release: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_GRPCData_Drop(t *testing.T) {
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, grpcEngine, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Service: "Greeter",
			Method:  "SayHello",
			Payload: []byte("body"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionDrop})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("GRPCData_Drop: got action %v, want Drop", result.Action)
	}
}

// TestInterceptStep_GRPCEnd_Receive_Hold verifies an End event in Receive
// direction (native gRPC) is dispatched through MatchEnd and held by the
// queue under a catch-all rule.
func TestInterceptStep_GRPCEnd_Receive_Hold(t *testing.T) {
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, grpcEngine, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCEndMessage{
			Status: 0,
		},
	}

	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCEnd_Receive_Hold: got action %v, want Continue", result.Action)
	}
}

// TestInterceptStep_GRPCEnd_Send_PassThrough verifies the grpc-web Send-side
// End sentinel is filtered before MatchEnd runs — even with a catch-all rule
// loaded, the queue must remain empty so the request flush doesn't hang.
func TestInterceptStep_GRPCEnd_Send_PassThrough(t *testing.T) {
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, grpcEngine, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCEndMessage{
			Status: 0,
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPCEnd_Send_PassThrough: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("GRPCEnd_Send_PassThrough: queue should be empty (Send-side End sentinel), got %d", queue.Len())
	}
}

func TestInterceptStep_GRPC_NilEngine(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service: "Greeter",
			Method:  "SayHello",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("GRPC_NilEngine: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("GRPC_NilEngine: queue should be empty, got %d", queue.Len())
	}
}

// TestInterceptStep_SSE_PassThrough verifies SSEMessage envelopes pass through
// silently even when other engines are wired (N7 scope-out).
func TestInterceptStep_SSE_PassThrough(t *testing.T) {
	httpEngine := newTestInterceptEngine(newCatchAllRequestRule())
	wsEngine := newTestWSInterceptEngine(newCatchAllWSRule())
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(httpEngine, wsEngine, grpcEngine, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Message: &envelope.SSEMessage{
			Event: "msg",
			Data:  "hello",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("SSE_PassThrough: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("SSE_PassThrough: queue should be empty, got %d", queue.Len())
	}
}

// ---------------------------------------------------------------------------
// SafetyStep re-check on modify_and_forward (USK-702).
//
// When the operator/AI agent supplies a modified envelope via the MCP
// `intercept` tool's modify_and_forward action, the modified envelope is
// re-checked against the same SafetyStep that gated the original held
// envelope at hold time. This is defense-in-depth — the SafetyStep ran
// BEFORE InterceptStep at hold time, so the original payload was safe;
// modify_and_forward could otherwise inject a destructive payload that
// bypasses the safety gate entirely.
// ---------------------------------------------------------------------------

func newDestructiveSQLSafetyStep(t *testing.T) *SafetyStep {
	t.Helper()
	httpSafety := httprules.NewSafetyEngine()
	if err := httpSafety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("load http safety preset: %v", err)
	}
	wsSafety := wsrules.NewSafetyEngine()
	wsPattern, err := common.CompilePattern(`(?i)\bDROP\s+TABLE\b`)
	if err != nil {
		t.Fatalf("compile ws pattern: %v", err)
	}
	wsSafety.AddRule(common.CompiledRule{
		ID:      "ws:drop-table",
		Name:    "DROP TABLE in payload",
		Pattern: wsPattern,
		Targets: []common.Target{wsrules.TargetPayload},
	})
	grpcSafety := grpcrules.NewSafetyEngine()
	if err := grpcSafety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("load grpc safety preset: %v", err)
	}
	return NewSafetyStep(httpSafety, wsSafety, grpcSafety, nil)
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_BlocksDestructiveBody
// verifies that an HTTP envelope modified via modify_and_forward to carry a
// destructive SQL payload is dropped by the SafetyStep re-check inside
// holdAndDispatch — the original safe held envelope passed SafetyStep at
// hold time, but the modified payload re-enters the gate and is rejected.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_BlocksDestructiveBody(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	safety := newDestructiveSQLSafetyStep(t)
	step := NewInterceptStep(engine, nil, nil, queue, safety, nil)

	// Original held envelope is safe — passes SafetyStep at hold time.
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte(`{"query":"SELECT 1"}`),
		},
	}
	// Modified envelope carries a destructive payload — the operator (or
	// an AI agent acting on their behalf) attempts to bypass safety via
	// the modify_and_forward release path.
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte("DROP TABLE users;"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("SafetyRecheck_Destructive: got action %v, want Drop", result.Action)
	}
	if result.Envelope != nil {
		t.Errorf("SafetyRecheck_Destructive: expected nil Envelope on Drop, got non-nil")
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_AllowsSafeBody verifies
// that a safe modify_and_forward payload is forwarded unchanged — the
// re-check is permissive and only intervenes on a violation.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_AllowsSafeBody(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	safety := newDestructiveSQLSafetyStep(t)
	step := NewInterceptStep(engine, nil, nil, queue, safety, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte(`{"query":"SELECT 1"}`),
		},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte(`{"query":"SELECT 2"}`),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("SafetyRecheck_Safe: got action %v, want Continue", result.Action)
	}
	if result.Envelope == nil {
		t.Fatal("SafetyRecheck_Safe: expected non-nil Envelope (modified)")
	}
	msg, ok := result.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("SafetyRecheck_Safe: expected HTTPMessage on result envelope")
	}
	if string(msg.Body) != `{"query":"SELECT 2"}` {
		t.Errorf("SafetyRecheck_Safe: body = %q, want SELECT 2", msg.Body)
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_NilSafety_PassThrough
// verifies that a nil SafetyStep disables the re-check — preserves the
// pre-USK-702 behaviour for callers/tests that don't wire safety.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_NilSafety_PassThrough(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, queue, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte(`{"query":"SELECT 1"}`),
		},
	}
	// Even a clearly destructive modify is forwarded when no SafetyStep
	// is wired — caller's responsibility to opt in.
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api/query",
			Body:   []byte("DROP TABLE users;"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilSafety: got action %v, want Continue", result.Action)
	}
	if result.Envelope == nil {
		t.Fatal("NilSafety: expected non-nil Envelope")
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_WS verifies the re-check
// fires on WS modify_and_forward when the modified frame carries a payload
// matching the WS SafetyEngine's rules.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_WS(t *testing.T) {
	wsEngine := newTestWSInterceptEngine(newCatchAllWSRule())
	queue := common.NewHoldQueue()
	safety := newDestructiveSQLSafetyStep(t)
	step := NewInterceptStep(nil, wsEngine, nil, queue, safety, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte(`{"hello":"world"}`),
		},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Payload: []byte("DROP TABLE accounts;"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("WS_SafetyRecheck: got action %v, want Drop", result.Action)
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_GRPCData verifies the
// re-check fires on gRPC modify_and_forward when the modified LPM payload
// matches the gRPC SafetyEngine's rules.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_GRPCData(t *testing.T) {
	grpcEngine := newTestGRPCInterceptEngine(newCatchAllGRPCRule())
	queue := common.NewHoldQueue()
	safety := newDestructiveSQLSafetyStep(t)
	step := NewInterceptStep(nil, nil, grpcEngine, queue, safety, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Service: "Greeter",
			Method:  "SayHello",
			Payload: []byte("safe payload"),
		},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Service: "Greeter",
			Method:  "SayHello",
			Payload: []byte("DROP TABLE sessions;"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("GRPC_SafetyRecheck: got action %v, want Drop", result.Action)
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_ReceiveDirection_Skip
// verifies that a Receive-direction modified response passes through even
// when its body would otherwise match a SafetyEngine rule. SafetyStep is a
// Send-only Input Filter; output filter re-evaluation is explicitly out of
// scope for USK-702 (separate per-MCP-response masking path).
func TestInterceptStep_ModifyAndForward_SafetyRecheck_ReceiveDirection_Skip(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllResponseRule())
	queue := common.NewHoldQueue()
	safety := newDestructiveSQLSafetyStep(t)
	step := NewInterceptStep(engine, nil, nil, queue, safety, nil)

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
		},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status: 200,
			// Even a body matching a Send-side rule must pass through on
			// Receive — Input Filter is Send-only.
			Body: []byte("DROP TABLE users;"),
		},
	}

	releaseFirst(t, queue, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modifiedEnv,
	})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("Receive_SafetyRecheck_Skip: got action %v, want Continue", result.Action)
	}
}
