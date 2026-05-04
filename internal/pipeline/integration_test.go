//go:build legacy

package pipeline

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// buildFullPipeline constructs a Pipeline with all Steps in the canonical order:
// Scope -> RateLimit -> Safety -> Plugin(PhaseRecv) -> Intercept -> Transform -> Plugin(PhaseSend) -> Record
func buildFullPipeline(
	scope *proxy.TargetScope,
	limiter *proxy.RateLimiter,
	safetyEngine *safety.Engine,
	pluginEngine *plugin.Engine,
	interceptEngine *intercept.Engine,
	interceptQueue *intercept.Queue,
	transformPipeline *rules.Pipeline,
	store RecordWriter,
) *Pipeline {
	return New(
		NewScopeStep(scope),
		NewRateLimitStep(limiter),
		NewSafetyStep(safetyEngine),
		NewPluginStep(pluginEngine, PhaseRecv, nil),
		NewInterceptStep(interceptEngine, interceptQueue),
		NewTransformStep(transformPipeline),
		NewPluginStep(pluginEngine, PhaseSend, nil),
		NewRecordStep(store, nil),
	)
}

// testStore records all SaveStream and SaveFlow calls for verification.
type testStore struct {
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *testStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.streams = append(s.streams, st)
	return nil
}

func (s *testStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (s *testStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.flows = append(s.flows, f)
	return nil
}

func (s *testStore) flowsByVariant(variant string) []*flow.Flow {
	var result []*flow.Flow
	for _, f := range s.flows {
		if f.Metadata != nil && f.Metadata["variant"] == variant {
			result = append(result, f)
		}
	}
	return result
}

func (s *testStore) flowsWithoutVariant() []*flow.Flow {
	var result []*flow.Flow
	for _, f := range s.flows {
		if f.Metadata == nil || f.Metadata["variant"] == "" {
			result = append(result, f)
		}
	}
	return result
}

// newSendExchange creates a typical Send Exchange for tests.
func newSendExchange(streamID, flowID string, seq int) *exchange.Exchange {
	return &exchange.Exchange{
		StreamID:  streamID,
		FlowID:    flowID,
		Sequence:  seq,
		Direction: envelope.Send,
		Method:    "GET",
		URL:       &url.URL{Scheme: "https", Host: "example.com", Path: "/api"},
		Protocol:  envelope.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
			{Name: "Accept", Value: "text/html"},
		},
		Body: []byte("request body"),
	}
}

// newReceiveExchange creates a typical Receive Exchange for tests.
func newReceiveExchange(streamID, flowID string, seq int) *exchange.Exchange {
	return &exchange.Exchange{
		StreamID:  streamID,
		FlowID:    flowID,
		Sequence:  seq,
		Direction: envelope.Receive,
		Status:    200,
		Protocol:  envelope.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "text/html"},
		},
		Body: []byte("response body"),
	}
}

// --- Test 1: Normal path ---

func TestIntegration_NormalPath(t *testing.T) {
	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	got, action, resp := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if got != ex {
		t.Fatal("expected original exchange returned")
	}

	// Stream created on first Send.
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}
	st := store.streams[0]
	if st.ID != "stream-1" {
		t.Errorf("stream ID = %q, want %q", st.ID, "stream-1")
	}
	if st.Protocol != "HTTP/1.x" {
		t.Errorf("stream protocol = %q, want %q", st.Protocol, "HTTP/1.x")
	}
	if st.State != "active" {
		t.Errorf("stream state = %q, want %q", st.State, "active")
	}
	if st.Scheme != "https" {
		t.Errorf("stream scheme = %q, want %q", st.Scheme, "https")
	}

	// Flow created.
	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}
	fl := store.flows[0]
	if fl.ID != "flow-1" {
		t.Errorf("flow ID = %q, want %q", fl.ID, "flow-1")
	}
	if fl.StreamID != "stream-1" {
		t.Errorf("flow stream ID = %q, want %q", fl.StreamID, "stream-1")
	}
	if fl.Direction != "send" {
		t.Errorf("flow direction = %q, want %q", fl.Direction, "send")
	}
}

// --- Test 2: ScopeStep Drop ---

func TestIntegration_ScopeStep_Drop(t *testing.T) {
	scope := proxy.NewTargetScope()
	scope.SetPolicyRules(nil, []proxy.TargetRule{
		{Hostname: "example.com"},
	})

	store := &testStore{}
	p := buildFullPipeline(scope, nil, nil, nil, nil, nil, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	_, action, _ := p.Run(context.Background(), ex)

	if action != Drop {
		t.Fatalf("expected Drop, got %v", action)
	}

	// No stream or flow recorded (RecordStep never reached).
	if len(store.streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(store.streams))
	}
	if len(store.flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(store.flows))
	}
}

// --- Test 3: RateLimitStep Drop ---

func TestIntegration_RateLimitStep_Drop(t *testing.T) {
	limiter := proxy.NewRateLimiter()
	// 0.001 RPS with burst=1: first request passes, second is denied.
	limiter.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 0.001,
	})

	store := &testStore{}
	p := buildFullPipeline(nil, limiter, nil, nil, nil, nil, nil, store)

	// First request consumes the burst token.
	ex1 := newSendExchange("stream-1", "flow-1", 0)
	_, action1, _ := p.Run(context.Background(), ex1)
	if action1 != Continue {
		t.Fatalf("first request: expected Continue, got %v", action1)
	}

	// Second request should be rate limited (Drop).
	ex2 := newSendExchange("stream-2", "flow-2", 0)
	_, action2, _ := p.Run(context.Background(), ex2)
	if action2 != Drop {
		t.Fatalf("second request: expected Drop, got %v", action2)
	}

	// First request recorded (1 stream + 1 flow), second not recorded.
	if len(store.streams) != 1 {
		t.Errorf("expected 1 stream, got %d", len(store.streams))
	}
	if len(store.flows) != 1 {
		t.Errorf("expected 1 flow, got %d", len(store.flows))
	}
}

// --- Test 4: SafetyStep Drop ---

func TestIntegration_SafetyStep_Drop(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	store := &testStore{}
	p := buildFullPipeline(nil, nil, engine, nil, nil, nil, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	ex.Body = []byte("DROP TABLE users")
	_, action, _ := p.Run(context.Background(), ex)

	if action != Drop {
		t.Fatalf("expected Drop, got %v", action)
	}

	// No stream or flow recorded.
	if len(store.streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(store.streams))
	}
	if len(store.flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(store.flows))
	}
}

// --- Test 5: PluginStep Drop ---

func TestIntegration_PluginStep_Drop(t *testing.T) {
	pluginEngine := setupIntegrationPlugin(t, `
def on_receive_from_client(data):
    return {"action": "DROP"}
`, plugin.HookOnReceiveFromClient)

	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, pluginEngine, nil, nil, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	_, action, _ := p.Run(context.Background(), ex)

	if action != Drop {
		t.Fatalf("expected Drop, got %v", action)
	}

	// No stream or flow recorded.
	if len(store.streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(store.streams))
	}
	if len(store.flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(store.flows))
	}
}

// --- Test 6: PluginStep Respond ---

func TestIntegration_PluginStep_Respond(t *testing.T) {
	pluginEngine := setupIntegrationPlugin(t, `
def on_receive_from_client(data):
    return {
        "action": "RESPOND",
        "response": {
            "status_code": 403,
            "headers": [{"name": "X-Blocked", "value": "true"}],
            "body": "blocked by plugin",
        },
    }
`, plugin.HookOnReceiveFromClient)

	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, pluginEngine, nil, nil, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	_, action, resp := p.Run(context.Background(), ex)

	if action != Respond {
		t.Fatalf("expected Respond, got %v", action)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != 403 {
		t.Errorf("response status = %d, want 403", resp.Status)
	}
	if string(resp.Body) != "blocked by plugin" {
		t.Errorf("response body = %q, want %q", string(resp.Body), "blocked by plugin")
	}

	// No stream or flow recorded (RecordStep not reached).
	if len(store.streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(store.streams))
	}
}

// --- Test 7: InterceptStep blocking + release ---

func TestIntegration_InterceptStep_BlockAndRelease(t *testing.T) {
	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "catch-all",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	queue := intercept.NewQueue()

	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, engine, queue, nil, store)

	ex := newSendExchange("stream-1", "flow-1", 0)

	// Release the intercepted exchange asynchronously.
	go func() {
		for i := 0; i < 200; i++ {
			items := queue.List()
			if len(items) > 0 {
				if err := queue.Respond(items[0].ID, intercept.InterceptAction{
					Type: intercept.ActionRelease,
				}); err != nil {
					t.Errorf("Respond: %v", err)
				}
				return
			}
			sleepShort()
		}
		t.Errorf("timed out waiting for queue item")
	}()

	_, action, _ := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue after release, got %v", action)
	}

	// Stream and flow should be recorded (RecordStep reached after Intercept release).
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}
	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}
}

// --- Test 8: TransformStep + RecordStep variant ---

func TestIntegration_TransformStep_Variant(t *testing.T) {
	rp := rules.NewPipeline()
	if err := rp.AddRule(rules.Rule{
		ID:        "add-auth",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "Authorization",
			Value:  "Bearer test-token",
		},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, rp, store)

	ex := newSendExchange("stream-1", "flow-1", 0)
	_, action, _ := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}

	// Stream created.
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}

	// Variant detection: original + modified flows.
	if len(store.flows) != 2 {
		t.Fatalf("expected 2 flows (variant), got %d", len(store.flows))
	}

	origFlows := store.flowsByVariant("original")
	modFlows := store.flowsByVariant("modified")

	if len(origFlows) != 1 {
		t.Fatalf("expected 1 original variant, got %d", len(origFlows))
	}
	if len(modFlows) != 1 {
		t.Fatalf("expected 1 modified variant, got %d", len(modFlows))
	}

	// Original should not have the Authorization header.
	if origFlows[0].Headers["Authorization"] != nil {
		t.Error("original variant should not have Authorization header")
	}

	// Modified should have the Authorization header.
	authVals := modFlows[0].Headers["Authorization"]
	if len(authVals) == 0 || authVals[0] != "Bearer test-token" {
		t.Errorf("modified variant Authorization = %v, want [Bearer test-token]", authVals)
	}
}

// --- Test 9: Without(InterceptStep) for Macro pipeline ---

func TestIntegration_Without_InterceptStep(t *testing.T) {
	// Use a transform rule to verify the pipeline still works without InterceptStep.
	rp := rules.NewPipeline()
	if err := rp.AddRule(rules.Rule{
		ID:        "add-header",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "X-Macro",
			Value:  "true",
		},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := &testStore{}
	full := buildFullPipeline(nil, nil, nil, nil, nil, nil, rp, store)
	macro := full.Without(&InterceptStep{})

	ex := newSendExchange("stream-1", "flow-1", 0)
	got, action, _ := macro.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}

	// Verify Transform applied.
	if exchange.HeaderGet(got.Headers, "X-Macro") != "true" {
		t.Error("expected X-Macro header from TransformStep")
	}

	// Verify Record worked.
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}
	if len(store.flows) > 0 {
		// Variant flows should be present (since transform modified the exchange).
		found := false
		for _, f := range store.flows {
			if f.Metadata != nil && f.Metadata["variant"] == "modified" {
				found = true
			}
		}
		if !found {
			t.Error("expected modified variant flow from RecordStep")
		}
	}
}

// --- Test 10: Direction=Receive skips Send-only Steps ---

func TestIntegration_ReceiveDirection(t *testing.T) {
	// Configure ScopeStep with deny rules. These should NOT block Receive.
	scope := proxy.NewTargetScope()
	scope.SetPolicyRules(nil, []proxy.TargetRule{
		{Hostname: "example.com"},
	})

	// Configure a safety rule that blocks body content.
	safetyEngine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-all", Pattern: `.*`, Targets: []string{"body"}, Action: "block"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	store := &testStore{}
	p := buildFullPipeline(scope, nil, safetyEngine, nil, nil, nil, nil, store)

	ex := newReceiveExchange("stream-1", "flow-2", 1)
	_, action, _ := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue for Receive, got %v (Scope/Safety should skip Receive)", action)
	}

	// Flow recorded (no stream creation for Receive with Sequence>0).
	if len(store.streams) != 0 {
		t.Errorf("expected 0 streams for Receive, got %d", len(store.streams))
	}
	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}
	if store.flows[0].Direction != "receive" {
		t.Errorf("flow direction = %q, want %q", store.flows[0].Direction, "receive")
	}
}

// --- Test 11: Body nil (passthrough) ---

func TestIntegration_BodyNilPassthrough(t *testing.T) {
	// Safety rule that blocks "DROP TABLE" in body. With nil body, it should
	// not trigger (unless URL/headers also match).
	safetyEngine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	store := &testStore{}
	p := buildFullPipeline(nil, nil, safetyEngine, nil, nil, nil, nil, store)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: envelope.Send,
		Method:    "GET",
		URL:       &url.URL{Scheme: "https", Host: "example.com", Path: "/api"},
		Protocol:  envelope.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
		Body: nil, // passthrough
	}

	_, action, _ := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue with nil body, got %v", action)
	}

	// Stream + flow recorded.
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}
	if len(store.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.flows))
	}
	if store.flows[0].Body != nil {
		t.Errorf("flow body should be nil for passthrough, got %v", store.flows[0].Body)
	}
}

// --- Test 12: Streaming pattern (multiple Send/Receive) ---

func TestIntegration_StreamingPattern(t *testing.T) {
	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, nil, store)

	// Send #0 (creates Stream).
	ex0 := newSendExchange("stream-1", "flow-s0", 0)
	_, action, _ := p.Run(context.Background(), ex0)
	if action != Continue {
		t.Fatalf("Send #0: expected Continue, got %v", action)
	}

	// Receive #1.
	ex1 := newReceiveExchange("stream-1", "flow-r1", 1)
	_, action, _ = p.Run(context.Background(), ex1)
	if action != Continue {
		t.Fatalf("Receive #1: expected Continue, got %v", action)
	}

	// Send #2.
	ex2 := newSendExchange("stream-1", "flow-s2", 2)
	_, action, _ = p.Run(context.Background(), ex2)
	if action != Continue {
		t.Fatalf("Send #2: expected Continue, got %v", action)
	}

	// Receive #3.
	ex3 := newReceiveExchange("stream-1", "flow-r3", 3)
	_, action, _ = p.Run(context.Background(), ex3)
	if action != Continue {
		t.Fatalf("Receive #3: expected Continue, got %v", action)
	}

	// Verify: 1 Stream, 4 Flows.
	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(store.streams))
	}
	if store.streams[0].ID != "stream-1" {
		t.Errorf("stream ID = %q, want %q", store.streams[0].ID, "stream-1")
	}

	if len(store.flows) != 4 {
		t.Fatalf("expected 4 flows, got %d", len(store.flows))
	}

	// Verify flow ordering.
	expectedIDs := []string{"flow-s0", "flow-r1", "flow-s2", "flow-r3"}
	expectedDirs := []string{"send", "receive", "send", "receive"}
	for i, f := range store.flows {
		if f.ID != expectedIDs[i] {
			t.Errorf("flow[%d] ID = %q, want %q", i, f.ID, expectedIDs[i])
		}
		if f.Direction != expectedDirs[i] {
			t.Errorf("flow[%d] direction = %q, want %q", i, f.Direction, expectedDirs[i])
		}
		if f.StreamID != "stream-1" {
			t.Errorf("flow[%d] stream ID = %q, want %q", i, f.StreamID, "stream-1")
		}
	}

	// Stream state is NOT changed by RecordStep (Session's responsibility).
	if store.streams[0].State != "active" {
		t.Errorf("stream state = %q, want %q (RecordStep must not change state)", store.streams[0].State, "active")
	}
}

// --- Data model verification ---

func TestIntegration_DataModel_StreamCreatedOnFirstSend(t *testing.T) {
	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, nil, store)

	// Receive first (Sequence=1) -> no stream created.
	ex := newReceiveExchange("stream-1", "flow-r1", 1)
	p.Run(context.Background(), ex)

	if len(store.streams) != 0 {
		t.Fatalf("expected 0 streams after Receive, got %d", len(store.streams))
	}

	// Send with Sequence=0 -> stream created.
	ex2 := newSendExchange("stream-1", "flow-s0", 0)
	p.Run(context.Background(), ex2)

	if len(store.streams) != 1 {
		t.Fatalf("expected 1 stream after Send Seq=0, got %d", len(store.streams))
	}
}

func TestIntegration_DataModel_FlowPerExchange(t *testing.T) {
	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, nil, store)

	// Each Pipeline.Run creates exactly one Flow.
	for i := 0; i < 5; i++ {
		var ex *exchange.Exchange
		if i%2 == 0 {
			ex = newSendExchange("stream-1", "flow-"+string(rune('a'+i)), i)
		} else {
			ex = newReceiveExchange("stream-1", "flow-"+string(rune('a'+i)), i)
		}
		p.Run(context.Background(), ex)
	}

	nonVariantFlows := store.flowsWithoutVariant()
	if len(nonVariantFlows) != 5 {
		t.Fatalf("expected 5 non-variant flows, got %d", len(nonVariantFlows))
	}
}

func TestIntegration_DataModel_StreamStateNotChangedByRecordStep(t *testing.T) {
	store := &testStore{}
	p := buildFullPipeline(nil, nil, nil, nil, nil, nil, nil, store)

	// Create stream.
	ex := newSendExchange("stream-1", "flow-1", 0)
	p.Run(context.Background(), ex)

	// Multiple sends and receives.
	for i := 1; i <= 3; i++ {
		recv := newReceiveExchange("stream-1", "flow-r"+string(rune('0'+i)), i)
		p.Run(context.Background(), recv)
	}

	// Stream state should still be "active" (Session sets it to "complete").
	if store.streams[0].State != "active" {
		t.Errorf("stream state = %q, want %q", store.streams[0].State, "active")
	}
}

// --- Helpers ---

// setupIntegrationPlugin creates a plugin.Engine with a single Starlark script.
func setupIntegrationPlugin(t *testing.T, script string, hooks ...plugin.Hook) *plugin.Engine {
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

// sleepShort waits a short time for queue polling.
func sleepShort() {
	time.Sleep(time.Millisecond)
}
