package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// configureSessionWithEngines spins up an MCP server backed by the
// per-protocol intercept engines (USK-692). nil arguments disable that
// engine; the configure_tool's nil-engine guard surfaces the
// "not initialized" error path.
func configureSessionWithEngines(
	t *testing.T,
	httpEngine *httprules.InterceptEngine,
	wsEngine *wsrules.InterceptEngine,
	grpcEngine *grpcrules.InterceptEngine,
) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	scope := connector.NewTargetScope()
	pl := proxy.NewPassthroughList()
	hold := common.NewHoldQueue()

	opts := []ServerOption{
		WithTargetScope(scope),
		WithPassthroughList(pl),
		WithHoldQueue(hold),
	}
	if httpEngine != nil {
		opts = append(opts, WithHTTPInterceptEngine(httpEngine))
	}
	if wsEngine != nil {
		opts = append(opts, WithWSInterceptEngine(wsEngine))
	}
	if grpcEngine != nil {
		opts = append(opts, WithGRPCInterceptEngine(grpcEngine))
	}

	s := newServer(ctx, nil, nil, nil, opts...)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func TestConfigure_InterceptRules_MergeAdd_HTTP(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID:        "rule-1",
						Enabled:   true,
						Protocol:  "http",
						Direction: "request",
						HTTP: &interceptHTTPConditions{
							PathPattern: "/api/admin.*",
							Methods:     []string{"POST", "PUT", "DELETE"},
							HeaderMatch: map[string]string{"Content-Type": "application/json"},
						},
					},
					{
						ID:        "rule-2",
						Enabled:   false,
						Protocol:  "http",
						Direction: "both",
						HTTP:      &interceptHTTPConditions{PathPattern: "/api/.*"},
					},
				},
			},
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
	if out.InterceptRules == nil {
		t.Fatal("intercept_rules is nil")
	}
	if out.InterceptRules.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.InterceptRules.TotalRules)
	}
	if out.InterceptRules.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.InterceptRules.EnabledRules)
	}

	rules := httpEngine.Rules()
	if len(rules) != 2 {
		t.Fatalf("engine rules = %d, want 2", len(rules))
	}
	var r1 *httprules.InterceptRule
	for i := range rules {
		if rules[i].ID == "rule-1" {
			r1 = &rules[i]
		}
	}
	if r1 == nil || !r1.Enabled || r1.Direction != httprules.DirectionRequest {
		t.Errorf("rule-1 unexpected shape: %+v", r1)
	}
}

func TestConfigure_InterceptRules_MergeRemove(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	httpEngine.SetRules([]httprules.InterceptRule{
		{ID: "keep", Enabled: true, Direction: httprules.DirectionBoth},
		{ID: "remove-me", Enabled: true, Direction: httprules.DirectionBoth},
	})
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "merge",
			InterceptRules: &configureInterceptRules{Remove: []string{"remove-me"}},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}
	rules := httpEngine.Rules()
	if len(rules) != 1 || rules[0].ID != "keep" {
		t.Errorf("unexpected rules after remove: %+v", rules)
	}
}

func TestConfigure_InterceptRules_MergeEnableDisable(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	httpEngine.SetRules([]httprules.InterceptRule{
		{ID: "rule-a", Enabled: false, Direction: httprules.DirectionBoth},
		{ID: "rule-b", Enabled: true, Direction: httprules.DirectionBoth},
	})
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Enable:  []string{"rule-a"},
				Disable: []string{"rule-b"},
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}

	rules := httpEngine.Rules()
	got := map[string]bool{}
	for _, r := range rules {
		got[r.ID] = r.Enabled
	}
	if !got["rule-a"] || got["rule-b"] {
		t.Errorf("unexpected enabled state: %+v", got)
	}
}

func TestConfigure_InterceptRules_Replace_PartitionsByProtocol(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	wsEngine := wsrules.NewInterceptEngine()
	grpcEngine := grpcrules.NewInterceptEngine()
	httpEngine.SetRules([]httprules.InterceptRule{{ID: "old-http", Enabled: true, Direction: httprules.DirectionBoth}})

	cs := configureSessionWithEngines(t, httpEngine, wsEngine, grpcEngine)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			InterceptRules: &configureInterceptRules{
				Rules: []interceptRuleInput{
					{ID: "h1", Enabled: true, Protocol: "http", Direction: "request", HTTP: &interceptHTTPConditions{PathPattern: "/.*"}},
					{ID: "w1", Enabled: true, Protocol: "ws", Direction: "send", WS: &interceptWSConditions{HostPattern: "example.com"}},
					{ID: "g1", Enabled: true, Protocol: "grpc", Direction: "send", GRPC: &interceptGRPCConditions{ServicePattern: "svc"}},
				},
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}

	if rs := httpEngine.Rules(); len(rs) != 1 || rs[0].ID != "h1" {
		t.Errorf("http rules: %+v", rs)
	}
	if rs := wsEngine.Rules(); len(rs) != 1 || rs[0].ID != "w1" {
		t.Errorf("ws rules: %+v", rs)
	}
	if rs := grpcEngine.Rules(); len(rs) != 1 || rs[0].ID != "g1" {
		t.Errorf("grpc rules: %+v", rs)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)
	if out.InterceptRules == nil || out.InterceptRules.TotalRules != 3 || out.InterceptRules.EnabledRules != 3 {
		t.Errorf("aggregate counts: %+v", out.InterceptRules)
	}
}

func TestConfigure_InterceptRules_ReplaceEmpty_ClearsAll(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	httpEngine.SetRules([]httprules.InterceptRule{{ID: "x", Enabled: true, Direction: httprules.DirectionBoth}})
	cs := configureSessionWithEngines(t, httpEngine, wsrules.NewInterceptEngine(), grpcrules.NewInterceptEngine())
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "replace",
			InterceptRules: &configureInterceptRules{Rules: []interceptRuleInput{}},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}
	if rs := httpEngine.Rules(); len(rs) != 0 {
		t.Errorf("expected empty engine, got %d rules", len(rs))
	}
}

func TestConfigure_InterceptRules_AllEnginesNil_ReturnsError(t *testing.T) {
	cs := configureSessionWithEngines(t, nil, nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{{ID: "x", Enabled: true, Protocol: "http", Direction: "both", HTTP: &interceptHTTPConditions{}}},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when all engines nil")
	}
}

func TestConfigure_InterceptRules_AddInvalidPattern(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{ID: "bad", Enabled: true, Protocol: "http", Direction: "request",
						HTTP: &interceptHTTPConditions{PathPattern: "(unbalanced"}},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestConfigure_InterceptRules_MergeAdd_WS(t *testing.T) {
	wsEngine := wsrules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, nil, wsEngine, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{{
					ID: "ws-1", Enabled: true, Protocol: "ws", Direction: "send",
					WS: &interceptWSConditions{
						HostPattern:  "example\\.com",
						OpcodeFilter: []string{"text", "binary"},
					},
				}},
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}
	rules := wsEngine.Rules()
	if len(rules) != 1 || rules[0].ID != "ws-1" {
		t.Fatalf("ws rules: %+v", rules)
	}
	if len(rules[0].OpcodeFilter) != 2 {
		t.Errorf("opcode filter: %+v", rules[0].OpcodeFilter)
	}
}

func TestConfigure_InterceptRules_MergeAdd_GRPC(t *testing.T) {
	grpcEngine := grpcrules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, nil, nil, grpcEngine)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{{
					ID: "g1", Enabled: true, Protocol: "grpc", Direction: "send",
					GRPC: &interceptGRPCConditions{
						ServicePattern: "auth\\..*",
						HeaderMatch:    map[string]string{"x-tenant": ".*"},
					},
				}},
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}
	rules := grpcEngine.Rules()
	if len(rules) != 1 || rules[0].ID != "g1" {
		t.Fatalf("grpc rules: %+v", rules)
	}
}

func TestConfigure_InterceptRules_DefaultProtocolHTTP(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{{
					// Protocol omitted — defaults to "http".
					ID: "default", Enabled: true, Direction: "request",
					HTTP: &interceptHTTPConditions{PathPattern: "/.*"},
				}},
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v", err, result.IsError)
	}
	if rs := httpEngine.Rules(); len(rs) != 1 || rs[0].ID != "default" {
		t.Errorf("expected default-protocol routing to http engine, got %+v", rs)
	}
}

func TestConfigure_InterceptRules_UnknownProtocol(t *testing.T) {
	cs := configureSessionWithEngines(t, httprules.NewInterceptEngine(), nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{{ID: "x", Enabled: true, Protocol: "tcp", Direction: "both"}},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for unknown protocol")
	}
}

// TestConfigure_InterceptRules_MergeAdd_RejectsDuplicateID verifies the
// duplicate-ID rejection contract preserved from the legacy single-engine
// intercept.Engine.AddRule (USK-692 review F-1). Adding a rule whose ID
// already exists in any per-protocol engine must surface an error
// instead of silently appending a second copy.
func TestConfigure_InterceptRules_MergeAdd_RejectsDuplicateID(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	httpEngine.SetRules([]httprules.InterceptRule{
		{ID: "dup", Enabled: true, Direction: httprules.DirectionBoth},
	})
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID: "dup", Enabled: true, Protocol: "http", Direction: "both",
						HTTP: &interceptHTTPConditions{PathPattern: "/.*"},
					},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for duplicate rule ID")
	}
	body := flattenContent(result.Content)
	if !strings.Contains(body, "dup") || !strings.Contains(body, "already exists") {
		t.Errorf("error text should mention id and 'already exists', got %q", body)
	}
	// Must not have appended a second copy.
	if got := len(httpEngine.Rules()); got != 1 {
		t.Errorf("engine rule count after rejected add = %d, want 1", got)
	}
}

// TestConfigure_InterceptRules_MergeAdd_RejectsCrossEngineDuplicateID
// verifies the duplicate-ID check is global across the three
// per-protocol engines, not per-engine. An ID present in the WS engine
// must reject an HTTP add of the same ID.
func TestConfigure_InterceptRules_MergeAdd_RejectsCrossEngineDuplicateID(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	wsEngine := wsrules.NewInterceptEngine()
	wsEngine.SetRules([]wsrules.InterceptRule{
		{ID: "shared", Enabled: true},
	})
	cs := configureSessionWithEngines(t, httpEngine, wsEngine, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID: "shared", Enabled: true, Protocol: "http", Direction: "both",
						HTTP: &interceptHTTPConditions{PathPattern: "/.*"},
					},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for cross-engine duplicate rule ID")
	}
}

// TestConfigure_InterceptRules_MergeRemove_NonexistentID verifies the
// missing-ID error contract preserved from the legacy single engine
// (USK-692 review F-2). Removing an ID not owned by any engine must
// surface an error instead of silently no-op'ing.
func TestConfigure_InterceptRules_MergeRemove_NonexistentID(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "merge",
			InterceptRules: &configureInterceptRules{Remove: []string{"ghost"}},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent remove ID")
	}
	body := flattenContent(result.Content)
	if !strings.Contains(body, "ghost") || !strings.Contains(body, "not found") {
		t.Errorf("error text should mention id and 'not found', got %q", body)
	}
}

// TestConfigure_InterceptRules_MergeEnable_NonexistentID verifies the
// missing-ID error contract on enable/disable (USK-692 review F-2).
func TestConfigure_InterceptRules_MergeEnable_NonexistentID(t *testing.T) {
	httpEngine := httprules.NewInterceptEngine()
	cs := configureSessionWithEngines(t, httpEngine, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation:      "merge",
			InterceptRules: &configureInterceptRules{Enable: []string{"ghost"}},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent enable ID")
	}
}

func TestConfigure_InterceptQueue_TimeoutAndBehavior(t *testing.T) {
	cs := configureSessionWithEngines(t, httprules.NewInterceptEngine(), nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutMs:       intPtr(30000),
				TimeoutBehavior: "auto_drop",
			},
		}),
	})
	if err != nil || result.IsError {
		t.Fatalf("CallTool: err=%v isError=%v content=%v", err, result.IsError, result.Content)
	}
	var out configureResult
	configureUnmarshalResult(t, result, &out)
	if out.InterceptQueue == nil {
		t.Fatal("intercept_queue is nil")
	}
	if out.InterceptQueue.TimeoutMs != 30000 {
		t.Errorf("timeout_ms = %d, want 30000", out.InterceptQueue.TimeoutMs)
	}
	if out.InterceptQueue.TimeoutBehavior != "auto_drop" {
		t.Errorf("timeout_behavior = %q, want auto_drop", out.InterceptQueue.TimeoutBehavior)
	}
}

func TestConfigure_InterceptQueue_RejectsBadBehavior(t *testing.T) {
	cs := configureSessionWithEngines(t, httprules.NewInterceptEngine(), nil, nil)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{TimeoutBehavior: "explode"},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid timeout_behavior")
	}
	body := flattenContent(result.Content)
	if !strings.Contains(body, "explode") {
		t.Errorf("error text should mention the bad value, got %q", body)
	}
}

func TestProxyStart_InterceptRulesInputSerialization(t *testing.T) {
	in := []interceptRuleInput{
		{
			ID: "r1", Enabled: true, Protocol: "http", Direction: "request",
			HTTP: &interceptHTTPConditions{
				HostPattern: "example\\.com",
				PathPattern: "/api/.*",
				Methods:     []string{"POST"},
				HeaderMatch: map[string]string{"X-Foo": "bar"},
			},
		},
		{
			ID: "r2", Enabled: true, Protocol: "ws", Direction: "send",
			WS: &interceptWSConditions{HostPattern: "example\\.com", OpcodeFilter: []string{"text"}},
		},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip []interceptRuleInput
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundtrip) != 2 || roundtrip[0].HTTP == nil || roundtrip[1].WS == nil {
		t.Errorf("roundtrip lost discriminator: %+v", roundtrip)
	}
}

// flattenContent reduces the gomcp Content slice to a single string for
// substring assertions in error-path tests.
func flattenContent(content []gomcp.Content) string {
	var b strings.Builder
	for _, c := range content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
