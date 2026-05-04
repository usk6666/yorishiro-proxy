package mcp

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// setupTransformTestSession creates a connected MCP client session for
// auto-transform rule tests. The engine is the per-protocol HTTP transform
// engine used by the configure_tool's auto_transform schema.
func setupTransformTestSession(t *testing.T, engine *httprules.TransformEngine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	scope := connector.NewTargetScope()
	pl := connector.NewPassthroughList()

	var opts []ServerOption
	opts = append(opts, WithTargetScope(scope))
	opts = append(opts, WithPassthroughList(pl))
	if engine != nil {
		opts = append(opts, WithTransformHTTPEngine(engine))
	}

	s := newServer(ctx, nil, nil, nil, opts...)
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

// findEngineRule scans the engine for a rule with the given ID.
func findEngineRule(engine *httprules.TransformEngine, id string) (httprules.TransformRule, bool) {
	for _, r := range engine.Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return httprules.TransformRule{}, false
}

func TestConfigure_AutoTransform_MergeAdd(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "rule-1",
						Enabled:   true,
						Priority:  10,
						Direction: "request",
						Conditions: transformConditionsInput{
							URLPattern: "/api/admin.*",
							Methods:    []string{"POST", "PUT", "DELETE"},
						},
						Action: transformActionInput{
							Type:   "set_header",
							Header: "Authorization",
							Value:  "Bearer test-token",
						},
					},
					{
						ID:        "rule-2",
						Enabled:   false,
						Priority:  20,
						Direction: "response",
						Conditions: transformConditionsInput{
							URLPattern: "/api/.*",
						},
						Action: transformActionInput{
							Type:   "remove_header",
							Header: "Content-Security-Policy",
						},
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

	if out.AutoTransform == nil {
		t.Fatal("AutoTransform result is nil")
	}
	if out.AutoTransform.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.AutoTransform.TotalRules)
	}
	if out.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.AutoTransform.EnabledRules)
	}

	r, ok := findEngineRule(engine, "rule-1")
	if !ok {
		t.Fatal("rule-1 not present in engine")
	}
	if !r.Enabled {
		t.Error("rule-1 should be enabled")
	}
	if r.Direction != httprules.DirectionRequest {
		t.Errorf("direction = %q, want %q", r.Direction, httprules.DirectionRequest)
	}
	if r.ActionType != httprules.TransformSetHeader {
		t.Errorf("action type = %v, want %v", r.ActionType, httprules.TransformSetHeader)
	}
}

func TestConfigure_AutoTransform_MergeRemove(t *testing.T) {
	engine := httprules.NewTransformEngine()
	addr1, _ := httprules.CompileTransformRule("keep", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Keep", "true", "", "")
	addr2, _ := httprules.CompileTransformRule("remove-me", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Remove", "true", "", "")
	engine.AddRule(*addr1)
	engine.AddRule(*addr2)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Remove: []string{"remove-me"},
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

	if out.AutoTransform.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.AutoTransform.TotalRules)
	}

	if _, ok := findEngineRule(engine, "remove-me"); ok {
		t.Error("remove-me should have been removed")
	}
	if _, ok := findEngineRule(engine, "keep"); !ok {
		t.Error("keep should still exist")
	}
}

func TestConfigure_AutoTransform_MergeEnable(t *testing.T) {
	engine := httprules.NewTransformEngine()
	rule, _ := httprules.CompileTransformRule("r1", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Test", "true", "", "")
	rule.Enabled = false
	engine.AddRule(*rule)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Enable: []string{"r1"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	r, ok := findEngineRule(engine, "r1")
	if !ok {
		t.Fatal("r1 not found")
	}
	if !r.Enabled {
		t.Error("rule should now be enabled")
	}
}

func TestConfigure_AutoTransform_MergeDisable(t *testing.T) {
	engine := httprules.NewTransformEngine()
	rule, _ := httprules.CompileTransformRule("r1", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Test", "true", "", "")
	rule.Enabled = true
	engine.AddRule(*rule)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Disable: []string{"r1"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	r, ok := findEngineRule(engine, "r1")
	if !ok {
		t.Fatal("r1 not found")
	}
	if r.Enabled {
		t.Error("rule should now be disabled")
	}
}

func TestConfigure_AutoTransform_Replace(t *testing.T) {
	engine := httprules.NewTransformEngine()
	old, _ := httprules.CompileTransformRule("old-rule", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Old", "true", "", "")
	engine.AddRule(*old)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{
					{
						ID:        "new-rule-1",
						Enabled:   true,
						Priority:  5,
						Direction: "request",
						Action: transformActionInput{
							Type:   "set_header",
							Header: "X-New",
							Value:  "v1",
						},
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

	if _, ok := findEngineRule(engine, "old-rule"); ok {
		t.Error("old-rule should have been removed by replace")
	}
	if _, ok := findEngineRule(engine, "new-rule-1"); !ok {
		t.Error("new-rule-1 should be present after replace")
	}
}

func TestConfigure_AutoTransform_ReplaceEmpty(t *testing.T) {
	engine := httprules.NewTransformEngine()
	old, _ := httprules.CompileTransformRule("old-rule", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X-Old", "true", "", "")
	engine.AddRule(*old)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if got := len(engine.Rules()); got != 0 {
		t.Errorf("rules len = %d, want 0", got)
	}
}

func TestConfigure_AutoTransform_NilPipeline(t *testing.T) {
	cs := setupTransformTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{ID: "r", Enabled: true, Priority: 0, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X", Value: "1"}},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error when transform engine is nil")
	}
}

func TestConfigure_AutoTransform_MergeAddDuplicate(t *testing.T) {
	engine := httprules.NewTransformEngine()
	rule, _ := httprules.CompileTransformRule("dup", 0, httprules.DirectionRequest, "", "", nil, httprules.TransformAddHeader, "X", "1", "", "")
	engine.AddRule(*rule)

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{ID: "dup", Enabled: true, Priority: 1, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X", Value: "2"}},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for duplicate ID")
	}
}

func TestConfigure_AutoTransform_MergeAddInvalidPattern(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "bad", Enabled: true, Priority: 1, Direction: "request",
						Conditions: transformConditionsInput{URLPattern: "[unbalanced"},
						Action:     transformActionInput{Type: "add_header", Header: "X", Value: "1"},
					},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex")
	}
}

func TestConfigure_AutoTransform_MergeRemoveNonexistent(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Remove: []string{"missing"},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule remove")
	}
}

func TestConfigure_AutoTransform_MergeEnableNonexistent(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Enable: []string{"missing"},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule enable")
	}
}

func TestTransformHelpers_ToFromRoundTrip(t *testing.T) {
	input := transformRuleInput{
		ID:        "r1",
		Enabled:   true,
		Priority:  5,
		Direction: "both",
		Conditions: transformConditionsInput{
			URLPattern: "/api/.*",
			Methods:    []string{"POST", "PUT"},
		},
		Action: transformActionInput{
			Type:   "set_header",
			Header: "Authorization",
			Value:  "Bearer token",
		},
	}

	rule, err := toTransformRule(input)
	if err != nil {
		t.Fatalf("toTransformRule: %v", err)
	}

	if rule.ID != "r1" {
		t.Errorf("ID = %q, want %q", rule.ID, "r1")
	}
	if rule.Direction != httprules.DirectionBoth {
		t.Errorf("Direction = %q, want %q", rule.Direction, httprules.DirectionBoth)
	}
	if rule.Priority != 5 {
		t.Errorf("Priority = %d, want 5", rule.Priority)
	}
	if rule.ActionType != httprules.TransformSetHeader {
		t.Errorf("Action type = %v, want %v", rule.ActionType, httprules.TransformSetHeader)
	}

	output := fromTransformRule(rule)

	if output.ID != "r1" {
		t.Errorf("output ID = %q, want %q", output.ID, "r1")
	}
	if output.Direction != "both" {
		t.Errorf("output Direction = %q, want %q", output.Direction, "both")
	}
	if output.Conditions.URLPattern != "/api/.*" {
		t.Errorf("output URLPattern = %q, want %q", output.Conditions.URLPattern, "/api/.*")
	}
	if output.Action.Type != "set_header" {
		t.Errorf("output Action.Type = %q, want %q", output.Action.Type, "set_header")
	}
	if output.Action.Header != "Authorization" {
		t.Errorf("output Action.Header = %q, want %q", output.Action.Header, "Authorization")
	}
}

func TestConfigure_AutoTransform_ReplaceBodyAction(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "replace-host",
						Enabled:   true,
						Priority:  10,
						Direction: "request",
						Action: transformActionInput{
							Type:    "replace_body",
							Pattern: "production-host",
							Value:   "staging-host",
						},
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

	r, ok := findEngineRule(engine, "replace-host")
	if !ok {
		t.Fatal("replace-host not found")
	}
	if r.ActionType != httprules.TransformReplaceBody {
		t.Errorf("action type = %v, want TransformReplaceBody", r.ActionType)
	}
}

func TestConfigure_AutoTransform_PriorityPreserved(t *testing.T) {
	engine := httprules.NewTransformEngine()
	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "low-prio",
						Enabled:   true,
						Priority:  100,
						Direction: "request",
						Action:    transformActionInput{Type: "add_header", Header: "X-A", Value: "1"},
					},
					{
						ID:        "high-prio",
						Enabled:   true,
						Priority:  1,
						Direction: "request",
						Action:    transformActionInput{Type: "add_header", Header: "X-B", Value: "2"},
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

	rules := engine.Rules()
	if len(rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(rules))
	}
	if rules[0].ID != "high-prio" {
		t.Errorf("first rule = %q, want high-prio", rules[0].ID)
	}
}
