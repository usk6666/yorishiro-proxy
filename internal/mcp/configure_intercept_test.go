package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
)

// setupInterceptTestSession creates a connected MCP client session for intercept rule tests.
func setupInterceptTestSession(t *testing.T, engine *intercept.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	var opts []ServerOption
	opts = append(opts, WithCaptureScope(scope))
	opts = append(opts, WithPassthroughList(pl))
	if engine != nil {
		opts = append(opts, WithInterceptEngine(engine))
	}

	s := NewServer(ctx, nil, nil, nil, opts...)
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

func TestConfigure_InterceptRules_MergeAdd(t *testing.T) {
	engine := intercept.NewEngine()
	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID:        "rule-1",
						Enabled:   true,
						Direction: "request",
						Conditions: interceptConditionsInput{
							PathPattern: "/api/admin.*",
							Methods:    []string{"POST", "PUT", "DELETE"},
							HeaderMatch: map[string]string{
								"Content-Type": "application/json",
							},
						},
					},
					{
						ID:        "rule-2",
						Enabled:   false,
						Direction: "both",
						Conditions: interceptConditionsInput{
							PathPattern: "/api/.*",
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

	// Verify rule was actually added.
	r, err := engine.GetRule("rule-1")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if !r.Enabled {
		t.Error("rule-1 should be enabled")
	}
	if r.Direction != intercept.DirectionRequest {
		t.Errorf("direction = %q, want %q", r.Direction, intercept.DirectionRequest)
	}
}

func TestConfigure_InterceptRules_MergeRemove(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "keep", Enabled: true, Direction: intercept.DirectionRequest,
	})
	engine.AddRule(intercept.Rule{
		ID: "remove-me", Enabled: true, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
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

	if out.InterceptRules.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.InterceptRules.TotalRules)
	}

	// Verify removal.
	_, err = engine.GetRule("remove-me")
	if err == nil {
		t.Error("remove-me should have been removed")
	}
	_, err = engine.GetRule("keep")
	if err != nil {
		t.Error("keep should still exist")
	}
}

func TestConfigure_InterceptRules_MergeEnable(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "r1", Enabled: false, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.InterceptRules.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.InterceptRules.EnabledRules)
	}

	r, _ := engine.GetRule("r1")
	if !r.Enabled {
		t.Error("r1 should be enabled")
	}
}

func TestConfigure_InterceptRules_MergeDisable(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "r1", Enabled: true, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.InterceptRules.EnabledRules != 0 {
		t.Errorf("enabled_rules = %d, want 0", out.InterceptRules.EnabledRules)
	}

	r, _ := engine.GetRule("r1")
	if r.Enabled {
		t.Error("r1 should be disabled")
	}
}

func TestConfigure_InterceptRules_MergeCombined(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "to-remove", Enabled: true, Direction: intercept.DirectionRequest,
	})
	engine.AddRule(intercept.Rule{
		ID: "to-disable", Enabled: true, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{ID: "new-rule", Enabled: true, Direction: "request"},
				},
				Remove:  []string{"to-remove"},
				Disable: []string{"to-disable"},
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

	if out.InterceptRules.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.InterceptRules.TotalRules)
	}
	if out.InterceptRules.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.InterceptRules.EnabledRules)
	}
}

func TestConfigure_InterceptRules_Replace(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "old-1", Enabled: true, Direction: intercept.DirectionRequest,
	})
	engine.AddRule(intercept.Rule{
		ID: "old-2", Enabled: true, Direction: intercept.DirectionResponse,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			InterceptRules: &configureInterceptRules{
				Rules: []interceptRuleInput{
					{
						ID:        "new-1",
						Enabled:   true,
						Direction: "both",
						Conditions: interceptConditionsInput{
							PathPattern: "/api/.*",
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

	if out.InterceptRules.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.InterceptRules.TotalRules)
	}

	// Old rules should be gone.
	_, err = engine.GetRule("old-1")
	if err == nil {
		t.Error("old-1 should have been replaced")
	}
}

func TestConfigure_InterceptRules_ReplaceEmpty(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "r1", Enabled: true, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			InterceptRules: &configureInterceptRules{
				Rules: []interceptRuleInput{},
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

	if out.InterceptRules.TotalRules != 0 {
		t.Errorf("total_rules = %d, want 0", out.InterceptRules.TotalRules)
	}
}

func TestConfigure_InterceptRules_NilEngine(t *testing.T) {
	cs := setupInterceptTestSession(t, nil) // nil engine

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{ID: "r1", Enabled: true, Direction: "request"},
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil engine, got success")
	}
}

func TestConfigure_InterceptRules_NilEngineReplace(t *testing.T) {
	cs := setupInterceptTestSession(t, nil) // nil engine

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			InterceptRules: &configureInterceptRules{
				Rules: []interceptRuleInput{
					{ID: "r1", Enabled: true, Direction: "request"},
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil engine in replace, got success")
	}
}

func TestConfigure_InterceptRules_MergeAddDuplicate(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID: "r1", Enabled: true, Direction: intercept.DirectionRequest,
	})

	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{ID: "r1", Enabled: true, Direction: "request"},
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for duplicate rule ID, got success")
	}
}

func TestConfigure_InterceptRules_MergeAddInvalidPattern(t *testing.T) {
	engine := intercept.NewEngine()
	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID:        "bad",
						Enabled:   true,
						Direction: "request",
						Conditions: interceptConditionsInput{
							PathPattern: "[invalid",
						},
					},
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex pattern, got success")
	}
}

func TestConfigure_InterceptRules_MergeRemoveNonexistent(t *testing.T) {
	engine := intercept.NewEngine()
	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Remove: []string{"nonexistent"},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule removal, got success")
	}
}

func TestConfigure_InterceptRules_MergeEnableNonexistent(t *testing.T) {
	engine := intercept.NewEngine()
	cs := setupInterceptTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Enable: []string{"nonexistent"},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule enable, got success")
	}
}

// TestProxyStart_InterceptRules tests that intercept rules can be set via proxy_start.
// Note: We can't fully test proxy_start since it requires a real manager,
// but we test the JSON deserialization and structure via raw marshaling.
func TestProxyStart_InterceptRulesInputSerialization(t *testing.T) {
	input := proxyStartInput{
		InterceptRules: []interceptRuleInput{
			{
				ID:        "rule-1",
				Enabled:   true,
				Direction: "request",
				Conditions: interceptConditionsInput{
					PathPattern: "/api/admin.*",
					Methods:    []string{"POST", "PUT"},
					HeaderMatch: map[string]string{
						"Content-Type": "application/json",
					},
				},
			},
		},
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded proxyStartInput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.InterceptRules) != 1 {
		t.Fatalf("InterceptRules len = %d, want 1", len(decoded.InterceptRules))
	}
	if decoded.InterceptRules[0].ID != "rule-1" {
		t.Errorf("ID = %q, want %q", decoded.InterceptRules[0].ID, "rule-1")
	}
	if decoded.InterceptRules[0].Conditions.PathPattern != "/api/admin.*" {
		t.Errorf("PathPattern = %q, want %q", decoded.InterceptRules[0].Conditions.PathPattern, "/api/admin.*")
	}
}

func TestInterceptHelpers_ToFromRoundTrip(t *testing.T) {
	input := interceptRuleInput{
		ID:        "r1",
		Enabled:   true,
		Direction: "both",
		Conditions: interceptConditionsInput{
			PathPattern:  "/api/.*",
			Methods:     []string{"POST", "PUT"},
			HeaderMatch: map[string]string{"Content-Type": "json"},
		},
	}

	rule := toInterceptRule(input)

	if rule.ID != "r1" {
		t.Errorf("ID = %q, want %q", rule.ID, "r1")
	}
	if rule.Direction != intercept.DirectionBoth {
		t.Errorf("Direction = %q, want %q", rule.Direction, intercept.DirectionBoth)
	}

	output := fromInterceptRule(rule)

	if output.ID != "r1" {
		t.Errorf("output ID = %q, want %q", output.ID, "r1")
	}
	if output.Direction != "both" {
		t.Errorf("output Direction = %q, want %q", output.Direction, "both")
	}
	if output.Conditions.PathPattern != "/api/.*" {
		t.Errorf("output PathPattern = %q, want %q", output.Conditions.PathPattern, "/api/.*")
	}
}

func TestInterceptHelpers_FromInterceptRulesNil(t *testing.T) {
	out := fromInterceptRules(nil)
	if out != nil {
		t.Errorf("fromInterceptRules(nil) = %v, want nil", out)
	}
}
