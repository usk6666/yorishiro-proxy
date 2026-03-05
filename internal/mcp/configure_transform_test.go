package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
)

// setupTransformTestSession creates a connected MCP client session for auto-transform rule tests.
func setupTransformTestSession(t *testing.T, pipeline *rules.Pipeline) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	var opts []ServerOption
	opts = append(opts, WithCaptureScope(scope))
	opts = append(opts, WithPassthroughList(pl))
	if pipeline != nil {
		opts = append(opts, WithTransformPipeline(pipeline))
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

func TestConfigure_AutoTransform_MergeAdd(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

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
							HeaderMatch: map[string]string{
								"Content-Type": "application/json",
							},
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

	if out.Status != "configured" {
		t.Errorf("status = %q, want %q", out.Status, "configured")
	}
	if out.AutoTransform == nil {
		t.Fatal("auto_transform is nil")
	}
	if out.AutoTransform.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.AutoTransform.TotalRules)
	}
	if out.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.AutoTransform.EnabledRules)
	}

	// Verify rule was actually added.
	r, err := pipeline.GetRule("rule-1")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if !r.Enabled {
		t.Error("rule-1 should be enabled")
	}
	if r.Direction != rules.DirectionRequest {
		t.Errorf("direction = %q, want %q", r.Direction, rules.DirectionRequest)
	}
	if r.Action.Type != rules.ActionSetHeader {
		t.Errorf("action type = %q, want %q", r.Action.Type, rules.ActionSetHeader)
	}
}

func TestConfigure_AutoTransform_MergeRemove(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "keep", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Keep", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "remove-me", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Remove", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

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

	// Verify removal.
	_, err = pipeline.GetRule("remove-me")
	if err == nil {
		t.Error("remove-me should have been removed")
	}
	_, err = pipeline.GetRule("keep")
	if err != nil {
		t.Error("keep should still exist")
	}
}

func TestConfigure_AutoTransform_MergeEnable(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "r1", Enabled: false, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Test", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.AutoTransform.EnabledRules)
	}

	r, _ := pipeline.GetRule("r1")
	if !r.Enabled {
		t.Error("r1 should be enabled")
	}
}

func TestConfigure_AutoTransform_MergeDisable(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "r1", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Test", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.EnabledRules != 0 {
		t.Errorf("enabled_rules = %d, want 0", out.AutoTransform.EnabledRules)
	}

	r, _ := pipeline.GetRule("r1")
	if r.Enabled {
		t.Error("r1 should be disabled")
	}
}

func TestConfigure_AutoTransform_MergeCombined(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "to-remove", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Remove", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "to-disable", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Disable", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "new-rule", Enabled: true, Direction: "request",
						Action: transformActionInput{
							Type:   "set_header",
							Header: "X-New",
							Value:  "new-value",
						},
					},
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

	if out.AutoTransform.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.AutoTransform.TotalRules)
	}
	if out.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.AutoTransform.EnabledRules)
	}
}

func TestConfigure_AutoTransform_Replace(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "old-1", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Old1", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "old-2", Enabled: true, Direction: rules.DirectionResponse,
		Action: rules.Action{Type: rules.ActionRemoveHeader, Header: "X-Old2"},
	})

	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{
					{
						ID:        "new-1",
						Enabled:   true,
						Direction: "both",
						Conditions: transformConditionsInput{
							URLPattern: "/api/.*",
						},
						Action: transformActionInput{
							Type:   "set_header",
							Header: "X-Proxy",
							Value:  "yorishiro",
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

	if out.AutoTransform.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.AutoTransform.TotalRules)
	}

	// Old rules should be gone.
	_, err = pipeline.GetRule("old-1")
	if err == nil {
		t.Error("old-1 should have been replaced")
	}

	// New rule should exist.
	r, err := pipeline.GetRule("new-1")
	if err != nil {
		t.Fatalf("GetRule new-1: %v", err)
	}
	if r.Direction != rules.DirectionBoth {
		t.Errorf("direction = %q, want %q", r.Direction, rules.DirectionBoth)
	}
}

func TestConfigure_AutoTransform_ReplaceEmpty(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "r1", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Test", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.TotalRules != 0 {
		t.Errorf("total_rules = %d, want 0", out.AutoTransform.TotalRules)
	}
}

func TestConfigure_AutoTransform_NilPipeline(t *testing.T) {
	cs := setupTransformTestSession(t, nil) // nil pipeline

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "r1", Enabled: true, Direction: "request",
						Action: transformActionInput{
							Type:   "add_header",
							Header: "X-Test",
							Value:  "true",
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
		t.Fatal("expected error for nil pipeline, got success")
	}
}

func TestConfigure_AutoTransform_NilPipelineReplace(t *testing.T) {
	cs := setupTransformTestSession(t, nil) // nil pipeline

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{
					{
						ID: "r1", Enabled: true, Direction: "request",
						Action: transformActionInput{
							Type:   "add_header",
							Header: "X-Test",
							Value:  "true",
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
		t.Fatal("expected error for nil pipeline in replace, got success")
	}
}

func TestConfigure_AutoTransform_MergeAddDuplicate(t *testing.T) {
	pipeline := rules.NewPipeline()
	pipeline.AddRule(rules.Rule{
		ID: "r1", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Test", Value: "true"},
	})

	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "r1", Enabled: true, Direction: "request",
						Action: transformActionInput{
							Type:   "add_header",
							Header: "X-Dup",
							Value:  "true",
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
		t.Fatal("expected error for duplicate rule ID, got success")
	}
}

func TestConfigure_AutoTransform_MergeAddInvalidPattern(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "bad",
						Enabled:   true,
						Direction: "request",
						Conditions: transformConditionsInput{
							URLPattern: "[invalid",
						},
						Action: transformActionInput{
							Type:   "add_header",
							Header: "X-Test",
							Value:  "true",
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

func TestConfigure_AutoTransform_MergeRemoveNonexistent(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
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

func TestConfigure_AutoTransform_MergeEnableNonexistent(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
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

// TestProxyStart_AutoTransformInputSerialization tests that auto-transform rules can be serialized for proxy_start.
func TestProxyStart_AutoTransformInputSerialization(t *testing.T) {
	input := proxyStartInput{
		AutoTransform: []transformRuleInput{
			{
				ID:        "rule-1",
				Enabled:   true,
				Priority:  10,
				Direction: "request",
				Conditions: transformConditionsInput{
					URLPattern: "/api/admin.*",
					Methods:    []string{"POST", "PUT"},
					HeaderMatch: map[string]string{
						"Content-Type": "application/json",
					},
				},
				Action: transformActionInput{
					Type:   "set_header",
					Header: "Authorization",
					Value:  "Bearer token",
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

	if len(decoded.AutoTransform) != 1 {
		t.Fatalf("AutoTransform len = %d, want 1", len(decoded.AutoTransform))
	}
	if decoded.AutoTransform[0].ID != "rule-1" {
		t.Errorf("ID = %q, want %q", decoded.AutoTransform[0].ID, "rule-1")
	}
	if decoded.AutoTransform[0].Conditions.URLPattern != "/api/admin.*" {
		t.Errorf("URLPattern = %q, want %q", decoded.AutoTransform[0].Conditions.URLPattern, "/api/admin.*")
	}
	if decoded.AutoTransform[0].Action.Type != "set_header" {
		t.Errorf("Action.Type = %q, want %q", decoded.AutoTransform[0].Action.Type, "set_header")
	}
	if decoded.AutoTransform[0].Priority != 10 {
		t.Errorf("Priority = %d, want 10", decoded.AutoTransform[0].Priority)
	}
}

func TestTransformHelpers_ToFromRoundTrip(t *testing.T) {
	input := transformRuleInput{
		ID:        "r1",
		Enabled:   true,
		Priority:  5,
		Direction: "both",
		Conditions: transformConditionsInput{
			URLPattern:  "/api/.*",
			Methods:     []string{"POST", "PUT"},
			HeaderMatch: map[string]string{"Content-Type": "json"},
		},
		Action: transformActionInput{
			Type:   "set_header",
			Header: "Authorization",
			Value:  "Bearer token",
		},
	}

	rule := toTransformRule(input)

	if rule.ID != "r1" {
		t.Errorf("ID = %q, want %q", rule.ID, "r1")
	}
	if rule.Direction != rules.DirectionBoth {
		t.Errorf("Direction = %q, want %q", rule.Direction, rules.DirectionBoth)
	}
	if rule.Priority != 5 {
		t.Errorf("Priority = %d, want 5", rule.Priority)
	}
	if rule.Action.Type != rules.ActionSetHeader {
		t.Errorf("Action.Type = %q, want %q", rule.Action.Type, rules.ActionSetHeader)
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

func TestTransformHelpers_FromTransformRulesNil(t *testing.T) {
	out := fromTransformRules(nil)
	if out != nil {
		t.Errorf("fromTransformRules(nil) = %v, want nil", out)
	}
}

func TestConfigure_AutoTransform_ReplaceBodyAction(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:         "replace-host",
						Enabled:    true,
						Priority:   10,
						Direction:  "request",
						Conditions: transformConditionsInput{},
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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.AutoTransform.TotalRules)
	}

	r, err := pipeline.GetRule("replace-host")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if r.Action.Type != rules.ActionReplaceBody {
		t.Errorf("action type = %q, want %q", r.Action.Type, rules.ActionReplaceBody)
	}
}

func TestConfigure_AutoTransform_PriorityPreserved(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "high-priority", Enabled: true, Priority: 1, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X-First", Value: "1"},
					},
					{
						ID: "low-priority", Enabled: true, Priority: 100, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X-Last", Value: "100"},
					},
					{
						ID: "mid-priority", Enabled: true, Priority: 50, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X-Mid", Value: "50"},
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

	if out.AutoTransform.TotalRules != 3 {
		t.Errorf("total_rules = %d, want 3", out.AutoTransform.TotalRules)
	}

	// Verify rules are stored (pipeline maintains priority order internally).
	rulesList := pipeline.Rules()
	if len(rulesList) != 3 {
		t.Fatalf("rules count = %d, want 3", len(rulesList))
	}
	// Pipeline sorts by priority: lowest first.
	if rulesList[0].ID != "high-priority" {
		t.Errorf("first rule = %q, want %q", rulesList[0].ID, "high-priority")
	}
	if rulesList[1].ID != "mid-priority" {
		t.Errorf("second rule = %q, want %q", rulesList[1].ID, "mid-priority")
	}
	if rulesList[2].ID != "low-priority" {
		t.Errorf("third rule = %q, want %q", rulesList[2].ID, "low-priority")
	}
}
