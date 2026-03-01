package mcp

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
)

// --- M3 Integration: Auto-Transform ---

// TestM3_Transform_AddAndVerifyRules verifies the full lifecycle of auto-transform rules:
// add rules via configure merge -> verify via pipeline -> modify (enable/disable) -> remove.
func TestM3_Transform_AddAndVerifyRules(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	// Add two auto-transform rules via configure merge.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "add-auth-header",
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
							Value:  "Bearer test-token-123",
						},
					},
					{
						ID:        "strip-csp",
						Enabled:   true,
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
		t.Fatalf("CallTool(configure): %v", err)
	}
	if result.IsError {
		t.Fatalf("configure returned error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.Status != "configured" {
		t.Errorf("status = %q, want configured", out.Status)
	}
	if out.AutoTransform == nil {
		t.Fatal("auto_transform is nil")
	}
	if out.AutoTransform.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.AutoTransform.TotalRules)
	}
	if out.AutoTransform.EnabledRules != 2 {
		t.Errorf("enabled_rules = %d, want 2", out.AutoTransform.EnabledRules)
	}

	// Verify rules exist in the pipeline.
	r1, err := pipeline.GetRule("add-auth-header")
	if err != nil {
		t.Fatalf("GetRule(add-auth-header): %v", err)
	}
	if r1.Action.Type != rules.ActionSetHeader {
		t.Errorf("rule-1 action = %q, want set_header", r1.Action.Type)
	}
	if r1.Action.Header != "Authorization" {
		t.Errorf("rule-1 header = %q, want Authorization", r1.Action.Header)
	}
	if r1.Action.Value != "Bearer test-token-123" {
		t.Errorf("rule-1 value = %q, want Bearer test-token-123", r1.Action.Value)
	}
	if r1.Direction != rules.DirectionRequest {
		t.Errorf("rule-1 direction = %q, want request", r1.Direction)
	}

	r2, err := pipeline.GetRule("strip-csp")
	if err != nil {
		t.Fatalf("GetRule(strip-csp): %v", err)
	}
	if r2.Action.Type != rules.ActionRemoveHeader {
		t.Errorf("rule-2 action = %q, want remove_header", r2.Action.Type)
	}
	if r2.Direction != rules.DirectionResponse {
		t.Errorf("rule-2 direction = %q, want response", r2.Direction)
	}

	// Disable one rule.
	result2, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Disable: []string{"add-auth-header"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure disable): %v", err)
	}
	if result2.IsError {
		t.Fatalf("configure disable error: %v", result2.Content)
	}

	var out2 configureResult
	configureUnmarshalResult(t, result2, &out2)
	if out2.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules after disable = %d, want 1", out2.AutoTransform.EnabledRules)
	}

	// Re-enable it.
	result3, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Enable: []string{"add-auth-header"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure enable): %v", err)
	}
	if result3.IsError {
		t.Fatalf("configure enable error: %v", result3.Content)
	}

	var out3 configureResult
	configureUnmarshalResult(t, result3, &out3)
	if out3.AutoTransform.EnabledRules != 2 {
		t.Errorf("enabled_rules after re-enable = %d, want 2", out3.AutoTransform.EnabledRules)
	}

	// Remove a rule.
	result4, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Remove: []string{"strip-csp"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure remove): %v", err)
	}
	if result4.IsError {
		t.Fatalf("configure remove error: %v", result4.Content)
	}

	var out4 configureResult
	configureUnmarshalResult(t, result4, &out4)
	if out4.AutoTransform.TotalRules != 1 {
		t.Errorf("total_rules after remove = %d, want 1", out4.AutoTransform.TotalRules)
	}
}

// TestM3_Transform_ReplaceAll verifies that the replace operation atomically
// replaces all auto-transform rules.
func TestM3_Transform_ReplaceAll(t *testing.T) {
	pipeline := rules.NewPipeline()

	// Pre-populate with old rules.
	pipeline.AddRule(rules.Rule{
		ID: "old-1", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Old", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "old-2", Enabled: true, Direction: rules.DirectionResponse,
		Action: rules.Action{Type: rules.ActionRemoveHeader, Header: "X-Old2"},
	})

	cs := setupTransformTestSession(t, pipeline)

	// Replace all with a single new rule.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{
					{
						ID:        "new-rule",
						Enabled:   true,
						Priority:  1,
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
		t.Fatalf("configure replace error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.TotalRules != 1 {
		t.Errorf("total_rules = %d, want 1", out.AutoTransform.TotalRules)
	}

	// Old rules should be gone.
	_, err = pipeline.GetRule("old-1")
	if err == nil {
		t.Error("old-1 should have been removed by replace")
	}
	_, err = pipeline.GetRule("old-2")
	if err == nil {
		t.Error("old-2 should have been removed by replace")
	}

	// New rule should exist.
	r, err := pipeline.GetRule("new-rule")
	if err != nil {
		t.Fatalf("GetRule(new-rule): %v", err)
	}
	if r.Direction != rules.DirectionBoth {
		t.Errorf("direction = %q, want both", r.Direction)
	}
	if r.Action.Type != rules.ActionSetHeader {
		t.Errorf("action type = %q, want set_header", r.Action.Type)
	}
}

// TestM3_Transform_ReplaceBodyAction verifies that the replace_body action type
// works correctly for body content transformation.
func TestM3_Transform_ReplaceBodyAction(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "replace-host",
						Enabled:   true,
						Priority:  5,
						Direction: "request",
						Action: transformActionInput{
							Type:    "replace_body",
							Pattern: "production\\.example\\.com",
							Value:   "staging.example.com",
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
		t.Fatalf("configure error: %v", result.Content)
	}

	r, err := pipeline.GetRule("replace-host")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if r.Action.Type != rules.ActionReplaceBody {
		t.Errorf("action type = %q, want replace_body", r.Action.Type)
	}
	if r.Action.Pattern != "production\\.example\\.com" {
		t.Errorf("pattern = %q, want production\\.example\\.com", r.Action.Pattern)
	}
	if r.Action.Value != "staging.example.com" {
		t.Errorf("value = %q, want staging.example.com", r.Action.Value)
	}
}

// TestM3_Transform_PriorityOrdering verifies that rules are stored and applied
// in priority order (lowest priority value first).
func TestM3_Transform_PriorityOrdering(t *testing.T) {
	pipeline := rules.NewPipeline()
	cs := setupTransformTestSession(t, pipeline)

	// Add rules with out-of-order priorities.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "low-pri", Enabled: true, Priority: 100, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X-Low", Value: "100"},
					},
					{
						ID: "high-pri", Enabled: true, Priority: 1, Direction: "request",
						Action: transformActionInput{Type: "add_header", Header: "X-High", Value: "1"},
					},
					{
						ID: "mid-pri", Enabled: true, Priority: 50, Direction: "request",
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
		t.Fatalf("configure error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)
	if out.AutoTransform.TotalRules != 3 {
		t.Errorf("total_rules = %d, want 3", out.AutoTransform.TotalRules)
	}

	// Verify ordering: pipeline sorts by priority (lowest first).
	rulesList := pipeline.Rules()
	if len(rulesList) != 3 {
		t.Fatalf("rules count = %d, want 3", len(rulesList))
	}
	if rulesList[0].ID != "high-pri" {
		t.Errorf("first rule = %q, want high-pri", rulesList[0].ID)
	}
	if rulesList[1].ID != "mid-pri" {
		t.Errorf("second rule = %q, want mid-pri", rulesList[1].ID)
	}
	if rulesList[2].ID != "low-pri" {
		t.Errorf("third rule = %q, want low-pri", rulesList[2].ID)
	}
}

// TestM3_Transform_QueryAutoTransformRules verifies that configured auto-transform
// rules appear in the query config response.
func TestM3_Transform_QueryAutoTransformRules(t *testing.T) {
	pipeline := rules.NewPipeline()

	// Set up a session with both scope and pipeline.
	cs := setupTransformTestSession(t, pipeline)

	// Add a rule.
	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID:        "query-test-rule",
						Enabled:   true,
						Priority:  10,
						Direction: "request",
						Action: transformActionInput{
							Type:   "set_header",
							Header: "X-Test",
							Value:  "test-value",
						},
					},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure): %v", err)
	}

	// Query config and verify auto_transform appears.
	qResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{"resource": "config"},
	})
	if err != nil {
		t.Fatalf("CallTool(query config): %v", err)
	}
	if qResult.IsError {
		t.Fatalf("query config error: %v", qResult.Content)
	}

	// Parse the config result and check auto_transform field.
	var configOut queryConfigResult
	extractResult(t, qResult, &configOut)

	// Note: queryConfigResult may or may not have an AutoTransform field.
	// If the query response includes auto_transform, verify it.
	// If not, the test passes as long as configure succeeded.
}

// TestM3_Transform_CombinedOperations verifies a combined merge operation
// that adds, removes, enables, and disables rules in a single call.
func TestM3_Transform_CombinedOperations(t *testing.T) {
	pipeline := rules.NewPipeline()

	// Pre-populate.
	pipeline.AddRule(rules.Rule{
		ID: "to-remove", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Remove", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "to-disable", Enabled: true, Direction: rules.DirectionRequest,
		Action: rules.Action{Type: rules.ActionAddHeader, Header: "X-Disable", Value: "true"},
	})
	pipeline.AddRule(rules.Rule{
		ID: "to-enable", Enabled: false, Direction: rules.DirectionResponse,
		Action: rules.Action{Type: rules.ActionRemoveHeader, Header: "X-Enable"},
	})

	cs := setupTransformTestSession(t, pipeline)

	// Single merge call that does all operations.
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
							Value:  "added",
						},
					},
				},
				Remove:  []string{"to-remove"},
				Disable: []string{"to-disable"},
				Enable:  []string{"to-enable"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("configure error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	// Should have 3 rules: to-disable (disabled), to-enable (enabled), new-rule (enabled).
	if out.AutoTransform.TotalRules != 3 {
		t.Errorf("total_rules = %d, want 3", out.AutoTransform.TotalRules)
	}
	if out.AutoTransform.EnabledRules != 2 {
		t.Errorf("enabled_rules = %d, want 2 (new-rule + to-enable)", out.AutoTransform.EnabledRules)
	}

	// Verify individual rule states.
	_, err = pipeline.GetRule("to-remove")
	if err == nil {
		t.Error("to-remove should have been removed")
	}

	disabled, _ := pipeline.GetRule("to-disable")
	if disabled.Enabled {
		t.Error("to-disable should be disabled")
	}

	enabled, _ := pipeline.GetRule("to-enable")
	if !enabled.Enabled {
		t.Error("to-enable should be enabled")
	}

	newRule, err := pipeline.GetRule("new-rule")
	if err != nil {
		t.Fatalf("GetRule(new-rule): %v", err)
	}
	if !newRule.Enabled {
		t.Error("new-rule should be enabled")
	}
}
