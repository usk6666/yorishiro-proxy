package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// setupSafetyFilterTestSession creates an MCP client session with optional SafetyEngine.
func setupSafetyFilterTestSession(t *testing.T, engine *safety.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if engine != nil {
		opts = append(opts, WithSafetyEngine(engine))
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

func TestSecurity_GetSafetyFilter_NotEnabled(t *testing.T) {
	// When no safety engine is provided, get_safety_filter should return disabled.
	cs := setupSafetyFilterTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_safety_filter",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	var got getSafetyFilterResult
	securityUnmarshalResult(t, result, &got)

	if got.Enabled {
		t.Error("expected enabled=false when no safety engine is provided")
	}
	if !got.Immutable {
		t.Error("expected immutable=true")
	}
	if len(got.InputRules) != 0 {
		t.Errorf("expected 0 input rules, got %d", len(got.InputRules))
	}
	if len(got.OutputRules) != 0 {
		t.Errorf("expected 0 output rules, got %d", len(got.OutputRules))
	}
}

func TestSecurity_GetSafetyFilter_WithEngine(t *testing.T) {
	// Create an engine with preset + custom rules for both input and output.
	cfg := safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql"},
			{
				ID:      "custom-test",
				Name:    "Custom Test Rule",
				Pattern: `(?i)test-pattern`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
		OutputRules: []safety.RuleConfig{
			{Preset: "credit-card", Action: "mask"},
		},
	}
	engine, err := safety.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cs := setupSafetyFilterTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_safety_filter",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	var got getSafetyFilterResult
	securityUnmarshalResult(t, result, &got)

	if !got.Enabled {
		t.Error("expected enabled=true when safety engine is provided")
	}
	if !got.Immutable {
		t.Error("expected immutable=true")
	}

	// destructive-sql has 6 rules + 1 custom = 7 total.
	expectedMinRules := 7
	if len(got.InputRules) < expectedMinRules {
		t.Errorf("expected at least %d input rules, got %d", expectedMinRules, len(got.InputRules))
	}

	// Check custom rule is present.
	found := false
	for _, r := range got.InputRules {
		if r.ID == "custom-test" {
			found = true
			if r.Name != "Custom Test Rule" {
				t.Errorf("custom rule name = %q, want %q", r.Name, "Custom Test Rule")
			}
			if r.Action != "block" {
				t.Errorf("custom rule action = %q, want %q", r.Action, "block")
			}
			if r.Category != "custom" {
				t.Errorf("custom rule category = %q, want %q", r.Category, "custom")
			}
		}
	}
	if !found {
		t.Error("custom-test rule not found in result")
	}

	// Check preset rules are present.
	presetFound := false
	for _, r := range got.InputRules {
		if r.Category == "destructive-sql" {
			presetFound = true
			break
		}
	}
	if !presetFound {
		t.Error("destructive-sql preset rules not found in result")
	}

	// Check output rules are present (credit-card preset).
	if len(got.OutputRules) == 0 {
		t.Error("expected output rules from credit-card preset, got 0")
	}
	outputPresetFound := false
	for _, r := range got.OutputRules {
		if r.Category == "credit-card" {
			outputPresetFound = true
			if r.Action != "mask" {
				t.Errorf("output rule action = %q, want %q", r.Action, "mask")
			}
			break
		}
	}
	if !outputPresetFound {
		t.Error("credit-card preset rules not found in output rules")
	}
}

func TestSecurity_GetSafetyFilter_InAvailableActions(t *testing.T) {
	// Verify get_safety_filter is listed in available actions.
	found := false
	for _, a := range availableSecurityActions {
		if a == "get_safety_filter" {
			found = true
			break
		}
	}
	if !found {
		t.Error("get_safety_filter not listed in availableSecurityActions")
	}
}

func TestSecurity_GetSafetyFilter_QueryConfigIncluded(t *testing.T) {
	// When safety engine is provided, query config should include safety_filter info.
	cfg := safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql"},
		},
	}
	engine, err := safety.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cs := setupSafetyFilterTestSession(t, engine)

	// Query config resource.
	input := map[string]any{"resource": "config"}
	data, _ := json.Marshal(input)
	var args map[string]json.RawMessage
	_ = json.Unmarshal(data, &args)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	var got queryConfigResult
	securityUnmarshalResult(t, result, &got)

	if got.SafetyFilter == nil {
		t.Fatal("safety_filter is nil in config result")
	}
	if !got.SafetyFilter.Enabled {
		t.Error("expected safety_filter.enabled=true")
	}
	if got.SafetyFilter.InputRules < 6 {
		t.Errorf("expected at least 6 input rules, got %d", got.SafetyFilter.InputRules)
	}
}

func TestSecurity_GetSafetyFilter_QueryConfigDisabled(t *testing.T) {
	// When no safety engine is provided, query config should show disabled.
	cs := setupSafetyFilterTestSession(t, nil)

	input := map[string]any{"resource": "config"}
	data, _ := json.Marshal(input)
	var args map[string]json.RawMessage
	_ = json.Unmarshal(data, &args)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	var got queryConfigResult
	securityUnmarshalResult(t, result, &got)

	if got.SafetyFilter == nil {
		t.Fatal("safety_filter is nil in config result")
	}
	if got.SafetyFilter.Enabled {
		t.Error("expected safety_filter.enabled=false when no engine is set")
	}
}
