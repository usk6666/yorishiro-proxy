package mcp

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// setupTransformTestSession creates a connected MCP client session for
// auto-transform rule tests. It threads a shared *httprules.TransformEngine
// into the Pipeline component so the configure auto_transform path mutates
// the same engine the test verifies on directly.
func setupTransformTestSession(t *testing.T, engine *httprules.TransformEngine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	pl := connector.NewPassthroughList()
	opts := []ServerOption{WithPassthroughList(pl)}
	if engine != nil {
		opts = append(opts, WithHTTPTransformEngine(engine))
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

// findTransformRule returns the engine rule with the given ID, or nil.
func findTransformRule(engine *httprules.TransformEngine, id string) *httprules.TransformRule {
	for _, r := range engine.Rules() {
		if r.ID == id {
			rc := r
			return &rc
		}
	}
	return nil
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
						ID:          "rule-1",
						Enabled:     true,
						Priority:    10,
						Direction:   "request",
						HostPattern: "api\\.example\\.com",
						PathPattern: "/admin",
						Methods:     []string{"POST", "PUT", "DELETE"},
						ActionType:  "set_header",
						HeaderName:  "Authorization",
						HeaderValue: "Bearer test-token",
					},
					{
						ID:          "rule-2",
						Enabled:     false,
						Priority:    20,
						Direction:   "response",
						PathPattern: "/api/",
						ActionType:  "remove_header",
						HeaderName:  "Content-Security-Policy",
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

	r := findTransformRule(engine, "rule-1")
	if r == nil {
		t.Fatal("rule-1 not found")
	}
	if !r.Enabled {
		t.Error("rule-1 should be enabled")
	}
	if r.Direction != httprules.DirectionRequest {
		t.Errorf("direction = %q, want %q", r.Direction, httprules.DirectionRequest)
	}
	if r.ActionType != httprules.TransformSetHeader {
		t.Errorf("action_type = %d, want %d", r.ActionType, httprules.TransformSetHeader)
	}
}

func TestConfigure_AutoTransform_MergeRemove(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "keep", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Keep", HeaderValue: "true",
	})
	engine.AddRule(httprules.TransformRule{
		ID: "remove-me", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Remove", HeaderValue: "true",
	})

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

	if findTransformRule(engine, "remove-me") != nil {
		t.Error("remove-me should have been removed")
	}
	if findTransformRule(engine, "keep") == nil {
		t.Error("keep should still exist")
	}
}

func TestConfigure_AutoTransform_MergeEnable(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "r1", Enabled: false, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Test", HeaderValue: "true",
	})

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.EnabledRules != 1 {
		t.Errorf("enabled_rules = %d, want 1", out.AutoTransform.EnabledRules)
	}

	r := findTransformRule(engine, "r1")
	if r == nil || !r.Enabled {
		t.Error("r1 should be enabled")
	}
}

func TestConfigure_AutoTransform_MergeDisable(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "r1", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Test", HeaderValue: "true",
	})

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.EnabledRules != 0 {
		t.Errorf("enabled_rules = %d, want 0", out.AutoTransform.EnabledRules)
	}

	r := findTransformRule(engine, "r1")
	if r == nil || r.Enabled {
		t.Error("r1 should be disabled")
	}
}

func TestConfigure_AutoTransform_Replace(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "old-1", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Old1", HeaderValue: "true",
	})

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			AutoTransform: &configureAutoTransform{
				Rules: []transformRuleInput{
					{
						ID:          "new-1",
						Enabled:     true,
						Direction:   "both",
						PathPattern: "/api/",
						ActionType:  "set_header",
						HeaderName:  "X-Proxy",
						HeaderValue: "yorishiro",
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

	if findTransformRule(engine, "old-1") != nil {
		t.Error("old-1 should have been replaced")
	}
	r := findTransformRule(engine, "new-1")
	if r == nil {
		t.Fatal("new-1 not found")
	}
	if r.Direction != httprules.DirectionBoth {
		t.Errorf("direction = %q, want %q", r.Direction, httprules.DirectionBoth)
	}
}

func TestConfigure_AutoTransform_ReplaceEmpty(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "r1", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Test", HeaderValue: "true",
	})

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

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.AutoTransform.TotalRules != 0 {
		t.Errorf("total_rules = %d, want 0", out.AutoTransform.TotalRules)
	}
}

func TestConfigure_AutoTransform_NilEngine(t *testing.T) {
	cs := setupTransformTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "r1", Enabled: true, Direction: "request",
						ActionType: "add_header", HeaderName: "X-Test", HeaderValue: "true",
					},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nil engine, got success")
	}
}

func TestConfigure_AutoTransform_MergeAddDuplicate(t *testing.T) {
	engine := httprules.NewTransformEngine()
	engine.AddRule(httprules.TransformRule{
		ID: "r1", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Test", HeaderValue: "true",
	})

	cs := setupTransformTestSession(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			AutoTransform: &configureAutoTransform{
				Add: []transformRuleInput{
					{
						ID: "r1", Enabled: true, Direction: "request",
						ActionType: "add_header", HeaderName: "X-Dup", HeaderValue: "true",
					},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for duplicate rule ID, got success")
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
						ID:          "bad",
						Enabled:     true,
						Direction:   "request",
						HostPattern: "[invalid",
						ActionType:  "add_header",
						HeaderName:  "X-Test",
						HeaderValue: "true",
					},
				},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex pattern, got success")
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
				Remove: []string{"nonexistent"},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule removal, got success")
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
				Enable: []string{"nonexistent"},
			},
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nonexistent rule enable, got success")
	}
}

func TestTransformHelpers_ToFromRoundTrip(t *testing.T) {
	input := transformRuleInput{
		ID:          "r1",
		Enabled:     true,
		Priority:    5,
		Direction:   "both",
		HostPattern: "api\\.example\\.com",
		PathPattern: "/api/",
		Methods:     []string{"POST", "PUT"},
		ActionType:  "set_header",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer token",
	}

	rule, err := compileTransformRule(input)
	if err != nil {
		t.Fatalf("compileTransformRule: %v", err)
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
		t.Errorf("ActionType = %d, want %d", rule.ActionType, httprules.TransformSetHeader)
	}

	output := fromTransformRule(*rule)

	if output.ID != "r1" {
		t.Errorf("output ID = %q, want %q", output.ID, "r1")
	}
	if output.Direction != "both" {
		t.Errorf("output Direction = %q, want %q", output.Direction, "both")
	}
	if output.HostPattern != "api\\.example\\.com" {
		t.Errorf("output HostPattern = %q, want %q", output.HostPattern, "api\\.example\\.com")
	}
	if output.ActionType != "set_header" {
		t.Errorf("output ActionType = %q, want %q", output.ActionType, "set_header")
	}
	if output.HeaderName != "Authorization" {
		t.Errorf("output HeaderName = %q, want %q", output.HeaderName, "Authorization")
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
						ID:          "replace-host",
						Enabled:     true,
						Priority:    10,
						Direction:   "request",
						ActionType:  "replace_body",
						BodyPattern: "production-host",
						BodyReplace: "staging-host",
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

	r := findTransformRule(engine, "replace-host")
	if r == nil {
		t.Fatal("replace-host not found")
	}
	if r.ActionType != httprules.TransformReplaceBody {
		t.Errorf("action_type = %d, want %d", r.ActionType, httprules.TransformReplaceBody)
	}
}

// TestConfigure_AutoTransform_RejectsCRLFInHeaderFields verifies the
// validateTransformRuleInput CWE-113 guard fires for the new schema's
// flat header_name / header_value fields across all three header
// actions. The guard runs before regex compile and rejects the rule
// at MCP boundary.
func TestConfigure_AutoTransform_RejectsCRLFInHeaderFields(t *testing.T) {
	tests := []struct {
		name  string
		input transformRuleInput
	}{
		{
			name: "add_header CR in header_name",
			input: transformRuleInput{
				ID: "add-cr-name", Enabled: true, Direction: "request",
				ActionType: "add_header", HeaderName: "X-Test\r", HeaderValue: "1",
			},
		},
		{
			name: "add_header LF in header_value",
			input: transformRuleInput{
				ID: "add-lf-value", Enabled: true, Direction: "request",
				ActionType: "add_header", HeaderName: "X-Test", HeaderValue: "1\n",
			},
		},
		{
			name: "set_header CRLF in header_name",
			input: transformRuleInput{
				ID: "set-crlf-name", Enabled: true, Direction: "request",
				ActionType: "set_header", HeaderName: "X-T\r\nInjected", HeaderValue: "v",
			},
		},
		{
			name: "set_header CRLF in header_value",
			input: transformRuleInput{
				ID: "set-crlf-value", Enabled: true, Direction: "request",
				ActionType: "set_header", HeaderName: "X-T", HeaderValue: "v\r\nInjected: smuggled",
			},
		},
		{
			name: "remove_header CR in header_name",
			input: transformRuleInput{
				ID: "remove-cr-name", Enabled: true, Direction: "request",
				ActionType: "remove_header", HeaderName: "X-Test\r",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := httprules.NewTransformEngine()
			cs := setupTransformTestSession(t, engine)

			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "configure",
				Arguments: configureMarshal(t, configureInput{
					Operation: "merge",
					AutoTransform: &configureAutoTransform{
						Add: []transformRuleInput{tc.input},
					},
				}),
			})
			if err != nil {
				return
			}
			if !result.IsError {
				t.Fatal("expected error for CR/LF in header field, got success")
			}

			// Engine must NOT have stored the rule.
			if len(engine.Rules()) != 0 {
				t.Errorf("engine.Rules() len = %d, want 0 (rule must be rejected before AddRule)", len(engine.Rules()))
			}
		})
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
						ID: "high-priority", Enabled: true, Priority: 1, Direction: "request",
						ActionType: "add_header", HeaderName: "X-First", HeaderValue: "1",
					},
					{
						ID: "low-priority", Enabled: true, Priority: 100, Direction: "request",
						ActionType: "add_header", HeaderName: "X-Last", HeaderValue: "100",
					},
					{
						ID: "mid-priority", Enabled: true, Priority: 50, Direction: "request",
						ActionType: "add_header", HeaderName: "X-Mid", HeaderValue: "50",
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

	// AddRule re-sorts by priority ascending. Engine.Rules() returns the
	// stored slice as a defensive copy.
	rulesList := engine.Rules()
	if len(rulesList) != 3 {
		t.Fatalf("rules count = %d, want 3", len(rulesList))
	}
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
