package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupSecurityTestSession creates an MCP client flow with a TargetScope for testing.
func setupSecurityTestSession(t *testing.T, ts *proxy.TargetScope) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if ts != nil {
		opts = append(opts, WithTargetScope(ts))
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

// securityMarshal marshals v to JSON Arguments map for security tool tests.
func securityMarshal(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal to map: %v", err)
	}
	return m
}

// securityUnmarshalResult extracts the structured result from CallToolResult content.
func securityUnmarshalResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), dest); err != nil {
		t.Fatalf("unmarshal result: %v (text: %s)", err, text.Text)
	}
}

func TestSecurity_GetTargetScope_EmptyDefault(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var got getTargetScopeResult
	securityUnmarshalResult(t, result, &got)

	if got.EffectiveMode != "open" {
		t.Errorf("effective_mode = %q, want %q", got.EffectiveMode, "open")
	}
	if len(got.Agent.Allows) != 0 {
		t.Errorf("agent.allows = %v, want empty", got.Agent.Allows)
	}
	if len(got.Agent.Denies) != 0 {
		t.Errorf("agent.denies = %v, want empty", got.Agent.Denies)
	}
	if len(got.Policy.Allows) != 0 {
		t.Errorf("policy.allows = %v, want empty", got.Policy.Allows)
	}
	if len(got.Policy.Denies) != 0 {
		t.Errorf("policy.denies = %v, want empty", got.Policy.Denies)
	}
	if got.Policy.Source != "none" {
		t.Errorf("policy.source = %q, want %q", got.Policy.Source, "none")
	}
	if !got.Policy.Immutable {
		t.Error("policy.immutable should be true")
	}
}

func TestSecurity_GetTargetScope_WithPolicyAndAgent(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "*.internal.corp"}},
	)
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "api.target.com"}},
		[]proxy.TargetRule{{Hostname: "admin.target.com"}},
	)
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var got getTargetScopeResult
	securityUnmarshalResult(t, result, &got)

	if got.EffectiveMode != "enforcing" {
		t.Errorf("effective_mode = %q, want %q", got.EffectiveMode, "enforcing")
	}

	// Policy layer.
	if len(got.Policy.Allows) != 1 || got.Policy.Allows[0].Hostname != "*.target.com" {
		t.Errorf("policy.allows = %v, want [{Hostname: *.target.com}]", got.Policy.Allows)
	}
	if len(got.Policy.Denies) != 1 || got.Policy.Denies[0].Hostname != "*.internal.corp" {
		t.Errorf("policy.denies = %v, want [{Hostname: *.internal.corp}]", got.Policy.Denies)
	}
	if got.Policy.Source != "config file" {
		t.Errorf("policy.source = %q, want %q", got.Policy.Source, "config file")
	}
	if !got.Policy.Immutable {
		t.Error("policy.immutable should be true")
	}

	// Agent layer.
	if len(got.Agent.Allows) != 1 || got.Agent.Allows[0].Hostname != "api.target.com" {
		t.Errorf("agent.allows = %v, want [{Hostname: api.target.com}]", got.Agent.Allows)
	}
	if len(got.Agent.Denies) != 1 || got.Agent.Denies[0].Hostname != "admin.target.com" {
		t.Errorf("agent.denies = %v, want [{Hostname: admin.target.com}]", got.Agent.Denies)
	}
}

func TestSecurity_SetGetRoundtrip(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Set rules.
	setResult, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{
					{Hostname: "example.com", Ports: []int{443}, Schemes: []string{"https"}},
					{Hostname: "*.internal.net"},
				},
				Denies: []targetRuleInput{
					{Hostname: "blocked.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_target_scope: %v", err)
	}

	var setRes setTargetScopeResult
	securityUnmarshalResult(t, setResult, &setRes)

	if setRes.Status != "updated" {
		t.Errorf("status = %q, want %q", setRes.Status, "updated")
	}
	if setRes.Mode != "enforcing" {
		t.Errorf("mode = %q, want %q", setRes.Mode, "enforcing")
	}
	if len(setRes.Allows) != 2 {
		t.Errorf("allows count = %d, want 2", len(setRes.Allows))
	}
	if len(setRes.Denies) != 1 {
		t.Errorf("denies count = %d, want 1", len(setRes.Denies))
	}

	// Get and verify.
	getResult, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("get_target_scope: %v", err)
	}

	var getRes getTargetScopeResult
	securityUnmarshalResult(t, getResult, &getRes)

	if getRes.EffectiveMode != "enforcing" {
		t.Errorf("get effective_mode = %q, want %q", getRes.EffectiveMode, "enforcing")
	}
	if len(getRes.Agent.Allows) != 2 {
		t.Errorf("get agent.allows count = %d, want 2", len(getRes.Agent.Allows))
	}
	if getRes.Agent.Allows[0].Hostname != "example.com" {
		t.Errorf("agent.allows[0].hostname = %q, want %q", getRes.Agent.Allows[0].Hostname, "example.com")
	}
	if len(getRes.Agent.Denies) != 1 {
		t.Errorf("get agent.denies count = %d, want 1", len(getRes.Agent.Denies))
	}
	if getRes.Agent.Denies[0].Hostname != "blocked.com" {
		t.Errorf("agent.denies[0].hostname = %q, want %q", getRes.Agent.Denies[0].Hostname, "blocked.com")
	}
}

func TestSecurity_SetClearsRules(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "existing.com"}},
		[]proxy.TargetRule{{Hostname: "blocked.com"}},
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Set with empty arrays to clear.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{},
				Denies: []targetRuleInput{},
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_target_scope: %v", err)
	}

	var res setTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if res.Mode != "open" {
		t.Errorf("mode = %q, want %q after clearing rules", res.Mode, "open")
	}
	if len(res.Allows) != 0 {
		t.Errorf("allows = %v, want empty", res.Allows)
	}
	if len(res.Denies) != 0 {
		t.Errorf("denies = %v, want empty", res.Denies)
	}
}

func TestSecurity_SetTargetScope_PolicyBoundaryError(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)

	// Try to set agent allows outside policy boundary.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{
					{Hostname: "evil.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for allows outside policy boundary")
	}
}

func TestSecurity_UpdateMerge_AddRemove(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "existing.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Add an allow and a deny, remove the existing allow.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				AddAllows:    []targetRuleInput{{Hostname: "new.com"}},
				RemoveAllows: []targetRuleInput{{Hostname: "existing.com"}},
				AddDenies:    []targetRuleInput{{Hostname: "evil.com"}},
			},
		}),
	})
	if err != nil {
		t.Fatalf("update_target_scope: %v", err)
	}

	var res setTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if res.Status != "updated" {
		t.Errorf("status = %q, want %q", res.Status, "updated")
	}
	if len(res.Allows) != 1 || res.Allows[0].Hostname != "new.com" {
		t.Errorf("allows = %v, want [{Hostname: new.com}]", res.Allows)
	}
	if len(res.Denies) != 1 || res.Denies[0].Hostname != "evil.com" {
		t.Errorf("denies = %v, want [{Hostname: evil.com}]", res.Denies)
	}
}

func TestSecurity_UpdateMerge_SkipsDuplicates(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "existing.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Add a duplicate allow.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				AddAllows: []targetRuleInput{{Hostname: "existing.com"}},
			},
		}),
	})
	if err != nil {
		t.Fatalf("update_target_scope: %v", err)
	}

	var res setTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if len(res.Allows) != 1 {
		t.Errorf("allows count = %d, want 1 (duplicate should be skipped)", len(res.Allows))
	}
}

func TestSecurity_UpdateTargetScope_RemovePolicyDenyError(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "*.internal.corp"}},
	)
	cs := setupSecurityTestSession(t, ts)

	// Try to remove a policy deny rule.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				RemoveDenies: []targetRuleInput{
					{Hostname: "*.internal.corp"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when removing policy deny rule")
	}
	// Verify the error message mentions policy immutability.
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if !strings.Contains(text.Text, "policy") || !strings.Contains(text.Text, "immutable") {
		t.Errorf("error message should mention policy immutability, got: %s", text.Text)
	}
}

func TestSecurity_UpdateTargetScope_RemoveAgentDenyAllowed(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		nil,
		[]proxy.TargetRule{{Hostname: "agent-blocked.com"}},
	)
	cs := setupSecurityTestSession(t, ts)

	// Removing an agent deny should succeed.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				RemoveDenies: []targetRuleInput{
					{Hostname: "agent-blocked.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success when removing agent deny rule")
	}

	var res setTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if len(res.Denies) != 0 {
		t.Errorf("denies = %v, want empty after removal", res.Denies)
	}
}

func TestSecurity_UpdateTargetScope_AddAllowsOutsidePolicy(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)

	// Try to add allows outside policy.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				AddAllows: []targetRuleInput{
					{Hostname: "evil.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for add_allows outside policy boundary")
	}
}

func TestSecurity_TestTarget_AllowedInOpenMode(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://example.com/api/test",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if !res.Allowed {
		t.Error("expected allowed=true in open mode")
	}
	if res.MatchedRule != nil {
		t.Error("expected matched_rule=nil in open mode")
	}
	if res.Layer != "" {
		t.Errorf("expected empty layer in open mode, got %q", res.Layer)
	}
	// Verify tested_target is populated.
	if res.TestedTarget == nil {
		t.Fatal("expected tested_target to be populated")
	}
	if res.TestedTarget.Hostname != "example.com" {
		t.Errorf("tested_target.hostname = %q, want %q", res.TestedTarget.Hostname, "example.com")
	}
	if res.TestedTarget.Port != 443 {
		t.Errorf("tested_target.port = %d, want 443", res.TestedTarget.Port)
	}
	if res.TestedTarget.Scheme != "https" {
		t.Errorf("tested_target.scheme = %q, want %q", res.TestedTarget.Scheme, "https")
	}
	if res.TestedTarget.Path != "/api/test" {
		t.Errorf("tested_target.path = %q, want %q", res.TestedTarget.Path, "/api/test")
	}
}

func TestSecurity_TestTarget_BlockedByAgentDeny(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{{Hostname: "blocked.com"}})
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://blocked.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false for denied target")
	}
	if res.Reason == "" {
		t.Error("expected non-empty reason for denied target")
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want %q", res.Layer, "agent")
	}
	if res.MatchedRule == nil {
		t.Error("expected matched_rule for denied target")
	}
	if res.MatchedRule != nil && res.MatchedRule.Hostname != "blocked.com" {
		t.Errorf("matched_rule.hostname = %q, want %q", res.MatchedRule.Hostname, "blocked.com")
	}
}

func TestSecurity_TestTarget_BlockedByPolicyDeny(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		nil,
		[]proxy.TargetRule{{Hostname: "policy-blocked.com"}},
	)
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://policy-blocked.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false for policy-denied target")
	}
	if res.Layer != "policy" {
		t.Errorf("layer = %q, want %q", res.Layer, "policy")
	}
	if res.MatchedRule == nil || res.MatchedRule.Hostname != "policy-blocked.com" {
		t.Errorf("matched_rule = %v, want hostname=policy-blocked.com", res.MatchedRule)
	}
}

func TestSecurity_TestTarget_NotInPolicyAllowList(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://evil.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false for target not in policy allow list")
	}
	if res.Layer != "policy" {
		t.Errorf("layer = %q, want %q", res.Layer, "policy")
	}
	if res.Reason != "not in policy allow list" {
		t.Errorf("reason = %q, want %q", res.Reason, "not in policy allow list")
	}
	// No matched rule because none matched.
	if res.MatchedRule != nil {
		t.Error("expected matched_rule=nil when blocked due to not matching any allow rule")
	}
}

func TestSecurity_TestTarget_NotInAgentAllowList(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "allowed.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://other.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false for target not in agent allow list")
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want %q", res.Layer, "agent")
	}
	if res.Reason != "not in agent allow list" {
		t.Errorf("reason = %q, want %q", res.Reason, "not in agent allow list")
	}
	// No matched rule because none matched.
	if res.MatchedRule != nil {
		t.Error("expected matched_rule=nil when blocked due to not matching any allow rule")
	}
}

func TestSecurity_TestTarget_AllowedByAgentRule(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "*.example.com", Schemes: []string{"https"}}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://api.example.com/data",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if !res.Allowed {
		t.Error("expected allowed=true for matching allow rule")
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want %q", res.Layer, "agent")
	}
	if res.MatchedRule == nil {
		t.Error("expected matched_rule for allowed target")
	}
	if res.MatchedRule != nil && res.MatchedRule.Hostname != "*.example.com" {
		t.Errorf("matched_rule.hostname = %q, want %q", res.MatchedRule.Hostname, "*.example.com")
	}
}

func TestSecurity_TestTarget_WithPortAndPath(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{
			Hostname:   "target.internal",
			Ports:      []int{8080, 8443},
			PathPrefix: "/api/",
			Schemes:    []string{"https"},
		}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	tests := []struct {
		name    string
		url     string
		allowed bool
	}{
		{
			name:    "matching URL",
			url:     "https://target.internal:8080/api/test",
			allowed: true,
		},
		{
			name:    "wrong port",
			url:     "https://target.internal:9090/api/test",
			allowed: false,
		},
		{
			name:    "wrong path",
			url:     "https://target.internal:8080/other",
			allowed: false,
		},
		{
			name:    "wrong scheme",
			url:     "http://target.internal:8080/api/test",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
				Name: "security",
				Arguments: securityMarshal(t, securityInput{
					Action: "test_target",
					Params: securityParams{
						URL: tt.url,
					},
				}),
			})
			if err != nil {
				t.Fatalf("test_target: %v", err)
			}

			var res testTargetResult
			securityUnmarshalResult(t, result, &res)

			if res.Allowed != tt.allowed {
				t.Errorf("allowed = %v, want %v", res.Allowed, tt.allowed)
			}
		})
	}
}

func TestSecurity_InvalidAction(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "invalid_action",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid action")
	}
}

func TestSecurity_EmptyAction(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty action")
	}
}

func TestSecurity_SetTargetScope_EmptyHostname(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{
					{Hostname: ""},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty hostname")
	}
}

func TestSecurity_UpdateTargetScope_EmptyHostname(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				AddAllows: []targetRuleInput{
					{Hostname: ""},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty hostname in add_allows")
	}
}

func TestSecurity_TestTarget_EmptyURL(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "",
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty URL")
	}
}

func TestSecurity_TestTarget_InvalidURL(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "://invalid",
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid URL")
	}
}

func TestSecurity_DefaultTargetScopeInitialized(t *testing.T) {
	// Create server without WithTargetScope -- should auto-initialize.
	cs := setupSecurityTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("get_target_scope with default scope: %v", err)
	}

	var res getTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if res.EffectiveMode != "open" {
		t.Errorf("effective_mode = %q, want %q for default scope", res.EffectiveMode, "open")
	}
}

func TestSecurity_DenyTakesPrecedence(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "*.example.com"}},
		[]proxy.TargetRule{{Hostname: "blocked.example.com"}},
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://blocked.example.com/api",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false: deny should take precedence over allow")
	}
	if res.MatchedRule == nil || res.MatchedRule.Hostname != "blocked.example.com" {
		t.Errorf("expected matched deny rule, got %v", res.MatchedRule)
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want %q", res.Layer, "agent")
	}
}

func TestSecurity_SetThenUpdate(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Set initial rules.
	_, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{
					{Hostname: "first.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_target_scope: %v", err)
	}

	// Update: add another allow.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "update_target_scope",
			Params: securityParams{
				AddAllows: []targetRuleInput{
					{Hostname: "second.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("update_target_scope: %v", err)
	}

	var res setTargetScopeResult
	securityUnmarshalResult(t, result, &res)

	if len(res.Allows) != 2 {
		t.Errorf("allows count = %d, want 2", len(res.Allows))
	}
	if res.Mode != "enforcing" {
		t.Errorf("mode = %q, want %q", res.Mode, "enforcing")
	}
}

// TestSecurity_JSONNullArrays verifies that empty allows/denies are serialized
// as empty JSON arrays [] rather than null.
func TestSecurity_JSONNullArrays(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("get_target_scope: %v", err)
	}

	// Check raw JSON to ensure nested arrays are [] not null.
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}

	var raw struct {
		Policy struct {
			Allows json.RawMessage `json:"allows"`
			Denies json.RawMessage `json:"denies"`
		} `json:"policy"`
		Agent struct {
			Allows json.RawMessage `json:"allows"`
			Denies json.RawMessage `json:"denies"`
		} `json:"agent"`
	}
	if err := json.Unmarshal([]byte(text.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	for _, tc := range []struct {
		name string
		val  json.RawMessage
	}{
		{"policy.allows", raw.Policy.Allows},
		{"policy.denies", raw.Policy.Denies},
		{"agent.allows", raw.Agent.Allows},
		{"agent.denies", raw.Agent.Denies},
	} {
		if string(tc.val) != "[]" {
			t.Errorf("%s = %s, want []", tc.name, string(tc.val))
		}
	}
}

// TestSecurity_TestTarget_DefaultPort verifies that default ports are inferred
// for http (80) and https (443) when not explicitly specified in the URL.
func TestSecurity_TestTarget_DefaultPort(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "example.com", Ports: []int{443}}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// https://example.com should default to port 443.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://example.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if !res.Allowed {
		t.Error("expected allowed=true for default HTTPS port 443")
	}
	// Verify tested_target has the inferred port.
	if res.TestedTarget == nil {
		t.Fatal("expected tested_target to be populated")
	}
	if res.TestedTarget.Port != 443 {
		t.Errorf("tested_target.port = %d, want 443", res.TestedTarget.Port)
	}
}

// TestSecurity_TestTarget_BothLayersDecide verifies that test_target correctly
// reports the layer for a target that passes policy but is blocked by agent.
func TestSecurity_TestTarget_BothLayersDecide(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)
	ts.SetAgentRules(
		nil,
		[]proxy.TargetRule{{Hostname: "admin.target.com"}},
	)
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://admin.target.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false: agent deny should block")
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want %q", res.Layer, "agent")
	}
	if res.MatchedRule == nil || res.MatchedRule.Hostname != "admin.target.com" {
		t.Errorf("matched_rule = %v, want hostname=admin.target.com", res.MatchedRule)
	}
}

// TestSecurity_NoPolicyBackwardCompat verifies backward compatibility when no
// policy is configured - the tool should work as before.
func TestSecurity_NoPolicyBackwardCompat(t *testing.T) {
	ts := proxy.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	// Set agent rules without any policy.
	_, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_target_scope",
			Params: securityParams{
				Allows: []targetRuleInput{
					{Hostname: "example.com"},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_target_scope: %v", err)
	}

	// Test allowed target.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://example.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	var res testTargetResult
	securityUnmarshalResult(t, result, &res)

	if !res.Allowed {
		t.Error("expected allowed=true without policy")
	}

	// Test blocked target.
	result, err = cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "test_target",
			Params: securityParams{
				URL: "https://other.com/path",
			},
		}),
	})
	if err != nil {
		t.Fatalf("test_target: %v", err)
	}

	securityUnmarshalResult(t, result, &res)

	if res.Allowed {
		t.Error("expected allowed=false for target not in allow list")
	}

	// Verify get_target_scope shows no policy.
	getResult, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_target_scope",
		}),
	})
	if err != nil {
		t.Fatalf("get_target_scope: %v", err)
	}

	var getRes getTargetScopeResult
	securityUnmarshalResult(t, getResult, &getRes)

	if getRes.Policy.Source != "none" {
		t.Errorf("policy.source = %q, want %q", getRes.Policy.Source, "none")
	}
	if len(getRes.Policy.Allows) != 0 {
		t.Errorf("policy.allows = %v, want empty", getRes.Policy.Allows)
	}
	if len(getRes.Agent.Allows) != 1 {
		t.Errorf("agent.allows count = %d, want 1", len(getRes.Agent.Allows))
	}
}

// Test helper functions.
func TestMatchHostnameLocal(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		want     bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "Example.COM", true},
		{"example.com", "other.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := matchHostnameLocal(tt.pattern, tt.hostname)
			if got != tt.want {
				t.Errorf("matchHostnameLocal(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
			}
		})
	}
}

func TestTargetDefaultPort(t *testing.T) {
	tests := []struct {
		scheme  string
		portStr string
		want    int
	}{
		{"https", "", 443},
		{"http", "", 80},
		{"ftp", "", 0},
		{"https", "8443", 8443},
		{"http", "8080", 8080},
	}

	for _, tt := range tests {
		t.Run(tt.scheme+"_"+tt.portStr, func(t *testing.T) {
			got := targetDefaultPort(tt.scheme, tt.portStr)
			if got != tt.want {
				t.Errorf("targetDefaultPort(%q, %q) = %d, want %d", tt.scheme, tt.portStr, got, tt.want)
			}
		})
	}
}

func TestValidateTargetRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []targetRuleInput
		wantErr bool
	}{
		{
			name:    "valid rules",
			rules:   []targetRuleInput{{Hostname: "example.com"}, {Hostname: "*.test.com"}},
			wantErr: false,
		},
		{
			name:    "empty hostname",
			rules:   []targetRuleInput{{Hostname: ""}},
			wantErr: true,
		},
		{
			name:    "nil rules",
			rules:   nil,
			wantErr: false,
		},
		{
			name:    "empty slice",
			rules:   []targetRuleInput{},
			wantErr: false,
		},
		{
			name:    "second rule empty hostname",
			rules:   []targetRuleInput{{Hostname: "ok.com"}, {Hostname: ""}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetRules("test", tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTargetRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToTargetRules(t *testing.T) {
	inputs := []targetRuleInput{
		{Hostname: "example.com", Ports: []int{80, 443}, PathPrefix: "/api/", Schemes: []string{"https"}},
	}
	rules := toTargetRules(inputs)

	if len(rules) != 1 {
		t.Fatalf("len = %d, want 1", len(rules))
	}
	r := rules[0]
	if r.Hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", r.Hostname, "example.com")
	}
	if len(r.Ports) != 2 || r.Ports[0] != 80 || r.Ports[1] != 443 {
		t.Errorf("ports = %v, want [80, 443]", r.Ports)
	}
	if r.PathPrefix != "/api/" {
		t.Errorf("path_prefix = %q, want %q", r.PathPrefix, "/api/")
	}
	if len(r.Schemes) != 1 || r.Schemes[0] != "https" {
		t.Errorf("schemes = %v, want [https]", r.Schemes)
	}
}

func TestToTargetRules_Empty(t *testing.T) {
	rules := toTargetRules(nil)
	if rules != nil {
		t.Errorf("expected nil for nil input, got %v", rules)
	}

	rules = toTargetRules([]targetRuleInput{})
	if rules != nil {
		t.Errorf("expected nil for empty input, got %v", rules)
	}
}

func TestEnsureNonNilRules(t *testing.T) {
	var nilRules []proxy.TargetRule
	result := ensureNonNilRules(nilRules)
	if result == nil {
		t.Error("expected non-nil result for nil input")
	}
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}

	existing := []proxy.TargetRule{{Hostname: "test.com"}}
	result = ensureNonNilRules(existing)
	if len(result) != 1 {
		t.Errorf("expected 1 rule, got %d", len(result))
	}
}

func TestTargetScopeMode(t *testing.T) {
	if mode := targetScopeMode(nil); mode != "open" {
		t.Errorf("mode = %q, want %q for nil scope", mode, "open")
	}
	tsEmpty := proxy.NewTargetScope()
	if mode := targetScopeMode(tsEmpty); mode != "open" {
		t.Errorf("mode = %q, want %q for empty scope", mode, "open")
	}
	tsWithRules := proxy.NewTargetScope()
	tsWithRules.SetAgentRules([]proxy.TargetRule{{Hostname: "x"}}, nil)
	if mode := targetScopeMode(tsWithRules); mode != "enforcing" {
		t.Errorf("mode = %q, want %q for scope with rules", mode, "enforcing")
	}
}

func TestLayerFromReason(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		{"blocked by policy deny rule", "policy"},
		{"not in policy allow list", "policy"},
		{"blocked by agent deny rule", "agent"},
		{"not in agent allow list", "agent"},
		{"", ""},
		{"unknown reason", ""},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			got := layerFromReason(tt.reason)
			if got != tt.want {
				t.Errorf("layerFromReason(%q) = %q, want %q", tt.reason, got, tt.want)
			}
		})
	}
}

func TestValidateNotPolicyDenies(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		nil,
		[]proxy.TargetRule{
			{Hostname: "*.internal.corp"},
			{Hostname: "admin.target.com", Ports: []int{443}},
		},
	)

	tests := []struct {
		name        string
		removeDenies []proxy.TargetRule
		wantErr     bool
	}{
		{
			name:        "no removals",
			removeDenies: nil,
			wantErr:     false,
		},
		{
			name:        "remove non-policy deny",
			removeDenies: []proxy.TargetRule{{Hostname: "other.com"}},
			wantErr:     false,
		},
		{
			name:        "remove matching policy deny",
			removeDenies: []proxy.TargetRule{{Hostname: "*.internal.corp"}},
			wantErr:     true,
		},
		{
			name:        "remove matching policy deny with ports",
			removeDenies: []proxy.TargetRule{{Hostname: "admin.target.com", Ports: []int{443}}},
			wantErr:     true,
		},
		{
			name:        "remove similar but different hostname",
			removeDenies: []proxy.TargetRule{{Hostname: "admin.target.com"}},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNotPolicyDenies(ts, tt.removeDenies)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNotPolicyDenies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTargetRuleMatchesLocal(t *testing.T) {
	tests := []struct {
		name string
		a    proxy.TargetRule
		b    proxy.TargetRule
		want bool
	}{
		{
			name: "exact match",
			a:    proxy.TargetRule{Hostname: "example.com"},
			b:    proxy.TargetRule{Hostname: "example.com"},
			want: true,
		},
		{
			name: "case insensitive hostname",
			a:    proxy.TargetRule{Hostname: "Example.COM"},
			b:    proxy.TargetRule{Hostname: "example.com"},
			want: true,
		},
		{
			name: "different hostname",
			a:    proxy.TargetRule{Hostname: "a.com"},
			b:    proxy.TargetRule{Hostname: "b.com"},
			want: false,
		},
		{
			name: "with matching ports",
			a:    proxy.TargetRule{Hostname: "a.com", Ports: []int{80, 443}},
			b:    proxy.TargetRule{Hostname: "a.com", Ports: []int{80, 443}},
			want: true,
		},
		{
			name: "different ports",
			a:    proxy.TargetRule{Hostname: "a.com", Ports: []int{80}},
			b:    proxy.TargetRule{Hostname: "a.com", Ports: []int{443}},
			want: false,
		},
		{
			name: "with matching schemes",
			a:    proxy.TargetRule{Hostname: "a.com", Schemes: []string{"HTTPS"}},
			b:    proxy.TargetRule{Hostname: "a.com", Schemes: []string{"https"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetRuleMatchesLocal(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("targetRuleMatchesLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}
