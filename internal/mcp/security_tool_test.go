package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupSecurityTestSession creates an MCP client session with a TargetScope for testing.
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

	if got.Mode != "open" {
		t.Errorf("mode = %q, want %q", got.Mode, "open")
	}
	if len(got.Allows) != 0 {
		t.Errorf("allows = %v, want empty", got.Allows)
	}
	if len(got.Denies) != 0 {
		t.Errorf("denies = %v, want empty", got.Denies)
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

	if getRes.Mode != "enforcing" {
		t.Errorf("get mode = %q, want %q", getRes.Mode, "enforcing")
	}
	if len(getRes.Allows) != 2 {
		t.Errorf("get allows count = %d, want 2", len(getRes.Allows))
	}
	if getRes.Allows[0].Hostname != "example.com" {
		t.Errorf("allows[0].hostname = %q, want %q", getRes.Allows[0].Hostname, "example.com")
	}
	if len(getRes.Denies) != 1 {
		t.Errorf("get denies count = %d, want 1", len(getRes.Denies))
	}
	if getRes.Denies[0].Hostname != "blocked.com" {
		t.Errorf("denies[0].hostname = %q, want %q", getRes.Denies[0].Hostname, "blocked.com")
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
}

func TestSecurity_TestTarget_BlockedByDeny(t *testing.T) {
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
	if res.MatchedRule == nil {
		t.Error("expected matched_rule for denied target")
	}
	if res.MatchedRule != nil && res.MatchedRule.Hostname != "blocked.com" {
		t.Errorf("matched_rule.hostname = %q, want %q", res.MatchedRule.Hostname, "blocked.com")
	}
}

func TestSecurity_TestTarget_AllowedByRule(t *testing.T) {
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
	if res.MatchedRule == nil {
		t.Error("expected matched_rule for allowed target")
	}
	if res.MatchedRule != nil && res.MatchedRule.Hostname != "*.example.com" {
		t.Errorf("matched_rule.hostname = %q, want %q", res.MatchedRule.Hostname, "*.example.com")
	}
}

func TestSecurity_TestTarget_NotInAllowList(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "allowed.com"}},
		nil,
	)
	cs := setupSecurityTestSession(t, ts)
	ctx := context.Background()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
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
		t.Error("expected allowed=false for target not in allow list")
	}
	if res.Reason == "" {
		t.Error("expected non-empty reason")
	}
	// No matched rule because none matched.
	if res.MatchedRule != nil {
		t.Error("expected matched_rule=nil when blocked due to not matching any allow rule")
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
	// Create server without WithTargetScope — should auto-initialize.
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

	if res.Mode != "open" {
		t.Errorf("mode = %q, want %q for default scope", res.Mode, "open")
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

	// Check raw JSON to ensure arrays are [] not null.
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	for _, field := range []string{"allows", "denies"} {
		val := string(raw[field])
		if val != "[]" {
			t.Errorf("%s = %s, want []", field, val)
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
