package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupConfigureTestSession creates a connected MCP client session for configure tool tests.
func setupConfigureTestSession(t *testing.T, scope *proxy.CaptureScope, pl *proxy.PassthroughList) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if scope != nil {
		opts = append(opts, WithCaptureScope(scope))
	}
	if pl != nil {
		opts = append(opts, WithPassthroughList(pl))
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

// configureMarshal marshals v to JSON Arguments map for configure tool tests.
func configureMarshal(t *testing.T, v any) map[string]json.RawMessage {
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

// configureUnmarshalResult extracts the structured result from CallToolResult content.
func configureUnmarshalResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), dest); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}

func TestConfigure_MergeAddIncludes(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "existing.com"}},
		nil,
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{
					{Hostname: "new-target.com"},
					{Hostname: "*.example.com", Method: "POST"},
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
	if out.CaptureScope == nil {
		t.Fatal("capture_scope is nil")
	}
	if out.CaptureScope.IncludeCount != 3 {
		t.Errorf("include_count = %d, want 3", out.CaptureScope.IncludeCount)
	}

	// Verify actual rules.
	includes, _ := scope.Rules()
	if len(includes) != 3 {
		t.Fatalf("scope includes = %d, want 3", len(includes))
	}
	// existing.com should still be there.
	found := false
	for _, r := range includes {
		if r.Hostname == "existing.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("existing.com should still be in includes")
	}
}

func TestConfigure_MergeRemoveIncludes(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{
			{Hostname: "keep.com"},
			{Hostname: "remove-me.com"},
			{Hostname: "also-keep.com"},
		},
		nil,
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				RemoveIncludes: []scopeRuleInput{
					{Hostname: "remove-me.com"},
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

	if out.CaptureScope.IncludeCount != 2 {
		t.Errorf("include_count = %d, want 2", out.CaptureScope.IncludeCount)
	}

	includes, _ := scope.Rules()
	for _, r := range includes {
		if r.Hostname == "remove-me.com" {
			t.Error("remove-me.com should have been removed from includes")
		}
	}
}

func TestConfigure_MergeAddRemoveExcludes(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		nil,
		[]proxy.ScopeRule{{Hostname: "old-cdn.com"}},
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddExcludes:    []scopeRuleInput{{Hostname: "cdn.example.com"}},
				RemoveExcludes: []scopeRuleInput{{Hostname: "old-cdn.com"}},
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

	if out.CaptureScope.ExcludeCount != 1 {
		t.Errorf("exclude_count = %d, want 1", out.CaptureScope.ExcludeCount)
	}

	_, excludes := scope.Rules()
	if len(excludes) != 1 || excludes[0].Hostname != "cdn.example.com" {
		t.Errorf("excludes = %v, want [{Hostname:cdn.example.com}]", excludes)
	}
}

func TestConfigure_MergeTLSPassthroughAddRemove(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	pl.Add("existing.com")
	pl.Add("to-remove.com")
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			TLSPassthrough: &configureTLSPassthrough{
				Add:    []string{"new-pinned.com", "*.new.com"},
				Remove: []string{"to-remove.com"},
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

	if out.TLSPassthrough == nil {
		t.Fatal("tls_passthrough is nil")
	}
	if out.TLSPassthrough.TotalPatterns != 3 {
		t.Errorf("total_patterns = %d, want 3", out.TLSPassthrough.TotalPatterns)
	}

	// Verify actual patterns.
	if pl.Contains("to-remove.com") {
		t.Error("to-remove.com should have been removed")
	}
	if !pl.Contains("existing.com") {
		t.Error("existing.com should still be present")
	}
	if !pl.Contains("new-pinned.com") {
		t.Error("new-pinned.com should have been added")
	}
}

func TestConfigure_MergeBothSections(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{{Hostname: "target.com"}},
			},
			TLSPassthrough: &configureTLSPassthrough{
				Add: []string{"pinned.com"},
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

	if out.CaptureScope == nil {
		t.Fatal("capture_scope is nil")
	}
	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1", out.CaptureScope.IncludeCount)
	}
	if out.TLSPassthrough == nil {
		t.Fatal("tls_passthrough is nil")
	}
	if out.TLSPassthrough.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TLSPassthrough.TotalPatterns)
	}
}

func TestConfigure_ReplaceCaptureScope(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "old.com"}, {Hostname: "old2.com"}},
		[]proxy.ScopeRule{{Hostname: "old-exclude.com"}},
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			CaptureScope: &configureCaptureScope{
				Includes: []scopeRuleInput{{Hostname: "*.target.com"}},
				Excludes: []scopeRuleInput{},
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

	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1", out.CaptureScope.IncludeCount)
	}
	if out.CaptureScope.ExcludeCount != 0 {
		t.Errorf("exclude_count = %d, want 0", out.CaptureScope.ExcludeCount)
	}

	includes, excludes := scope.Rules()
	if len(includes) != 1 || includes[0].Hostname != "*.target.com" {
		t.Errorf("includes = %v, want [{Hostname:*.target.com}]", includes)
	}
	if len(excludes) != 0 {
		t.Errorf("excludes = %v, want empty", excludes)
	}
}

func TestConfigure_ReplaceTLSPassthrough(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	pl.Add("old-1.com")
	pl.Add("old-2.com")
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			TLSPassthrough: &configureTLSPassthrough{
				Patterns: []string{"only-this.com"},
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

	if out.TLSPassthrough.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TLSPassthrough.TotalPatterns)
	}

	patterns := pl.List()
	if len(patterns) != 1 {
		t.Fatalf("patterns = %v, want [only-this.com]", patterns)
	}
	if !pl.Contains("only-this.com") {
		t.Error("only-this.com should be present")
	}
	if pl.Contains("old-1.com") {
		t.Error("old-1.com should have been removed")
	}
}

func TestConfigure_InvalidOperation(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "invalid",
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for invalid operation, got success")
	}
}

func TestConfigure_NilScope(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, nil, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{{Hostname: "example.com"}},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil scope, got success")
	}
}

func TestConfigure_NilPassthrough(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupConfigureTestSession(t, scope, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			TLSPassthrough: &configureTLSPassthrough{
				Add: []string{"example.com"},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil passthrough, got success")
	}
}

func TestConfigure_DefaultOperationIsMerge(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	// Omit operation field; should default to merge.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{{Hostname: "example.com"}},
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
	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1", out.CaptureScope.IncludeCount)
	}
}

func TestConfigure_EmptyInput(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	// No capture_scope or tls_passthrough specified; should succeed with no changes.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
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
	if out.CaptureScope != nil {
		t.Errorf("capture_scope should be nil when not specified, got %+v", out.CaptureScope)
	}
	if out.TLSPassthrough != nil {
		t.Errorf("tls_passthrough should be nil when not specified, got %+v", out.TLSPassthrough)
	}
}

func TestConfigure_MergeDuplicateAddIgnored(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "existing.com"}},
		nil,
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	// Adding a rule that already exists should not create a duplicate.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{{Hostname: "existing.com"}},
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

	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1 (duplicate should be ignored)", out.CaptureScope.IncludeCount)
	}
}

func TestConfigure_MergeRemoveNonexistent(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "keep.com"}},
		nil,
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	// Removing a rule that doesn't exist should succeed without error.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				RemoveIncludes: []scopeRuleInput{{Hostname: "nonexistent.com"}},
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

	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1 (original rule should remain)", out.CaptureScope.IncludeCount)
	}
}

func TestConfigure_ReplaceNilScope(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, nil, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			CaptureScope: &configureCaptureScope{
				Includes: []scopeRuleInput{{Hostname: "example.com"}},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil scope in replace, got success")
	}
}

func TestConfigure_ReplaceNilPassthrough(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupConfigureTestSession(t, scope, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			TLSPassthrough: &configureTLSPassthrough{
				Patterns: []string{"example.com"},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for nil passthrough in replace, got success")
	}
}

func TestConfigure_MergeScopeRuleWithAllFields(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "api.example.com", URLPrefix: "/v1/", Method: "POST"}},
		nil,
	)
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	// Remove rule that matches all fields exactly.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				RemoveIncludes: []scopeRuleInput{
					{Hostname: "api.example.com", URLPrefix: "/v1/", Method: "POST"},
				},
				AddIncludes: []scopeRuleInput{
					{Hostname: "api.example.com", URLPrefix: "/v2/", Method: "GET"},
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

	if out.CaptureScope.IncludeCount != 1 {
		t.Errorf("include_count = %d, want 1", out.CaptureScope.IncludeCount)
	}

	includes, _ := scope.Rules()
	if len(includes) != 1 {
		t.Fatalf("includes = %d, want 1", len(includes))
	}
	if includes[0].Hostname != "api.example.com" || includes[0].URLPrefix != "/v2/" || includes[0].Method != "GET" {
		t.Errorf("includes[0] = %+v, want {Hostname:api.example.com URLPrefix:/v2/ Method:GET}", includes[0])
	}
}

func TestConfigure_ReplaceTLSPassthroughEmptyList(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	pl.Add("a.com")
	pl.Add("b.com")
	cs := setupConfigureTestSession(t, scope, pl)

	// Replace with empty list should clear all patterns.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			TLSPassthrough: &configureTLSPassthrough{
				Patterns: []string{},
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

	if out.TLSPassthrough.TotalPatterns != 0 {
		t.Errorf("total_patterns = %d, want 0", out.TLSPassthrough.TotalPatterns)
	}
	if pl.Len() != 0 {
		t.Errorf("passthrough.Len() = %d, want 0", pl.Len())
	}
}

func TestConfigure_MergeRejectsEmptyAddIncludeRule(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddIncludes: []scopeRuleInput{
					{Hostname: "valid.com"},
					{}, // all-empty rule
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for all-empty add_includes rule, got success")
	}

	// Scope should not have been modified.
	includes, _ := scope.Rules()
	if len(includes) != 0 {
		t.Errorf("scope should remain empty after validation failure, got %d includes", len(includes))
	}
}

func TestConfigure_MergeRejectsEmptyAddExcludeRule(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			CaptureScope: &configureCaptureScope{
				AddExcludes: []scopeRuleInput{
					{}, // all-empty rule
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for all-empty add_excludes rule, got success")
	}
}

func TestConfigure_ReplaceRejectsEmptyIncludeRule(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			CaptureScope: &configureCaptureScope{
				Includes: []scopeRuleInput{
					{Hostname: "valid.com"},
					{}, // all-empty rule
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for all-empty include rule in replace, got success")
	}
}

func TestConfigure_ReplaceRejectsEmptyExcludeRule(t *testing.T) {
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, scope, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "replace",
			CaptureScope: &configureCaptureScope{
				Excludes: []scopeRuleInput{
					{}, // all-empty rule
				},
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for all-empty exclude rule in replace, got success")
	}
}
