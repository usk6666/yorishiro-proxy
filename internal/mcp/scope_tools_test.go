package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// setupScopeTestSession creates a connected MCP client session with a CaptureScope for testing.
func setupScopeTestSession(t *testing.T, scope *proxy.CaptureScope) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ctx, nil, nil, nil, WithCaptureScope(scope))
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

// callScopeToolExpectError calls a scope tool and expects an error response.
func callScopeToolExpectError(t *testing.T, cs *gomcp.ClientSession, name string, args map[string]json.RawMessage) {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return // Go-level error is acceptable
	}
	if !result.IsError {
		t.Fatalf("CallTool(%s) expected error, got success", name)
	}
}

func TestSetCaptureScope_Success(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "set_capture_scope",
		Arguments: scopeMarshal(t, setCaptureInput{
			Includes: []scopeRuleInput{
				{Hostname: "example.com"},
				{Hostname: "*.target.com", Method: "POST"},
			},
			Excludes: []scopeRuleInput{
				{Hostname: "ads.target.com"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out setCaptureResult
	scopeUnmarshalResult(t, result, &out)

	if out.Status != "scope_updated" {
		t.Errorf("status = %q, want %q", out.Status, "scope_updated")
	}
	if out.IncludeCount != 2 {
		t.Errorf("include_count = %d, want 2", out.IncludeCount)
	}
	if out.ExcludeCount != 1 {
		t.Errorf("exclude_count = %d, want 1", out.ExcludeCount)
	}

	// Verify the scope was actually set.
	includes, excludes := scope.Rules()
	if len(includes) != 2 {
		t.Errorf("scope includes = %d, want 2", len(includes))
	}
	if len(excludes) != 1 {
		t.Errorf("scope excludes = %d, want 1", len(excludes))
	}
}

func TestSetCaptureScope_EmptyRules(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	callScopeToolExpectError(t, cs, "set_capture_scope",
		scopeMarshal(t, setCaptureInput{}))
}

func TestSetCaptureScope_EmptyFieldsInRule(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	callScopeToolExpectError(t, cs, "set_capture_scope",
		scopeMarshal(t, setCaptureInput{
			Includes: []scopeRuleInput{{}},
		}))
}

func TestSetCaptureScope_NilScope(t *testing.T) {
	cs := setupScopeTestSession(t, nil)

	callScopeToolExpectError(t, cs, "set_capture_scope",
		scopeMarshal(t, setCaptureInput{
			Includes: []scopeRuleInput{{Hostname: "example.com"}},
		}))
}

func TestGetCaptureScope_Empty(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "get_capture_scope",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getCaptureResult
	scopeUnmarshalResult(t, result, &out)

	if len(out.Includes) != 0 {
		t.Errorf("includes = %d, want 0", len(out.Includes))
	}
	if len(out.Excludes) != 0 {
		t.Errorf("excludes = %d, want 0", len(out.Excludes))
	}
}

func TestGetCaptureScope_WithRules(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "example.com", Method: "GET"}},
		[]proxy.ScopeRule{{URLPrefix: "/admin/"}},
	)
	cs := setupScopeTestSession(t, scope)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "get_capture_scope",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getCaptureResult
	scopeUnmarshalResult(t, result, &out)

	if len(out.Includes) != 1 {
		t.Fatalf("includes = %d, want 1", len(out.Includes))
	}
	if out.Includes[0].Hostname != "example.com" {
		t.Errorf("includes[0].hostname = %q, want %q", out.Includes[0].Hostname, "example.com")
	}
	if out.Includes[0].Method != "GET" {
		t.Errorf("includes[0].method = %q, want %q", out.Includes[0].Method, "GET")
	}

	if len(out.Excludes) != 1 {
		t.Fatalf("excludes = %d, want 1", len(out.Excludes))
	}
	if out.Excludes[0].URLPrefix != "/admin/" {
		t.Errorf("excludes[0].url_prefix = %q, want %q", out.Excludes[0].URLPrefix, "/admin/")
	}
}

func TestGetCaptureScope_NilScope(t *testing.T) {
	cs := setupScopeTestSession(t, nil)

	callScopeToolExpectError(t, cs, "get_capture_scope", nil)
}

func TestClearCaptureScope_Success(t *testing.T) {
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "example.com"}},
		[]proxy.ScopeRule{{Hostname: "other.com"}},
	)
	cs := setupScopeTestSession(t, scope)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "clear_capture_scope",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out clearCaptureResult
	scopeUnmarshalResult(t, result, &out)

	if out.Status != "scope_cleared" {
		t.Errorf("status = %q, want %q", out.Status, "scope_cleared")
	}

	// Verify the scope was actually cleared.
	if !scope.IsEmpty() {
		t.Error("scope should be empty after clear")
	}
}

func TestClearCaptureScope_NilScope(t *testing.T) {
	cs := setupScopeTestSession(t, nil)

	callScopeToolExpectError(t, cs, "clear_capture_scope", nil)
}

func TestSetCaptureScope_ReplaceExisting(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	// Set initial rules.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "set_capture_scope",
		Arguments: scopeMarshal(t, setCaptureInput{
			Includes: []scopeRuleInput{{Hostname: "old.com"}},
		}),
	})
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("first call: expected success, got error: %v", result.Content)
	}

	// Replace with new rules.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "set_capture_scope",
		Arguments: scopeMarshal(t, setCaptureInput{
			Includes: []scopeRuleInput{{Hostname: "new.com"}},
			Excludes: []scopeRuleInput{{Method: "DELETE"}},
		}),
	})
	if err != nil {
		t.Fatalf("second CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("second call: expected success, got error: %v", result.Content)
	}

	includes, excludes := scope.Rules()
	if len(includes) != 1 || includes[0].Hostname != "new.com" {
		t.Errorf("includes should be replaced, got %v", includes)
	}
	if len(excludes) != 1 || excludes[0].Method != "DELETE" {
		t.Errorf("excludes should be set, got %v", excludes)
	}
}

func TestSetCaptureScope_ExcludeEmptyFieldValidation(t *testing.T) {
	scope := proxy.NewCaptureScope()
	cs := setupScopeTestSession(t, scope)

	callScopeToolExpectError(t, cs, "set_capture_scope",
		scopeMarshal(t, setCaptureInput{
			Excludes: []scopeRuleInput{{}},
		}))
}

// scopeMarshal marshals v to JSON Arguments map for scope tool tests.
func scopeMarshal(t *testing.T, v any) map[string]json.RawMessage {
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

// scopeUnmarshalResult extracts the structured result from CallToolResult content.
func scopeUnmarshalResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	// The go-sdk returns JSON as text content (pointer type).
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), dest); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}
