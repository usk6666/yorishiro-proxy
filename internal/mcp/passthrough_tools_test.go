package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// setupTestSessionWithPassthrough creates an MCP client session with a PassthroughList for testing.
func setupTestSessionWithPassthrough(t *testing.T, pl *proxy.PassthroughList) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if pl != nil {
		opts = append(opts, WithPassthroughList(pl))
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

func TestAddTLSPassthrough_Success(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "add_tls_passthrough",
		Arguments: map[string]any{"pattern": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out addTLSPassthroughResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TotalPatterns)
	}

	// Verify pattern was added to the list.
	if !pl.Contains("example.com") {
		t.Error("expected pattern to be in list")
	}
}

func TestAddTLSPassthrough_Wildcard(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "add_tls_passthrough",
		Arguments: map[string]any{"pattern": "*.example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if !pl.Contains("foo.example.com") {
		t.Error("expected wildcard pattern to match subdomain")
	}
	if pl.Contains("example.com") {
		t.Error("wildcard should not match exact domain")
	}
}

func TestAddTLSPassthrough_EmptyPattern(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "add_tls_passthrough",
		Arguments: map[string]any{"pattern": ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty pattern")
	}
}

func TestAddTLSPassthrough_NilPassthroughList(t *testing.T) {
	cs := setupTestSessionWithPassthrough(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "add_tls_passthrough",
		Arguments: map[string]any{"pattern": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil passthrough list")
	}
}

func TestRemoveTLSPassthrough_Success(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("example.com")
	pl.Add("other.com")

	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "remove_tls_passthrough",
		Arguments: map[string]any{"pattern": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out removeTLSPassthroughResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !out.Removed {
		t.Error("expected removed = true")
	}
	if out.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TotalPatterns)
	}

	if pl.Contains("example.com") {
		t.Error("expected pattern to be removed from list")
	}
	if !pl.Contains("other.com") {
		t.Error("expected other pattern to still be in list")
	}
}

func TestRemoveTLSPassthrough_NotFound(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("example.com")

	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "remove_tls_passthrough",
		Arguments: map[string]any{"pattern": "notfound.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out removeTLSPassthroughResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Removed {
		t.Error("expected removed = false for non-existent pattern")
	}
	if out.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TotalPatterns)
	}
}

func TestRemoveTLSPassthrough_EmptyPattern(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "remove_tls_passthrough",
		Arguments: map[string]any{"pattern": ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty pattern")
	}
}

func TestRemoveTLSPassthrough_NilPassthroughList(t *testing.T) {
	cs := setupTestSessionWithPassthrough(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "remove_tls_passthrough",
		Arguments: map[string]any{"pattern": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil passthrough list")
	}
}

func TestListTLSPassthrough_Empty(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_tls_passthrough",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listTLSPassthroughResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if len(out.Patterns) != 0 {
		t.Errorf("patterns len = %d, want 0", len(out.Patterns))
	}
}

func TestListTLSPassthrough_WithPatterns(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("beta.com")
	pl.Add("alpha.com")
	pl.Add("*.gamma.com")

	cs := setupTestSessionWithPassthrough(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_tls_passthrough",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listTLSPassthroughResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}

	// Patterns should be sorted alphabetically.
	want := []string{"*.gamma.com", "alpha.com", "beta.com"}
	if len(out.Patterns) != len(want) {
		t.Fatalf("patterns len = %d, want %d", len(out.Patterns), len(want))
	}
	for i, p := range out.Patterns {
		if p != want[i] {
			t.Errorf("patterns[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestListTLSPassthrough_NilPassthroughList(t *testing.T) {
	cs := setupTestSessionWithPassthrough(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_tls_passthrough",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil passthrough list")
	}
}

func TestTLSPassthrough_AddRemoveListCycle(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupTestSessionWithPassthrough(t, pl)

	// Add two patterns.
	for _, pattern := range []string{"example.com", "*.cdn.example.com"} {
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name:      "add_tls_passthrough",
			Arguments: map[string]any{"pattern": pattern},
		})
		if err != nil {
			t.Fatalf("CallTool add %q: %v", pattern, err)
		}
		if result.IsError {
			t.Fatalf("expected success for add %q: %v", pattern, result.Content)
		}
	}

	// List and verify.
	listResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_tls_passthrough",
	})
	if err != nil {
		t.Fatalf("CallTool list: %v", err)
	}
	var listOut listTLSPassthroughResult
	textContent := listResult.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &listOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if listOut.Count != 2 {
		t.Errorf("count = %d, want 2", listOut.Count)
	}

	// Remove one.
	removeResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "remove_tls_passthrough",
		Arguments: map[string]any{"pattern": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool remove: %v", err)
	}
	var removeOut removeTLSPassthroughResult
	textContent = removeResult.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &removeOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !removeOut.Removed {
		t.Error("expected removed = true")
	}
	if removeOut.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", removeOut.TotalPatterns)
	}

	// List again and verify only one remains.
	listResult, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_tls_passthrough",
	})
	if err != nil {
		t.Fatalf("CallTool list: %v", err)
	}
	textContent = listResult.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &listOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if listOut.Count != 1 {
		t.Errorf("count = %d, want 1", listOut.Count)
	}
	if len(listOut.Patterns) != 1 || listOut.Patterns[0] != "*.cdn.example.com" {
		t.Errorf("patterns = %v, want [*.cdn.example.com]", listOut.Patterns)
	}
}
