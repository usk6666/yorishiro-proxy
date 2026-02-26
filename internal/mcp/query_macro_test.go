package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// setupMacroQueryTestSession creates an MCP client session for macro query tests.
func setupMacroQueryTestSession(t *testing.T, store session.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ctx, nil, store, nil)
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

// callQueryRaw invokes the query tool with raw arguments.
func callQueryRaw(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// unmarshalQueryResultRaw extracts the JSON result from CallToolResult.
func unmarshalQueryResultRaw(t *testing.T, result *gomcp.CallToolResult, dest any) {
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

func TestQuery_Macros_Empty(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroQueryTestSession(t, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macros",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryMacrosResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 0 {
		t.Errorf("Count = %d, want 0", out.Count)
	}
	if len(out.Macros) != 0 {
		t.Errorf("len(Macros) = %d, want 0", len(out.Macros))
	}
}

func TestQuery_Macros_WithEntries(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Define macros directly in the store.
	if err := store.SaveMacro(ctx, "alpha", "Alpha macro", `{"steps":[{"id":"s1","session_id":"sess-1"}]}`); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}
	if err := store.SaveMacro(ctx, "beta", "Beta macro", `{"steps":[{"id":"s1","session_id":"sess-1"},{"id":"s2","session_id":"sess-2"}]}`); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	cs := setupMacroQueryTestSession(t, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macros",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryMacrosResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 2 {
		t.Errorf("Count = %d, want 2", out.Count)
	}
	if len(out.Macros) != 2 {
		t.Fatalf("len(Macros) = %d, want 2", len(out.Macros))
	}

	// Should be ordered by name.
	if out.Macros[0].Name != "alpha" {
		t.Errorf("Macros[0].Name = %q, want %q", out.Macros[0].Name, "alpha")
	}
	if out.Macros[0].Description != "Alpha macro" {
		t.Errorf("Macros[0].Description = %q, want %q", out.Macros[0].Description, "Alpha macro")
	}
	if out.Macros[0].StepCount != 1 {
		t.Errorf("Macros[0].StepCount = %d, want 1", out.Macros[0].StepCount)
	}
	if out.Macros[1].Name != "beta" {
		t.Errorf("Macros[1].Name = %q, want %q", out.Macros[1].Name, "beta")
	}
	if out.Macros[1].StepCount != 2 {
		t.Errorf("Macros[1].StepCount = %d, want 2", out.Macros[1].StepCount)
	}
	if out.Macros[0].CreatedAt == "" {
		t.Error("Macros[0].CreatedAt is empty")
	}
	if out.Macros[0].UpdatedAt == "" {
		t.Error("Macros[0].UpdatedAt is empty")
	}
}

func TestQuery_Macro_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	configJSON := `{"steps":[{"id":"login","session_id":"sess-1","override_headers":{"Cookie":"test"},"extract":[{"name":"token","from":"response","source":"header","header_name":"X-Token"}]},{"id":"get-csrf","session_id":"sess-2","when":{"step":"login","status_code":200}}],"initial_vars":{"password":"admin123"},"timeout_ms":60000}`
	if err := store.SaveMacro(ctx, "auth-flow", "Full auth flow", configJSON); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	cs := setupMacroQueryTestSession(t, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macro",
		"id":       "auth-flow",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryMacroResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Name != "auth-flow" {
		t.Errorf("Name = %q, want %q", out.Name, "auth-flow")
	}
	if out.Description != "Full auth flow" {
		t.Errorf("Description = %q, want %q", out.Description, "Full auth flow")
	}
	if len(out.Steps) != 2 {
		t.Fatalf("len(Steps) = %d, want 2", len(out.Steps))
	}
	if out.Steps[0].ID != "login" {
		t.Errorf("Steps[0].ID = %q, want %q", out.Steps[0].ID, "login")
	}
	if out.Steps[0].SessionID != "sess-1" {
		t.Errorf("Steps[0].SessionID = %q, want %q", out.Steps[0].SessionID, "sess-1")
	}
	if len(out.Steps[0].Extract) != 1 {
		t.Errorf("Steps[0].Extract count = %d, want 1", len(out.Steps[0].Extract))
	}
	if out.Steps[1].ID != "get-csrf" {
		t.Errorf("Steps[1].ID = %q, want %q", out.Steps[1].ID, "get-csrf")
	}
	if out.Steps[1].When == nil {
		t.Error("Steps[1].When is nil, expected guard")
	}
	if out.InitialVars["password"] != "admin123" {
		t.Errorf("InitialVars[password] = %q, want %q", out.InitialVars["password"], "admin123")
	}
	if out.TimeoutMs != 60000 {
		t.Errorf("TimeoutMs = %d, want 60000", out.TimeoutMs)
	}
	if out.CreatedAt == "" {
		t.Error("CreatedAt is empty")
	}
}

func TestQuery_Macro_NotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroQueryTestSession(t, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macro",
		"id":       "nonexistent",
	})

	if !result.IsError {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestQuery_Macro_MissingID(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroQueryTestSession(t, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macro",
	})

	if !result.IsError {
		t.Fatal("expected error for missing id")
	}
}

func TestQuery_Macros_NoStore(t *testing.T) {
	ctx := context.Background()
	s := NewServer(ctx, nil, nil, nil)
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

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "macros",
	})

	if !result.IsError {
		t.Fatal("expected error when store is nil")
	}
}
