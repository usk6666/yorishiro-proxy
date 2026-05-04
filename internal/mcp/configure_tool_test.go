package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupConfigureTestSession creates a connected MCP client session for configure tool tests.
func setupConfigureTestSession(t *testing.T, pl *proxy.PassthroughList) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
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

func TestConfigure_MergeTLSPassthroughAddRemove(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("existing.com")
	pl.Add("to-remove.com")
	cs := setupConfigureTestSession(t, pl)

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

func TestConfigure_ReplaceTLSPassthrough(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("old-1.com")
	pl.Add("old-2.com")
	cs := setupConfigureTestSession(t, pl)

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

func TestConfigure_ReplaceTLSPassthroughEmptyList(t *testing.T) {
	pl := proxy.NewPassthroughList()
	pl.Add("existing.com")
	cs := setupConfigureTestSession(t, pl)

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

	if pl.Contains("existing.com") {
		t.Error("existing.com should have been cleared by replace with empty list")
	}
}

func TestConfigure_InvalidOperation(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "invalid",
		}),
	})
	if err != nil {
		return
	}
	if !result.IsError {
		t.Fatal("expected error for invalid operation, got success")
	}
}

func TestConfigure_NilPassthrough(t *testing.T) {
	cs := setupConfigureTestSession(t, nil)

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
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nil passthrough, got success")
	}
}

func TestConfigure_ReplaceNilPassthrough(t *testing.T) {
	cs := setupConfigureTestSession(t, nil)

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
		return
	}
	if !result.IsError {
		t.Fatal("expected error for nil passthrough on replace, got success")
	}
}

func TestConfigure_DefaultOperationIsMerge(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, pl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			TLSPassthrough: &configureTLSPassthrough{
				Add: []string{"example.com"},
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
	if out.TLSPassthrough.TotalPatterns != 1 {
		t.Errorf("total_patterns = %d, want 1", out.TLSPassthrough.TotalPatterns)
	}
}

func TestConfigure_EmptyInput(t *testing.T) {
	pl := proxy.NewPassthroughList()
	cs := setupConfigureTestSession(t, pl)

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
	if out.TLSPassthrough != nil {
		t.Errorf("tls_passthrough should be nil when not specified, got %+v", out.TLSPassthrough)
	}
}
