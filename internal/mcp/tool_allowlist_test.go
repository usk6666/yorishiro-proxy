package mcp

import (
	"context"
	"slices"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectAllowlistSession connects an in-memory client to a Server built
// with opts and returns the session.
func connectAllowlistSession(t *testing.T, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	s := newServer(ctx, nil, nil, nil, opts...)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "allowlist-test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// listedToolNames returns the sorted tool names from tools/list.
func listedToolNames(t *testing.T, cs *gomcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// TestToolNames_MatchesRegisteredTools pins ToolNames() to what a default
// NewServer actually registers, so a new tool cannot be added without
// becoming nameable in the allowlist (and vice versa).
func TestToolNames_MatchesRegisteredTools(t *testing.T) {
	got := slices.Clone(ToolNames())
	slices.Sort(got)
	want := listedToolNames(t, connectAllowlistSession(t))
	if len(want) == 0 {
		t.Fatal("default server registered no tools")
	}
	if !slices.Equal(got, want) {
		t.Errorf("ToolNames() = %v\nregistered tools = %v", got, want)
	}
}

// TestToolAllowlist_EachNameAlone checks that every canonical name can be
// allowed on its own and that it is then the only tool listed.
func TestToolAllowlist_EachNameAlone(t *testing.T) {
	names := ToolNames()
	if len(names) == 0 {
		t.Fatal("ToolNames() is empty")
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			got := listedToolNames(t, connectAllowlistSession(t, WithToolAllowlist([]string{n})))
			if !slices.Equal(got, []string{n}) {
				t.Errorf("allowlist [%s]: tools/list = %v, want [%s]", n, got, n)
			}
		})
	}
}

// TestToolAllowlist_HidesAndRejectsUnlistedTools is acceptance criteria 1
// and 2 at the in-memory seam: only the three allowed tools are listed and
// a direct call to configure is refused as an unknown tool.
func TestToolAllowlist_HidesAndRejectsUnlistedTools(t *testing.T) {
	cs := connectAllowlistSession(t, WithToolAllowlist([]string{"resend_http", "fuzz_http", "query"}))

	got := listedToolNames(t, cs)
	want := []string{"fuzz_http", "query", "resend_http"}
	if !slices.Equal(got, want) {
		t.Errorf("tools/list = %v, want %v", got, want)
	}

	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: map[string]any{"request_timeout_ms": 1234},
	})
	if err == nil || !strings.Contains(err.Error(), `unknown tool "configure"`) {
		t.Errorf("tools/call configure: err = %v, want unknown tool \"configure\"", err)
	}

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil || res.IsError {
		t.Errorf("tools/call query (allowed): err = %v, isError = %v", err, res != nil && res.IsError)
	}
}

// TestToolAllowlist_NilListsAllTools is acceptance criterion 3: a nil
// allowlist leaves the full tool set registered.
func TestToolAllowlist_NilListsAllTools(t *testing.T) {
	all := listedToolNames(t, connectAllowlistSession(t))
	got := listedToolNames(t, connectAllowlistSession(t, WithToolAllowlist(nil)))
	if !slices.Equal(got, all) {
		t.Errorf("WithToolAllowlist(nil): tools/list = %v, want all %v", got, all)
	}
}

func TestValidateToolAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		wantErr string
	}{
		{name: "nil", in: nil},
		{name: "known names", in: []string{"query", "resend_http"}},
		{name: "duplicates tolerated", in: []string{"query", "query"}},
		{name: "unknown", in: []string{"query", "nope"}, wantErr: `"nope"`},
		{name: "case sensitive", in: []string{"Query"}, wantErr: `"Query"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateToolAllowlist(tt.in)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ValidateToolAllowlist(%v) = %v, want nil", tt.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateToolAllowlist(%v) = nil, want error naming %s", tt.in, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not name %s", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "resend_http") || !strings.Contains(err.Error(), "configure") {
				t.Errorf("error %q does not list the valid tool names", err)
			}
		})
	}
}
