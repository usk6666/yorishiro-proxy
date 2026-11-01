//go:build e2e && !e2e_smoke

// USK-1120: the -mcp-tools allowlist over the stdio MCP transport of the
// production binary.
package main_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestE2E_Binary_StdioMCPToolAllowlist(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()

	cmd := exec.Command(binary, "server",
		"-stdio-mcp", "-no-http-mcp",
		"-mcp-tools", "resend_http,fuzz_http,query",
		"-db", filepath.Join(dir, "stdio.db"),
		"-ca-ephemeral",
		"-log-level", "error",
	)
	cmd.Env = binaryChildEnv(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1120-stdio", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &gomcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	got := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		got = append(got, tool.Name)
	}
	slices.Sort(got)
	if want := []string{"fuzz_http", "query", "resend_http"}; !slices.Equal(got, want) {
		t.Errorf("stdio tools/list = %v, want %v", got, want)
	}

	_, err = cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: map[string]any{"request_timeout_ms": 4321},
	})
	if err == nil || !strings.Contains(err.Error(), `unknown tool "configure"`) {
		t.Errorf("stdio tools/call configure: err = %v, want unknown tool \"configure\"", err)
	}

	res, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil || res.IsError {
		t.Errorf("stdio tools/call query (allowed): err = %v isError = %v text = %q", err, res != nil && res.IsError, stdioText(res))
	}
}
