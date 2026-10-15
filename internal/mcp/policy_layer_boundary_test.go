package mcp

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestPolicyLayer_NotWritableFromMCP is the static half of USK-1115
// acceptance criterion 3: the agent-facing MCP server (one gomcp.Server
// behind both stdio and HTTP) must have no path that writes the Policy
// Layer. Every Policy Layer writer on the three engines is named
// SetPolicy* / ReplacePolicy* (TargetScope.SetPolicyRules /
// ReplacePolicyRules / SetPolicyOrigin, RateLimiter.SetPolicyLimits,
// BudgetManager.SetPolicyBudget / ReplacePolicyBudget); the only runtime
// writer is internal/mcpserver's SIGHUP-driven reloader. This test parses
// every non-test Go file under internal/mcp and fails on any call to such a
// method.
func TestPolicyLayer_NotWritableFromMCP(t *testing.T) {
	fset := token.NewFileSet()
	var violations []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			if strings.HasPrefix(name, "SetPolicy") || strings.HasPrefix(name, "ReplacePolicy") {
				violations = append(violations, fset.Position(sel.Pos()).String()+": "+name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/mcp: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf("internal/mcp references a Policy Layer writer; the agent-facing MCP must not modify the Policy Layer:\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestSecurity_GetTargetScope_ReportsPolicyOrigin is T12: get_target_scope
// reports where the Policy Layer actually came from and when it was last
// installed, instead of a hardcoded "config file". immutable stays true —
// it means "immutable by the agent".
func TestSecurity_GetTargetScope_ReportsPolicyOrigin(t *testing.T) {
	loadedAt := time.Date(2026, 10, 16, 9, 30, 0, 123, time.UTC)
	ts := connector.NewTargetScope()
	ts.ReplacePolicyRules([]connector.TargetRule{{Hostname: "*.target.com"}}, nil,
		connector.PolicyOrigin{Source: "policy file", LoadedAt: loadedAt})
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "security",
		Arguments: securityMarshal(t, securityInput{Action: "get_target_scope"}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var got getTargetScopeResult
	securityUnmarshalResult(t, result, &got)

	if got.Policy.Source != "policy file" {
		t.Errorf("policy.source = %q, want \"policy file\"", got.Policy.Source)
	}
	if want := loadedAt.Format(time.RFC3339Nano); got.Policy.LoadedAt != want {
		t.Errorf("policy.loaded_at = %q, want %q", got.Policy.LoadedAt, want)
	}
	if !got.Policy.Immutable {
		t.Error("policy.immutable = false, want true (immutable by the agent)")
	}
	if len(got.Policy.Allows) != 1 || got.Policy.Allows[0].Hostname != "*.target.com" {
		t.Errorf("policy.allows = %+v, want [*.target.com]", got.Policy.Allows)
	}
}

// TestSecurity_GetTargetScope_ConfigFileSourceWithoutRules: a config file
// that defines no target_scope_policy is still the policy source — the
// origin is reported even when there are no rules.
func TestSecurity_GetTargetScope_ConfigFileSourceWithoutRules(t *testing.T) {
	ts := connector.NewTargetScope()
	ts.SetPolicyOrigin(connector.PolicyOrigin{Source: "config file", LoadedAt: time.Unix(1700000000, 0).UTC()})
	cs := setupSecurityTestSession(t, ts)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "security",
		Arguments: securityMarshal(t, securityInput{Action: "get_target_scope"}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var got getTargetScopeResult
	securityUnmarshalResult(t, result, &got)
	if got.Policy.Source != "config file" {
		t.Errorf("policy.source = %q, want \"config file\"", got.Policy.Source)
	}
	if got.Policy.LoadedAt != "2023-11-14T22:13:20Z" {
		t.Errorf("policy.loaded_at = %q, want 2023-11-14T22:13:20Z", got.Policy.LoadedAt)
	}
}
