package mcp

import (
	"context"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestConfigure_CaptureScope_ReplaceThenMerge exercises the configure
// tool capture_scope action across both operations and asserts the result
// summary echoes the right include/exclude counts. Mirrors the legacy
// USK-63 surface that USK-705 deleted; restored under USK-776.
func TestConfigure_CaptureScope_ReplaceThenMerge(t *testing.T) {
	cs := setupConfigureTestSession(t, nil)

	// Replace: install a known-good rule set.
	replaceArgs := configureMarshal(t, configureInput{
		Operation: "replace",
		CaptureScope: &configureCaptureScope{
			Includes: []scopeRuleInput{
				{Hostname: "*.target.com"},
				{Hostname: "api2.target.com", URLPrefix: "/api/"},
			},
			Excludes: []scopeRuleInput{
				{Hostname: "static.target.com"},
			},
		},
	})
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure", Arguments: replaceArgs,
	})
	if err != nil {
		t.Fatalf("configure replace: %v", err)
	}
	if res.IsError {
		t.Fatalf("configure replace failed: %s", textContent(res))
	}
	var out configureResult
	configureUnmarshalResult(t, res, &out)
	if out.CaptureScope == nil || out.CaptureScope.Includes != 2 || out.CaptureScope.Excludes != 1 {
		t.Fatalf("after replace: capture_scope = %+v, want {Includes:2 Excludes:1}", out.CaptureScope)
	}

	// Merge: add an include and remove the exclude.
	mergeArgs := configureMarshal(t, configureInput{
		Operation: "merge",
		CaptureScope: &configureCaptureScope{
			AddIncludes: []scopeRuleInput{
				{Hostname: "another.target.com"},
			},
			RemoveExcludes: []scopeRuleInput{
				{Hostname: "static.target.com"},
			},
		},
	})
	res, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure", Arguments: mergeArgs,
	})
	if err != nil {
		t.Fatalf("configure merge: %v", err)
	}
	if res.IsError {
		t.Fatalf("configure merge failed: %s", textContent(res))
	}
	configureUnmarshalResult(t, res, &out)
	if out.CaptureScope == nil || out.CaptureScope.Includes != 3 || out.CaptureScope.Excludes != 0 {
		t.Fatalf("after merge: capture_scope = %+v, want {Includes:3 Excludes:0}", out.CaptureScope)
	}
}

func TestConfigure_CaptureScope_RejectsEmptyRule(t *testing.T) {
	cs := setupConfigureTestSession(t, nil)

	args := configureMarshal(t, configureInput{
		Operation: "replace",
		CaptureScope: &configureCaptureScope{
			Includes: []scopeRuleInput{{}}, // all fields empty — invalid.
		},
	})
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure", Arguments: args,
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected validation error for empty rule, got result %+v", res)
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if res != nil {
		msg += " " + textContent(res)
	}
	if !strings.Contains(msg, "capture_scope") || !strings.Contains(msg, "at least one") {
		t.Errorf("error message should reference capture_scope and the at-least-one rule; got %q", msg)
	}
}

func textContent(r *gomcp.CallToolResult) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}
