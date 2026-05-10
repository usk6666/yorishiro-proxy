package mcp

// Tests for USK-794: configure rejects field/operation mismatches across
// the three sections that share the merge-vs-replace shape
// (tls_passthrough, intercept_rules, auto_transform).
//
// Previously, supplying a replace-only field (Patterns / Rules) while the
// configure operation was merge silently dropped the field with no
// mutation; supplying a merge-only field (Add / Remove / Enable / Disable)
// while the operation was replace did the same. Both directions now
// return a structured error before any state mutation runs, so
// multi-section configure calls reject as a unit.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// configureMismatchSession spins up a server with all three sections wired so
// every rejection path is exercisable from the same harness. The session is
// reused across direct CallTool invocations within a test.
func configureMismatchSession(t *testing.T) (*gomcp.ClientSession, *connector.PassthroughList, *httprules.InterceptEngine, *httprules.TransformEngine) {
	t.Helper()
	ctx := context.Background()

	pl := connector.NewPassthroughList()
	hold := common.NewHoldQueue()
	httpInter := httprules.NewInterceptEngine()
	wsInter := wsrules.NewInterceptEngine()
	grpcInter := grpcrules.NewInterceptEngine()
	transformEngine := httprules.NewTransformEngine()

	opts := []ServerOption{
		WithPassthroughList(pl),
		WithHoldQueue(hold),
		WithHTTPInterceptEngine(httpInter),
		WithWSInterceptEngine(wsInter),
		WithGRPCInterceptEngine(grpcInter),
		WithHTTPTransformEngine(transformEngine),
	}

	s := newServer(ctx, nil, nil, nil, opts...)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, pl, httpInter, transformEngine
}

// callConfigure is a thin wrapper that calls the configure tool with the
// supplied input and returns the raw result. Errors raised by the
// transport layer fail the test; tool-level errors surface via
// result.IsError so individual tests can assert the rejection path.
func callConfigure(t *testing.T, cs *gomcp.ClientSession, in configureInput) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: configureMarshal(t, in),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// callConfigureRawJSON sends a raw JSON payload as the configure tool
// arguments. This bypasses Go's json.Marshal "omitempty" stripping of
// empty slices, which is required to faithfully exercise the
// `patterns:[]` / `rules:[]` empty-list rejection paths — Go's marshal
// drops `[]` identically to nil, but a real client (e.g. an AI agent
// emitting hand-built JSON) sends `[]` literally. The server's decode
// of `[]` into `[]string` produces a non-nil empty slice, which the
// validator distinguishes from a missing field via the `!= nil` check.
func callConfigureRawJSON(t *testing.T, cs *gomcp.ClientSession, payload string) *gomcp.CallToolResult {
	t.Helper()
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &args); err != nil {
		t.Fatalf("invalid raw JSON payload: %v", err)
	}
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "configure",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// assertErrorContains asserts that the call reported a tool-level error
// whose flattened text contains every supplied substring.
func assertErrorContains(t *testing.T, result *gomcp.CallToolResult, substrs ...string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected error result, got success: %+v", result.Content)
	}
	body := flattenContent(result.Content)
	for _, s := range substrs {
		if !strings.Contains(body, s) {
			t.Errorf("error text missing %q; got: %s", s, body)
		}
	}
}

// --------------------------------------------------------------------------
// tls_passthrough
// --------------------------------------------------------------------------

func TestConfigure_TLSPassthrough_Merge_RejectsReplaceOnlyPatternsEmpty(t *testing.T) {
	cs, pl, _, _ := configureMismatchSession(t)
	pl.Add("preexisting.com")

	// Raw JSON: Go marshal would strip the empty Patterns slice via
	// omitempty, defeating the test. Real clients send the literal []
	// they typed.
	result := callConfigureRawJSON(t, cs,
		`{"operation":"merge","tls_passthrough":{"patterns":[]}}`)
	assertErrorContains(t, result, "tls_passthrough", "patterns", "replace")
	if !pl.Contains("preexisting.com") {
		t.Error("preexisting.com must remain — validation failure must not mutate state")
	}
}

func TestConfigure_TLSPassthrough_Merge_RejectsReplaceOnlyPatternsNonEmpty(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "merge",
		TLSPassthrough: &configureTLSPassthrough{
			Patterns: []string{"x.com"},
		},
	})
	assertErrorContains(t, result, "tls_passthrough", "patterns", "replace")
}

func TestConfigure_TLSPassthrough_DefaultMerge_RejectsReplaceOnlyPatterns(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	// No Operation field — defaults to merge. Empty Patterns: must use
	// raw JSON (omitempty would strip the slice otherwise).
	result := callConfigureRawJSON(t, cs,
		`{"tls_passthrough":{"patterns":[]}}`)
	assertErrorContains(t, result, "tls_passthrough", "patterns", "replace")
}

func TestConfigure_TLSPassthrough_Replace_RejectsMergeOnlyAdd(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		TLSPassthrough: &configureTLSPassthrough{
			Add: []string{"x.com"},
		},
	})
	assertErrorContains(t, result, "tls_passthrough", "add", "merge")
}

func TestConfigure_TLSPassthrough_Replace_RejectsMergeOnlyRemove(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		TLSPassthrough: &configureTLSPassthrough{
			Remove: []string{"x.com"},
		},
	})
	assertErrorContains(t, result, "tls_passthrough", "remove", "merge")
}

// Regression guard: replace + patterns:[] must still clear correctly.
// Uses raw JSON because the literal {"patterns":[]} payload is exactly
// what an AI agent caller emits — Go's omitempty would otherwise drop
// the slice, and we want to confirm the literal-empty path stays
// healthy (this was the exact USK-794 reproduction shape).
func TestConfigure_TLSPassthrough_Replace_EmptyPatternsClears(t *testing.T) {
	cs, pl, _, _ := configureMismatchSession(t)
	pl.Add("clear-me.com")

	result := callConfigureRawJSON(t, cs,
		`{"operation":"replace","tls_passthrough":{"patterns":[]}}`)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if pl.Contains("clear-me.com") {
		t.Error("clear-me.com must have been removed by replace patterns:[]")
	}
}

// Regression guard: merge + add/remove must still apply deltas.
func TestConfigure_TLSPassthrough_Merge_AddRemoveStillWorks(t *testing.T) {
	cs, pl, _, _ := configureMismatchSession(t)
	pl.Add("to-remove.com")

	result := callConfigure(t, cs, configureInput{
		Operation: "merge",
		TLSPassthrough: &configureTLSPassthrough{
			Add:    []string{"new.com"},
			Remove: []string{"to-remove.com"},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if !pl.Contains("new.com") {
		t.Error("new.com must have been added")
	}
	if pl.Contains("to-remove.com") {
		t.Error("to-remove.com must have been removed")
	}
}

// --------------------------------------------------------------------------
// intercept_rules
// --------------------------------------------------------------------------

func TestConfigure_InterceptRules_Merge_RejectsReplaceOnlyRules(t *testing.T) {
	cs, _, httpInter, _ := configureMismatchSession(t)
	httpInter.SetRules([]httprules.InterceptRule{
		{ID: "preexisting", Enabled: true, Direction: httprules.DirectionBoth},
	})

	result := callConfigure(t, cs, configureInput{
		Operation: "merge",
		InterceptRules: &configureInterceptRules{
			Rules: []interceptRuleInput{
				{ID: "x", Enabled: true, Protocol: "http", Direction: "request",
					HTTP: &interceptHTTPConditions{PathPattern: "/.*"}},
			},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "rules", "replace")

	// Validation must not mutate the engine.
	if rs := httpInter.Rules(); len(rs) != 1 || rs[0].ID != "preexisting" {
		t.Errorf("engine state must be untouched; got %+v", rs)
	}
}

func TestConfigure_InterceptRules_Merge_RejectsReplaceOnlyRulesEmpty(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	// Raw JSON: see callConfigureRawJSON doc — empty rules slice would
	// be stripped by Go marshal via omitempty.
	result := callConfigureRawJSON(t, cs,
		`{"operation":"merge","intercept_rules":{"rules":[]}}`)
	assertErrorContains(t, result, "intercept_rules", "rules", "replace")
}

func TestConfigure_InterceptRules_Replace_RejectsMergeOnlyAdd(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		InterceptRules: &configureInterceptRules{
			Add: []interceptRuleInput{
				{ID: "x", Enabled: true, Protocol: "http", Direction: "request",
					HTTP: &interceptHTTPConditions{PathPattern: "/.*"}},
			},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "add", "merge")
}

func TestConfigure_InterceptRules_Replace_RejectsMergeOnlyRemove(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		InterceptRules: &configureInterceptRules{
			Remove: []string{"id"},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "remove", "merge")
}

func TestConfigure_InterceptRules_Replace_RejectsMergeOnlyEnable(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		InterceptRules: &configureInterceptRules{
			Enable: []string{"id"},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "enable", "merge")
}

func TestConfigure_InterceptRules_Replace_RejectsMergeOnlyDisable(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		InterceptRules: &configureInterceptRules{
			Disable: []string{"id"},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "disable", "merge")
}

// Regression guard: replace + rules:[] must still clear all engines.
// Raw JSON: see TestConfigure_TLSPassthrough_Replace_EmptyPatternsClears
// for rationale.
func TestConfigure_InterceptRules_Replace_EmptyRulesClears(t *testing.T) {
	cs, _, httpInter, _ := configureMismatchSession(t)
	httpInter.SetRules([]httprules.InterceptRule{
		{ID: "x", Enabled: true, Direction: httprules.DirectionBoth},
	})

	result := callConfigureRawJSON(t, cs,
		`{"operation":"replace","intercept_rules":{"rules":[]}}`)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if rs := httpInter.Rules(); len(rs) != 0 {
		t.Errorf("engine must be cleared by replace rules:[]; got %+v", rs)
	}
}

// --------------------------------------------------------------------------
// auto_transform
// --------------------------------------------------------------------------

func TestConfigure_AutoTransform_Merge_RejectsReplaceOnlyRules(t *testing.T) {
	cs, _, _, transformEngine := configureMismatchSession(t)
	transformEngine.AddRule(httprules.TransformRule{
		ID: "preexisting", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-Pre", HeaderValue: "1",
	})

	result := callConfigure(t, cs, configureInput{
		Operation: "merge",
		AutoTransform: &configureAutoTransform{
			Rules: []transformRuleInput{
				{ID: "r", Enabled: true, Direction: "request",
					ActionType: "add_header", HeaderName: "X-T", HeaderValue: "1"},
			},
		},
	})
	assertErrorContains(t, result, "auto_transform", "rules", "replace")

	// Validation must not mutate the engine.
	if rs := transformEngine.Rules(); len(rs) != 1 || rs[0].ID != "preexisting" {
		t.Errorf("engine state must be untouched; got %+v", rs)
	}
}

func TestConfigure_AutoTransform_Merge_RejectsReplaceOnlyRulesEmpty(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	// Raw JSON: see callConfigureRawJSON doc — empty rules slice would
	// be stripped by Go marshal via omitempty.
	result := callConfigureRawJSON(t, cs,
		`{"operation":"merge","auto_transform":{"rules":[]}}`)
	assertErrorContains(t, result, "auto_transform", "rules", "replace")
}

func TestConfigure_AutoTransform_Replace_RejectsMergeOnlyAdd(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		AutoTransform: &configureAutoTransform{
			Add: []transformRuleInput{
				{ID: "r", Enabled: true, Direction: "request",
					ActionType: "add_header", HeaderName: "X-T", HeaderValue: "1"},
			},
		},
	})
	assertErrorContains(t, result, "auto_transform", "add", "merge")
}

func TestConfigure_AutoTransform_Replace_RejectsMergeOnlyRemove(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		AutoTransform: &configureAutoTransform{
			Remove: []string{"id"},
		},
	})
	assertErrorContains(t, result, "auto_transform", "remove", "merge")
}

func TestConfigure_AutoTransform_Replace_RejectsMergeOnlyEnable(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		AutoTransform: &configureAutoTransform{
			Enable: []string{"id"},
		},
	})
	assertErrorContains(t, result, "auto_transform", "enable", "merge")
}

func TestConfigure_AutoTransform_Replace_RejectsMergeOnlyDisable(t *testing.T) {
	cs, _, _, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		AutoTransform: &configureAutoTransform{
			Disable: []string{"id"},
		},
	})
	assertErrorContains(t, result, "auto_transform", "disable", "merge")
}

// Regression guard: replace + rules:[] must still clear the engine.
// Raw JSON: see TestConfigure_TLSPassthrough_Replace_EmptyPatternsClears
// for rationale.
func TestConfigure_AutoTransform_Replace_EmptyRulesClears(t *testing.T) {
	cs, _, _, transformEngine := configureMismatchSession(t)
	transformEngine.AddRule(httprules.TransformRule{
		ID: "x", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X", HeaderValue: "1",
	})

	result := callConfigureRawJSON(t, cs,
		`{"operation":"replace","auto_transform":{"rules":[]}}`)
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	if rs := transformEngine.Rules(); len(rs) != 0 {
		t.Errorf("engine must be cleared by replace rules:[]; got %+v", rs)
	}
}

// --------------------------------------------------------------------------
// Cross-section: validation rejects multi-section calls atomically
// --------------------------------------------------------------------------

// TestConfigure_MultiSection_RejectAtomically supplies a valid section
// (tls_passthrough.add) alongside an invalid one
// (intercept_rules.rules) under merge. The invalid section must trigger
// an error and the valid section must NOT have mutated state — this
// verifies validation runs before any state mutation.
func TestConfigure_MultiSection_RejectAtomically(t *testing.T) {
	cs, pl, httpInter, _ := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "merge",
		TLSPassthrough: &configureTLSPassthrough{
			Add: []string{"never-applied.com"},
		},
		InterceptRules: &configureInterceptRules{
			Rules: []interceptRuleInput{
				{ID: "r", Enabled: true, Protocol: "http", Direction: "request",
					HTTP: &interceptHTTPConditions{PathPattern: "/.*"}},
			},
		},
	})
	assertErrorContains(t, result, "intercept_rules", "rules")

	if pl.Contains("never-applied.com") {
		t.Error("tls_passthrough.add must NOT have applied; validation failure must reject the whole call")
	}
	if rs := httpInter.Rules(); len(rs) != 0 {
		t.Errorf("intercept engine must be untouched; got %+v", rs)
	}
}

// TestConfigure_MultiSection_RejectAtomicallyReplace mirrors the
// previous test with replace mode.
func TestConfigure_MultiSection_RejectAtomicallyReplace(t *testing.T) {
	cs, pl, _, transformEngine := configureMismatchSession(t)

	result := callConfigure(t, cs, configureInput{
		Operation: "replace",
		TLSPassthrough: &configureTLSPassthrough{
			Patterns: []string{"never-applied.com"},
		},
		AutoTransform: &configureAutoTransform{
			Add: []transformRuleInput{
				{ID: "r", Enabled: true, Direction: "request",
					ActionType: "add_header", HeaderName: "X", HeaderValue: "1"},
			},
		},
	})
	assertErrorContains(t, result, "auto_transform", "add")

	if pl.Contains("never-applied.com") {
		t.Error("tls_passthrough.patterns must NOT have applied; validation failure must reject the whole call")
	}
	if rs := transformEngine.Rules(); len(rs) != 0 {
		t.Errorf("transform engine must be untouched; got %+v", rs)
	}
}
