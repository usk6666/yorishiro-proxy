package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestQuery_Config_CaptureScope_Default checks that an unconfigured
// capture_scope echoes empty arrays (USK-776 ACs require the field be
// present on every config response so clients see a stable shape).
func TestQuery_Config_CaptureScope_Default(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("query config errored: %s", textContent(result))
	}
	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if out.CaptureScope == nil {
		t.Fatalf("CaptureScope must be present even when unconfigured")
	}
	if out.CaptureScope.Includes == nil || len(out.CaptureScope.Includes) != 0 {
		t.Errorf("Includes default should be empty array, got %#v", out.CaptureScope.Includes)
	}
	if out.CaptureScope.Excludes == nil || len(out.CaptureScope.Excludes) != 0 {
		t.Errorf("Excludes default should be empty array, got %#v", out.CaptureScope.Excludes)
	}
}

// TestQuery_Config_CaptureScope_EchoesActiveRules verifies that mutating
// the shared *flow.RecordScope (the same pointer the configure tool
// would touch) is reflected in the next query{config} response.
func TestQuery_Config_CaptureScope_EchoesActiveRules(t *testing.T) {
	store := newTestStore(t)
	scope := flow.NewRecordScope()
	scope.SetRules(
		[]flow.ScopeRule{
			{Hostname: "*.target.com"},
			{Hostname: "api.target.com", URLPrefix: "/api/", Method: "POST"},
		},
		[]flow.ScopeRule{
			{Hostname: "static.target.com"},
		},
	)
	cs := setupQueryTestSession(t, store, withRecordScopeForTest(scope))

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("query config errored: %s", textContent(result))
	}
	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if out.CaptureScope == nil {
		t.Fatalf("CaptureScope must be present")
	}
	if len(out.CaptureScope.Includes) != 2 {
		t.Errorf("Includes count = %d, want 2", len(out.CaptureScope.Includes))
	}
	if len(out.CaptureScope.Excludes) != 1 {
		t.Errorf("Excludes count = %d, want 1", len(out.CaptureScope.Excludes))
	}
	wantInc1 := scopeRuleInput{Hostname: "*.target.com"}
	if out.CaptureScope.Includes[0] != wantInc1 {
		t.Errorf("Includes[0] = %#v, want %#v", out.CaptureScope.Includes[0], wantInc1)
	}
	wantInc2 := scopeRuleInput{Hostname: "api.target.com", URLPrefix: "/api/", Method: "POST"}
	if out.CaptureScope.Includes[1] != wantInc2 {
		t.Errorf("Includes[1] = %#v, want %#v", out.CaptureScope.Includes[1], wantInc2)
	}
	wantExc1 := scopeRuleInput{Hostname: "static.target.com"}
	if out.CaptureScope.Excludes[0] != wantExc1 {
		t.Errorf("Excludes[0] = %#v, want %#v", out.CaptureScope.Excludes[0], wantExc1)
	}
}

// withRecordScopeForTest swaps the FlowStore's recordScope pointer.
// Mirrors the live wiring in mcpserver where the orchestration layer
// builds the scope once and shares it with both proxybuild.Deps and
// mcp.NewFlowStore.
func withRecordScopeForTest(scope *flow.RecordScope) ServerOption {
	return func(s *Server) {
		s.flowStore.recordScope = scope
	}
}
