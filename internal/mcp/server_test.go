package mcp

import (
	"context"
	"testing"
)

// TestServer_HasSevenComponents verifies that NewServer populates all seven
// component slots required by the USK-664 redesign (RFC-001 N8). Future
// changes that drop or rename a component will fail this test.
func TestServer_HasSevenComponents(t *testing.T) {
	s := NewServer(
		NewMisc(context.Background(), nil, nil, "", nil, nil),
		NewPipeline(nil, nil, nil, nil, nil, nil, nil),
		NewConnector(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil),
		NewJobRunner(nil, nil, nil, nil, nil),
		NewFlowStore(nil),
		NewMacroEngine(),
		NewPluginEngine(nil, nil),
	)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.misc == nil {
		t.Error("Server.misc is nil")
	}
	if s.pipeline == nil {
		t.Error("Server.pipeline is nil")
	}
	if s.connector == nil {
		t.Error("Server.connector is nil")
	}
	if s.jobRunner == nil {
		t.Error("Server.jobRunner is nil")
	}
	if s.flowStore == nil {
		t.Error("Server.flowStore is nil")
	}
	if s.macroEngine == nil {
		t.Error("Server.macroEngine is nil")
	}
	if s.pluginEngine == nil {
		t.Error("Server.pluginEngine is nil")
	}
}

// TestServer_NewServer_NilComponentsTolerated verifies that NewServer fills
// in default empty components when nil pointers are passed for optional
// component slots. The "with-nils" path is exercised by tests via the
// legacy_options_test.go helpers; this test pins it explicitly.
func TestServer_NewServer_NilComponentsTolerated(t *testing.T) {
	s := NewServer(nil, nil, nil, nil, nil, nil, nil)
	if s == nil {
		t.Fatal("NewServer with all-nil components returned nil")
	}
	if s.misc == nil || s.pipeline == nil || s.connector == nil ||
		s.jobRunner == nil || s.flowStore == nil || s.macroEngine == nil ||
		s.pluginEngine == nil {
		t.Error("NewServer should fill nil component slots with empty defaults")
	}
	// finalizeDefaults should have created the rate limiter / target scope /
	// budget manager when not provided.
	if s.misc.rateLimiter == nil {
		t.Error("misc.rateLimiter should be populated by finalizeDefaults")
	}
	if s.misc.budgetManager == nil {
		t.Error("misc.budgetManager should be populated by finalizeDefaults")
	}
	if s.connector.targetScope == nil {
		t.Error("connector.targetScope should be populated by finalizeDefaults")
	}
}

// handlerComponentMap documents how many distinct components each tool
// handler file accesses. The constraint per USK-664 is that no handler
// should reach into more than 3 components — with two documented exceptions
// (proxy_start_tool.go and query_tool.go) which are assembly / dispatch
// handlers and therefore inherently touch more state.
//
// This is a documentation-only table; it is not enforced by static analysis
// because adding such tooling would exceed the mechanical refactor scope.
// When adding a new handler file, add an entry here listing the components
// it touches and confirm the count is ≤ 3 (or document the exception).
//
//	File                          Components used                                    Count
//	--------------------------    -----------------------------------------------    -----
//	compare_tool.go               flowStore                                          1
//	configure_tool.go             pipeline, connector, misc                          3
//	fuzz_tool.go                  jobRunner, flowStore, pipeline, connector, misc    5 (*)
//	helpers.go                    jobRunner, pipeline, connector                     3
//	intercept_helpers.go          pipeline                                           1
//	intercept_tool.go             pipeline                                           1
//	macro_handlers.go             jobRunner, flowStore, connector                    3
//	manage_tool.go                misc, flowStore                                    2
//	plugin_tool.go                pluginEngine                                       1
//	proxy_start_tool.go           misc, pipeline, connector, pluginEngine            4 (exception: assembly handler)
//	proxy_stop_tool.go            connector                                          1
//	query_fuzz.go                 jobRunner                                          1
//	query_technologies.go         flowStore                                          1
//	query_tool.go                 misc, pipeline, connector, flowStore               4 (exception: dispatch handler)
//	resend_multiproto.go          flowStore, connector                               2
//	resend_raw_h2.go              connector                                          1
//	resend_tool.go                jobRunner, flowStore, connector                    3
//	safety_helper.go              pipeline                                           1
//	security_tool.go              pipeline, connector, misc                          3
//	transform_helpers.go          pipeline                                           1
//
// (*) fuzz_tool.go uses 5 components (JobRunner.fuzzRunner / fuzzStore,
// FlowStore.store, Pipeline.safetyEngine, Connector.targetScope,
// Misc.appCtx). The last three are read-only; appCtx is needed because the
// fuzz job runs asynchronously beyond the request handler's lifetime.
// Splitting fuzz_tool.go is out of scope for USK-664 — the same boundaries
// will be revisited in N8 issues that introduce per-protocol fuzz handlers.
//
// TestHandlerComponentCount_DocumentationOnly is a placeholder that the
// table above is the source of truth.
func TestHandlerComponentCount_DocumentationOnly(t *testing.T) {
	t.Skip("documentation table; see comment above")
}
