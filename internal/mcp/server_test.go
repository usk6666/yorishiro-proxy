package mcp

import (
	"testing"
)

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
