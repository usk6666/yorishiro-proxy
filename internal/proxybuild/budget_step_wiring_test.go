package proxybuild

// budget_step_wiring_test.go (USK-818) verifies that BudgetStep is
// correctly wired into the canonical buildPipeline at position #3 (after
// HostScope / HTTPScope, before SafetyStep / Plugin / Intercept /
// Transform / Plugin / Record). Mirrors the existing pipeline-shape
// assertions in blocked_recorder_test.go.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// TestBuildPipeline_BudgetStep_Drops verifies that an over-budget HTTPMessage
// Send envelope is dropped by the canonical Pipeline produced by
// buildPipeline, and that the Drop carries BlockedBy="budget" so the
// session-side OnPipelineDrop callback can record an audit Stream.
func TestBuildPipeline_BudgetStep_Drops(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 2})
	bm.Start(nil)
	defer bm.Stop()

	deps := Deps{
		Logger:        silentLogger(),
		BudgetManager: bm,
	}
	encoders := defaultHTTP1WireEncoderRegistry()
	p := buildPipeline(deps, encoders, slog.Default())

	mkEnv := func() *envelope.Envelope {
		return &envelope.Envelope{
			StreamID:  "stream-1",
			Protocol:  envelope.ProtocolHTTP,
			Direction: envelope.Send,
			Message: &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    "http",
				Authority: "example.com",
				Path:      "/",
			},
		}
	}

	// First two Sends are under budget.
	for i := 0; i < 2; i++ {
		_, action, _, blockedBy := p.RunWithBlockedBy(context.Background(), mkEnv())
		if action != pipeline.Continue {
			t.Fatalf("iter %d: action = %v, want Continue (blockedBy=%q)", i, action, blockedBy)
		}
	}
	// Third Send is over budget.
	_, action, _, blockedBy := p.RunWithBlockedBy(context.Background(), mkEnv())
	if action != pipeline.Drop {
		t.Fatalf("over-budget: action = %v, want Drop", action)
	}
	if blockedBy != pipeline.BlockedByBudget {
		t.Errorf("over-budget: blockedBy = %q, want %q", blockedBy, pipeline.BlockedByBudget)
	}
	if got := bm.RequestCount(); got != 3 {
		t.Errorf("RequestCount() = %d, want 3", got)
	}
}

// TestBuildPipeline_BudgetStep_NilBudgetManager verifies that buildPipeline
// degrades to a no-op BudgetStep when Deps.BudgetManager is nil.
func TestBuildPipeline_BudgetStep_NilBudgetManager(t *testing.T) {
	deps := Deps{
		Logger:        silentLogger(),
		BudgetManager: nil,
	}
	encoders := defaultHTTP1WireEncoderRegistry()
	p := buildPipeline(deps, encoders, slog.Default())

	for i := 0; i < 100; i++ {
		env := &envelope.Envelope{
			StreamID:  "no-budget",
			Protocol:  envelope.ProtocolHTTP,
			Direction: envelope.Send,
			Message: &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    "http",
				Authority: "example.com",
				Path:      "/",
			},
		}
		_, action, _, blockedBy := p.RunWithBlockedBy(context.Background(), env)
		if action != pipeline.Continue {
			t.Fatalf("iter %d: action = %v, blockedBy = %q (nil BudgetManager must no-op)", i, action, blockedBy)
		}
	}
}
