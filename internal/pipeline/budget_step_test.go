package pipeline

import (
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestBudgetStep_NilManager(t *testing.T) {
	step := NewBudgetStep(nil)
	env := &envelope.Envelope{Direction: envelope.Send}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("nil manager: action = %v, want Continue", r.Action)
	}
	if r.BlockedBy != "" {
		t.Errorf("nil manager: BlockedBy = %q, want empty", r.BlockedBy)
	}
}

func TestBudgetStep_NilEnvelope(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)
	r := step.Process(context.Background(), nil)
	if r.Action != Continue {
		t.Errorf("nil envelope: action = %v, want Continue", r.Action)
	}
	if got := bm.RequestCount(); got != 0 {
		t.Errorf("nil envelope: counter = %d, want 0", got)
	}
}

func TestBudgetStep_GRPCDataAndEnd_NotCounted(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 1})
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	// GRPCStartMessage Send → counts as the boundary; consumes the budget.
	r := step.Process(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Message:   &envelope.GRPCStartMessage{},
	})
	if r.Action != Continue {
		t.Fatalf("Start: action = %v, want Continue", r.Action)
	}
	// GRPCDataMessage and GRPCEndMessage Sends are mid-stream — they do
	// NOT increment the counter, so they MUST NOT trip the budget even
	// though the (max+1)th request would otherwise drop.
	for i := 0; i < 5; i++ {
		dr := step.Process(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &envelope.GRPCDataMessage{},
		})
		if dr.Action != Continue {
			t.Errorf("Data[%d]: action = %v, want Continue", i, dr.Action)
		}
	}
	er := step.Process(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Message:   &envelope.GRPCEndMessage{},
	})
	if er.Action != Continue {
		t.Errorf("End: action = %v, want Continue", er.Action)
	}
	if got := bm.RequestCount(); got != 1 {
		t.Errorf("counter = %d, want 1 (only the Start envelope)", got)
	}
}

func TestBudgetStep_WSMessage_NotCounted(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 1})
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	for i := 0; i < 5; i++ {
		r := step.Process(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &envelope.WSMessage{},
		})
		if r.Action != Continue {
			t.Errorf("WSMessage[%d]: action = %v, want Continue", i, r.Action)
		}
	}
	if got := bm.RequestCount(); got != 0 {
		t.Errorf("counter = %d, want 0 (post-Upgrade WS frames)", got)
	}
}

func TestBudgetStep_NoBudget_ContinueAndCount(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	for i := 0; i < 10; i++ {
		env := &envelope.Envelope{Direction: envelope.Send}
		r := step.Process(context.Background(), env)
		if r.Action != Continue {
			t.Fatalf("iter %d: action = %v, want Continue", i, r.Action)
		}
	}
	// Counter is incremented even with no budget configured (the
	// underlying connector.BudgetManager increments-then-checks). The
	// blocked path requires a configured MaxTotalRequests > 0.
	if got := bm.RequestCount(); got != 10 {
		t.Errorf("counter = %d, want 10", got)
	}
}

func TestBudgetStep_UnderBudget_Continue(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 5})
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	for i := 0; i < 5; i++ {
		env := &envelope.Envelope{Direction: envelope.Send}
		r := step.Process(context.Background(), env)
		if r.Action != Continue {
			t.Fatalf("iter %d: action = %v, want Continue", i, r.Action)
		}
	}
	if got := bm.RequestCount(); got != 5 {
		t.Errorf("counter = %d, want 5", got)
	}
}

func TestBudgetStep_OverBudget_Drop(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 3})
	var shutdownCalled bool
	bm.Start(func(_ string) { shutdownCalled = true })
	defer bm.Stop()
	step := NewBudgetStep(bm)

	// First 3 envelopes are under budget.
	for i := 0; i < 3; i++ {
		r := step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Send})
		if r.Action != Continue {
			t.Fatalf("iter %d: action = %v, want Continue", i, r.Action)
		}
	}
	// 4th envelope (the (max+1)th) is counted-and-blocked.
	r := step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Send})
	if r.Action != Drop {
		t.Errorf("over-budget: action = %v, want Drop", r.Action)
	}
	if r.BlockedBy != BlockedByBudget {
		t.Errorf("over-budget: BlockedBy = %q, want %q", r.BlockedBy, BlockedByBudget)
	}
	if got := bm.RequestCount(); got != 4 {
		t.Errorf("counter after over-budget = %d, want 4", got)
	}
	if !shutdownCalled {
		t.Error("shutdown callback not fired on budget exhaustion")
	}
}

func TestBudgetStep_ReceiveDirection_Skipped(t *testing.T) {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 2})
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	for i := 0; i < 10; i++ {
		r := step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Receive})
		if r.Action != Continue {
			t.Fatalf("iter %d (receive): action = %v, want Continue", i, r.Action)
		}
	}
	if got := bm.RequestCount(); got != 0 {
		t.Errorf("counter after receive-only = %d, want 0", got)
	}
}

func TestBudgetStep_Concurrent(t *testing.T) {
	const goroutines = 50
	const callsPerGoroutine = 10
	const max = 300

	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: max})
	bm.Start(nil)
	defer bm.Stop()
	step := NewBudgetStep(bm)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < callsPerGoroutine; i++ {
				step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Send})
			}
		}()
	}
	wg.Wait()

	const total = goroutines * callsPerGoroutine
	if got := bm.RequestCount(); got != total {
		t.Errorf("counter = %d, want %d", got, total)
	}
}

func TestBudgetStep_ImplementsStep(t *testing.T) {
	var _ Step = (*BudgetStep)(nil)
}
