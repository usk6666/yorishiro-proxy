package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// mockStep records whether it was called and returns a preconfigured Result.
type mockStep struct {
	called bool
	result Result
}

func (m *mockStep) Process(_ context.Context, _ *exchange.Exchange) Result {
	m.called = true
	return m.result
}

// anotherStep is a distinct concrete type used to test Without filtering.
type anotherStep struct {
	called bool
	result Result
}

func (a *anotherStep) Process(_ context.Context, _ *exchange.Exchange) Result {
	a.called = true
	return a.result
}

func TestRun_AllStepsCalled(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &mockStep{result: Result{Action: Continue}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	ex := &exchange.Exchange{StreamID: "f1"}
	got, action, resp := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if got != ex {
		t.Fatal("expected original exchange to be returned")
	}
	for i, s := range []*mockStep{s1, s2, s3} {
		if !s.called {
			t.Errorf("step %d was not called", i)
		}
	}
}

func TestRun_DropStopsExecution(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &mockStep{result: Result{Action: Drop}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	ex := &exchange.Exchange{StreamID: "f1"}
	_, action, _ := p.Run(context.Background(), ex)

	if action != Drop {
		t.Fatalf("expected Drop, got %v", action)
	}
	if !s1.called {
		t.Error("step 1 should have been called")
	}
	if !s2.called {
		t.Error("step 2 should have been called")
	}
	if s3.called {
		t.Error("step 3 should not have been called after Drop")
	}
}

func TestRun_RespondReturnsResponse(t *testing.T) {
	respEx := &exchange.Exchange{StreamID: "resp", Status: 403}
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &mockStep{result: Result{Action: Respond, Response: respEx}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	ex := &exchange.Exchange{StreamID: "f1"}
	_, action, resp := p.Run(context.Background(), ex)

	if action != Respond {
		t.Fatalf("expected Respond, got %v", action)
	}
	if resp != respEx {
		t.Fatal("expected response exchange from step 2")
	}
	if s3.called {
		t.Error("step 3 should not have been called after Respond")
	}
}

func TestRun_ExchangeModificationPropagates(t *testing.T) {
	modified := &exchange.Exchange{StreamID: "modified"}

	s1 := &mockStep{result: Result{Action: Continue, Exchange: modified}}

	// s2 captures the exchange it receives via a custom step.
	var receivedEx *exchange.Exchange
	s2 := &captureStep{result: Result{Action: Continue}, received: &receivedEx}

	p := New(s1, s2)
	original := &exchange.Exchange{StreamID: "original"}
	got, action, _ := p.Run(context.Background(), original)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if got != modified {
		t.Fatal("expected modified exchange to be returned")
	}
	if receivedEx != modified {
		t.Fatalf("step 2 should have received modified exchange, got StreamID=%q", receivedEx.StreamID)
	}
}

// captureStep records the exchange it receives.
type captureStep struct {
	result   Result
	received **exchange.Exchange
}

func (c *captureStep) Process(_ context.Context, ex *exchange.Exchange) Result {
	*c.received = ex
	return c.result
}

func TestRun_EmptyPipeline(t *testing.T) {
	p := New()
	ex := &exchange.Exchange{StreamID: "f1"}
	got, action, resp := p.Run(context.Background(), ex)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if got != ex {
		t.Fatal("expected original exchange to be returned")
	}
}

func TestWithout_ExcludesMatchingType(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &anotherStep{result: Result{Action: Continue}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)

	// Exclude all mockStep instances.
	derived := p.Without(&mockStep{})

	ex := &exchange.Exchange{StreamID: "f1"}
	derived.Run(context.Background(), ex)

	// s1 and s3 are mockStep — they should NOT have been called in the
	// derived pipeline. s2 is anotherStep — it should have been called.
	if s1.called {
		t.Error("mockStep s1 should have been excluded")
	}
	if !s2.called {
		t.Error("anotherStep s2 should have been called")
	}
	if s3.called {
		t.Error("mockStep s3 should have been excluded")
	}
}

func TestWithout_OriginalUnchanged(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &anotherStep{result: Result{Action: Continue}}

	p := New(s1, s2)
	derived := p.Without(&anotherStep{})

	ex := &exchange.Exchange{StreamID: "f1"}

	// Run derived — only s1 should be called.
	derived.Run(context.Background(), ex)
	if !s1.called {
		t.Error("s1 should have been called in derived pipeline")
	}
	if s2.called {
		t.Error("s2 should have been excluded in derived pipeline")
	}

	// Reset and run original — both should be called.
	s1.called = false
	s2.called = false
	p.Run(context.Background(), ex)
	if !s1.called {
		t.Error("s1 should have been called in original pipeline")
	}
	if !s2.called {
		t.Error("s2 should have been called in original pipeline")
	}
}

func TestAction_String(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{Continue, "Continue"},
		{Drop, "Drop"},
		{Respond, "Respond"},
		{Action(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.want)
		}
	}
}
