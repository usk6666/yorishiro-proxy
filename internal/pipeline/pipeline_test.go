package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// mockStep records whether it was called and returns a preconfigured Result.
type mockStep struct {
	called bool
	result Result
}

func (m *mockStep) Process(_ context.Context, _ *envelope.Envelope) Result {
	m.called = true
	return m.result
}

// anotherStep is a distinct concrete type used to test Without filtering.
type anotherStep struct {
	called bool
	result Result
}

func (a *anotherStep) Process(_ context.Context, _ *envelope.Envelope) Result {
	a.called = true
	return a.result
}

func TestRun_AllStepsCalled(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &mockStep{result: Result{Action: Continue}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}
	got, action, resp := p.Run(context.Background(), env)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if got != env {
		t.Fatal("expected original envelope to be returned")
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
	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}
	_, action, _ := p.Run(context.Background(), env)

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
	respEnv := &envelope.Envelope{
		StreamID: "resp",
		Protocol: envelope.ProtocolHTTP,
		Message:  &envelope.HTTPMessage{Status: 403},
	}
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &mockStep{result: Result{Action: Respond, Response: respEnv}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}
	_, action, resp := p.Run(context.Background(), env)

	if action != Respond {
		t.Fatalf("expected Respond, got %v", action)
	}
	if resp != respEnv {
		t.Fatal("expected response envelope from step 2")
	}
	if s3.called {
		t.Error("step 3 should not have been called after Respond")
	}
}

func TestRun_EnvelopeModificationPropagates(t *testing.T) {
	modified := &envelope.Envelope{
		StreamID: "modified",
		Message:  &envelope.RawMessage{Bytes: []byte("modified")},
	}

	s1 := &mockStep{result: Result{Action: Continue, Envelope: modified}}

	var receivedEnv *envelope.Envelope
	s2 := &captureStep{result: Result{Action: Continue}, received: &receivedEnv}

	p := New(s1, s2)
	original := &envelope.Envelope{
		StreamID: "original",
		Message:  &envelope.RawMessage{Bytes: []byte("original")},
	}
	got, action, _ := p.Run(context.Background(), original)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if got != modified {
		t.Fatal("expected modified envelope to be returned")
	}
	if receivedEnv != modified {
		t.Fatalf("step 2 should have received modified envelope, got StreamID=%q", receivedEnv.StreamID)
	}
}

// captureStep records the envelope it receives.
type captureStep struct {
	result   Result
	received **envelope.Envelope
}

func (c *captureStep) Process(_ context.Context, env *envelope.Envelope) Result {
	*c.received = env
	return c.result
}

func TestRun_EmptyPipeline(t *testing.T) {
	p := New()
	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}
	got, action, resp := p.Run(context.Background(), env)

	if action != Continue {
		t.Fatalf("expected Continue, got %v", action)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if got != env {
		t.Fatal("expected original envelope to be returned")
	}
}

func TestRun_SnapshotUsesCloneMessage(t *testing.T) {
	// Verify that the snapshot stored in context is a deep copy via CloneMessage
	httpMsg := &envelope.HTTPMessage{
		Method: "GET",
		Path:   "/test",
		Headers: []envelope.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
	}
	env := &envelope.Envelope{
		StreamID:  "s1",
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("raw data"),
		Message:   httpMsg,
		Direction: envelope.Send,
	}

	// Step that mutates the envelope and checks snapshot independence
	verifyStep := &snapshotVerifyStep{t: t}
	p := New(verifyStep)
	p.Run(context.Background(), env)

	if !verifyStep.verified {
		t.Fatal("snapshot verification step was not called")
	}
}

type snapshotVerifyStep struct {
	t        *testing.T
	verified bool
}

func (s *snapshotVerifyStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	snap := SnapshotFromContext(ctx)
	if snap == nil {
		s.t.Fatal("snapshot should be present in context")
	}

	// Mutate the current envelope's headers
	if httpMsg, ok := env.Message.(*envelope.HTTPMessage); ok {
		httpMsg.Headers[0].Name = "MUTATED"
	}

	// Snapshot should be unaffected
	if snapHTTP, ok := snap.Message.(*envelope.HTTPMessage); ok {
		if snapHTTP.Headers[0].Name == "MUTATED" {
			s.t.Error("snapshot headers should be independent of envelope mutations")
		}
	}

	// Mutate raw bytes
	env.Raw[0] = 'X'
	if snap.Raw[0] == 'X' {
		s.t.Error("snapshot Raw should be independent of envelope mutations")
	}

	s.verified = true
	return Result{}
}

func TestWithout_ExcludesMatchingType(t *testing.T) {
	s1 := &mockStep{result: Result{Action: Continue}}
	s2 := &anotherStep{result: Result{Action: Continue}}
	s3 := &mockStep{result: Result{Action: Continue}}

	p := New(s1, s2, s3)
	derived := p.Without(&mockStep{})

	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}
	derived.Run(context.Background(), env)

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

	env := &envelope.Envelope{StreamID: "s1", Message: &envelope.RawMessage{Bytes: []byte("data")}}

	derived.Run(context.Background(), env)
	if !s1.called {
		t.Error("s1 should have been called in derived pipeline")
	}
	if s2.called {
		t.Error("s2 should have been excluded in derived pipeline")
	}

	s1.called = false
	s2.called = false
	p.Run(context.Background(), env)
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
