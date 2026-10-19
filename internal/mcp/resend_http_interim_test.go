package mcp

// resend_http_interim_test.go — unit tests for receiveResendHTTPResponse's
// 1xx interim-response handling (USK-1198), driven through a fake
// layer.Channel and a recording pipeline Step.

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// scriptedRespChannel yields the scripted response statuses in order, then
// io.EOF. It records how many envelopes Next handed out.
type scriptedRespChannel struct {
	statuses []int
	served   int
	closed   chan struct{}
}

func newScriptedRespChannel(statuses ...int) *scriptedRespChannel {
	return &scriptedRespChannel{statuses: statuses, closed: make(chan struct{})}
}

func (c *scriptedRespChannel) StreamID() string { return "" }

func (c *scriptedRespChannel) Next(_ context.Context) (*envelope.Envelope, error) {
	if c.served >= len(c.statuses) {
		return nil, io.EOF
	}
	st := c.statuses[c.served]
	c.served++
	return &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Status: st},
	}, nil
}

func (c *scriptedRespChannel) Send(context.Context, *envelope.Envelope) error { return nil }
func (c *scriptedRespChannel) Close() error                                   { return nil }
func (c *scriptedRespChannel) Closed() <-chan struct{}                        { return c.closed }
func (c *scriptedRespChannel) Err() error                                     { return nil }

// countingStep stands in for RecordStep: it records every envelope the
// pipeline is run on (i.e. every response Flow that would be recorded).
type countingStep struct {
	statuses  []int
	sequences []int
	streamIDs []string
}

func (s *countingStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if m, ok := env.Message.(*envelope.HTTPMessage); ok {
		s.statuses = append(s.statuses, m.Status)
	}
	s.sequences = append(s.sequences, env.Sequence)
	s.streamIDs = append(s.streamIDs, env.StreamID)
	return pipeline.Result{}
}

func TestReceiveResendHTTPResponse_InterimThenFinal(t *testing.T) {
	ch := newScriptedRespChannel(100, 103, 200)
	step := &countingStep{}
	resp, err := receiveResendHTTPResponse(context.Background(), ch, pipeline.New(step), "stream-1")
	if err != nil {
		t.Fatalf("receiveResendHTTPResponse: %v", err)
	}
	m, _ := resp.Message.(*envelope.HTTPMessage)
	if m == nil || m.Status != 200 {
		t.Fatalf("final response = %+v, want status 200", resp.Message)
	}
	wantStatuses := []int{100, 103, 200}
	wantSeq := []int{1, 2, 3}
	for i := range wantStatuses {
		if i >= len(step.statuses) || step.statuses[i] != wantStatuses[i] || step.sequences[i] != wantSeq[i] || step.streamIDs[i] != "stream-1" {
			t.Fatalf("recorded statuses=%v sequences=%v streamIDs=%v, want statuses=%v sequences=%v streamID=stream-1",
				step.statuses, step.sequences, step.streamIDs, wantStatuses, wantSeq)
		}
	}
	if len(step.statuses) != len(wantStatuses) {
		t.Fatalf("recorded %d flows, want %d", len(step.statuses), len(wantStatuses))
	}
}

// TestReceiveResendHTTPResponse_InterimCap: an upstream that sends one more
// 1xx than maxResendHTTPInterimResponses must make the call fail with
// exactly maxResendHTTPInterimResponses interim flows recorded — the
// over-cap response is neither recorded nor followed by further reads.
func TestReceiveResendHTTPResponse_InterimCap(t *testing.T) {
	statuses := make([]int, 0, maxResendHTTPInterimResponses+2)
	for i := 0; i < maxResendHTTPInterimResponses+1; i++ {
		statuses = append(statuses, 103)
	}
	statuses = append(statuses, 200) // never reached
	ch := newScriptedRespChannel(statuses...)
	step := &countingStep{}

	resp, err := receiveResendHTTPResponse(context.Background(), ch, pipeline.New(step), "stream-1")
	if err == nil {
		t.Fatalf("receiveResendHTTPResponse returned %+v, want interim-cap error", resp)
	}
	if errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "interim") {
		t.Fatalf("error = %v, want interim-cap error", err)
	}
	if got := len(step.statuses); got != maxResendHTTPInterimResponses {
		t.Fatalf("recorded %d interim flows, want exactly %d", got, maxResendHTTPInterimResponses)
	}
	if ch.served != maxResendHTTPInterimResponses+1 {
		t.Fatalf("read %d responses, want %d (stop at the first over-cap 1xx)", ch.served, maxResendHTTPInterimResponses+1)
	}
}

// TestReceiveResendHTTPResponse_ExactlyCapInterimThenFinal: exactly
// maxResendHTTPInterimResponses interim responses followed by a final one
// is within the cap and succeeds.
func TestReceiveResendHTTPResponse_ExactlyCapInterimThenFinal(t *testing.T) {
	statuses := make([]int, 0, maxResendHTTPInterimResponses+1)
	for i := 0; i < maxResendHTTPInterimResponses; i++ {
		statuses = append(statuses, 100)
	}
	statuses = append(statuses, 204)
	step := &countingStep{}
	resp, err := receiveResendHTTPResponse(context.Background(), newScriptedRespChannel(statuses...), pipeline.New(step), "s")
	if err != nil {
		t.Fatalf("receiveResendHTTPResponse: %v", err)
	}
	if m, _ := resp.Message.(*envelope.HTTPMessage); m == nil || m.Status != 204 {
		t.Fatalf("final response = %+v, want status 204", resp.Message)
	}
	if got := len(step.statuses); got != maxResendHTTPInterimResponses+1 {
		t.Fatalf("recorded %d flows, want %d", got, maxResendHTTPInterimResponses+1)
	}
}
