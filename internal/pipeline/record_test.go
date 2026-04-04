package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// fakeFlowWriter is a test double that records all calls to SaveFlow,
// UpdateFlow, and AppendMessage.
type fakeFlowWriter struct {
	savedFlows  []*flow.Flow
	updatedIDs  []string
	updates     []flow.FlowUpdate
	messages    []*flow.Message
	saveFlowErr error
}

func (f *fakeFlowWriter) SaveFlow(_ context.Context, fl *flow.Flow) error {
	if f.saveFlowErr != nil {
		return f.saveFlowErr
	}
	f.savedFlows = append(f.savedFlows, fl)
	return nil
}

func (f *fakeFlowWriter) UpdateFlow(_ context.Context, id string, u flow.FlowUpdate) error {
	f.updatedIDs = append(f.updatedIDs, id)
	f.updates = append(f.updates, u)
	return nil
}

func (f *fakeFlowWriter) AppendMessage(_ context.Context, msg *flow.Message) error {
	f.messages = append(f.messages, msg)
	return nil
}

func TestRecordStep_SendCreatesFlowAndMessage(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Scheme: "https", Host: "example.com", Path: "/"},
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
		Body:     []byte("request body"),
		RawBytes: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nrequest body"),
	}

	ctx := context.Background()
	r := step.Process(ctx, ex)

	if r.Action != Continue {
		t.Fatalf("expected Continue, got %v", r.Action)
	}
	if r.Exchange != nil {
		t.Fatal("RecordStep must not modify Exchange")
	}

	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 saved flow, got %d", len(store.savedFlows))
	}
	fl := store.savedFlows[0]
	if fl.ID != "flow-1" {
		t.Errorf("flow ID = %q, want %q", fl.ID, "flow-1")
	}
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
	}
	if fl.State != "active" {
		t.Errorf("flow state = %q, want %q", fl.State, "active")
	}
	if fl.Scheme != "https" {
		t.Errorf("flow scheme = %q, want %q", fl.Scheme, "https")
	}

	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}
	msg := store.messages[0]
	if msg.FlowID != "flow-1" {
		t.Errorf("message flow ID = %q, want %q", msg.FlowID, "flow-1")
	}
	if msg.Direction != "send" {
		t.Errorf("message direction = %q, want %q", msg.Direction, "send")
	}
	if msg.Method != "GET" {
		t.Errorf("message method = %q, want %q", msg.Method, "GET")
	}
	if msg.Headers["Host"][0] != "example.com" {
		t.Errorf("message Host header = %q, want %q", msg.Headers["Host"][0], "example.com")
	}
	if string(msg.Body) != "request body" {
		t.Errorf("message body = %q, want %q", msg.Body, "request body")
	}
	if string(msg.RawBytes) != "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nrequest body" {
		t.Errorf("message raw bytes mismatch")
	}
}

func TestRecordStep_ReceiveAppendsMessageAndCompletes(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  1,
		Direction: exchange.Receive,
		Status:    200,
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
		},
		Body: []byte("response body"),
	}

	ctx := context.Background()
	r := step.Process(ctx, ex)

	if r.Action != Continue {
		t.Fatalf("expected Continue, got %v", r.Action)
	}

	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}
	msg := store.messages[0]
	if msg.Direction != "receive" {
		t.Errorf("message direction = %q, want %q", msg.Direction, "receive")
	}
	if msg.StatusCode != 200 {
		t.Errorf("status code = %d, want %d", msg.StatusCode, 200)
	}

	if len(store.updatedIDs) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updatedIDs))
	}
	if store.updatedIDs[0] != "flow-1" {
		t.Errorf("updated flow ID = %q, want %q", store.updatedIDs[0], "flow-1")
	}
	if store.updates[0].State != "complete" {
		t.Errorf("flow update state = %q, want %q", store.updates[0].State, "complete")
	}
}

func TestRecordStep_VariantRecordedOnHeaderChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	original := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "POST",
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "X-Original", Value: "yes"},
		},
		Body: []byte("body"),
	}

	// Simulate Pipeline.Run(): clone at start, store in context.
	snap := original.Clone()
	ctx := withSnapshot(context.Background(), snap)

	// Modify the Exchange (as a preceding Step would).
	modified := original.Clone()
	modified.Headers = []exchange.KeyValue{
		{Name: "X-Modified", Value: "yes"},
	}

	r := step.Process(ctx, modified)
	if r.Action != Continue {
		t.Fatalf("expected Continue, got %v", r.Action)
	}

	// SaveFlow + 2 variant messages (original + modified).
	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 saved flow, got %d", len(store.savedFlows))
	}
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages (original + modified), got %d", len(store.messages))
	}

	origMsg := store.messages[0]
	if origMsg.Metadata["variant"] != "original" {
		t.Errorf("first message variant = %q, want %q", origMsg.Metadata["variant"], "original")
	}
	if origMsg.Headers["X-Original"] == nil {
		t.Error("original message should have X-Original header")
	}

	modMsg := store.messages[1]
	if modMsg.Metadata["variant"] != "modified" {
		t.Errorf("second message variant = %q, want %q", modMsg.Metadata["variant"], "modified")
	}
	if modMsg.Headers["X-Modified"] == nil {
		t.Error("modified message should have X-Modified header")
	}
}

func TestRecordStep_NoVariantWhenUnchanged(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "GET",
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
		Body: []byte("body"),
	}

	// Snapshot is identical to current Exchange.
	snap := ex.Clone()
	ctx := withSnapshot(context.Background(), snap)

	step.Process(ctx, ex)

	// Should produce exactly 1 message (no variant).
	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message (no variant), got %d", len(store.messages))
	}
	if store.messages[0].Metadata != nil {
		t.Errorf("message should have no variant metadata, got %v", store.messages[0].Metadata)
	}
}

func TestRecordStep_NilStoreReturnsImmediately(t *testing.T) {
	step := NewRecordStep(nil, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Direction: exchange.Send,
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Fatalf("expected Continue, got %v", r.Action)
	}
}

func TestRecordStep_NilBodyPassthrough(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "GET",
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Host", Value: "example.com"},
		},
		Body: nil, // passthrough
	}

	ctx := context.Background()
	step.Process(ctx, ex)

	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}
	if store.messages[0].Body != nil {
		t.Errorf("message body should be nil for passthrough, got %v", store.messages[0].Body)
	}
}

func TestRecordStep_VariantOnBodyChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "POST",
		Protocol:  exchange.HTTP1,
		Body:      []byte("original"),
	}

	snap := ex.Clone()
	ctx := withSnapshot(context.Background(), snap)

	// Modify body.
	ex.Body = []byte("modified")

	step.Process(ctx, ex)

	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages (variant), got %d", len(store.messages))
	}
	if string(store.messages[0].Body) != "original" {
		t.Errorf("original body = %q, want %q", store.messages[0].Body, "original")
	}
	if string(store.messages[1].Body) != "modified" {
		t.Errorf("modified body = %q, want %q", store.messages[1].Body, "modified")
	}
}

func TestRecordStep_VariantOnRawBytesChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: exchange.Send,
		Method:    "GET",
		Protocol:  exchange.HTTP1,
		RawBytes:  []byte("original raw"),
	}

	snap := ex.Clone()
	ctx := withSnapshot(context.Background(), snap)

	ex.RawBytes = []byte("modified raw")

	step.Process(ctx, ex)

	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages (variant), got %d", len(store.messages))
	}
	if string(store.messages[0].RawBytes) != "original raw" {
		t.Errorf("original raw = %q, want %q", store.messages[0].RawBytes, "original raw")
	}
	if string(store.messages[1].RawBytes) != "modified raw" {
		t.Errorf("modified raw = %q, want %q", store.messages[1].RawBytes, "modified raw")
	}
}

func TestPipeline_RunStoresSnapshot(t *testing.T) {
	// Verify that Pipeline.Run() stores a snapshot in context that a Step
	// can retrieve via SnapshotFromContext.
	var captured *exchange.Exchange
	capStep := &snapshotCaptureStep{captured: &captured}

	p := New(capStep)
	ex := &exchange.Exchange{
		FlowID: "flow-1",
		Headers: []exchange.KeyValue{
			{Name: "X-Test", Value: "value"},
		},
		Body: []byte("hello"),
	}
	p.Run(context.Background(), ex)

	if captured == nil {
		t.Fatal("snapshot should be stored in context")
	}
	if captured == ex {
		t.Fatal("snapshot should be a clone, not the same pointer")
	}
	if captured.FlowID != "flow-1" {
		t.Errorf("snapshot FlowID = %q, want %q", captured.FlowID, "flow-1")
	}
	if string(captured.Body) != "hello" {
		t.Errorf("snapshot Body = %q, want %q", captured.Body, "hello")
	}
}

// snapshotCaptureStep retrieves the snapshot from context for test verification.
type snapshotCaptureStep struct {
	captured **exchange.Exchange
}

func (s *snapshotCaptureStep) Process(ctx context.Context, _ *exchange.Exchange) Result {
	*s.captured = SnapshotFromContext(ctx)
	return Result{}
}

func TestRecordStep_ReceiveVariantRecording(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		FlowID:    "flow-1",
		Sequence:  1,
		Direction: exchange.Receive,
		Status:    200,
		Protocol:  exchange.HTTP1,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
		},
		Body: []byte("original response"),
	}

	snap := ex.Clone()
	ctx := withSnapshot(context.Background(), snap)

	// Modify the Exchange (as a preceding Step would).
	ex.Body = []byte("modified response")

	step.Process(ctx, ex)

	// 2 messages (variant) + 1 flow update.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages (variant), got %d", len(store.messages))
	}
	if store.messages[0].Metadata["variant"] != "original" {
		t.Errorf("first message variant = %q, want %q", store.messages[0].Metadata["variant"], "original")
	}
	if store.messages[1].Metadata["variant"] != "modified" {
		t.Errorf("second message variant = %q, want %q", store.messages[1].Metadata["variant"], "modified")
	}
	if len(store.updatedIDs) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updatedIDs))
	}
	if store.updates[0].State != "complete" {
		t.Errorf("flow update state = %q, want %q", store.updates[0].State, "complete")
	}
}

func TestExchangeModified_AllFields(t *testing.T) {
	base := &exchange.Exchange{
		Headers:  []exchange.KeyValue{{Name: "A", Value: "1"}},
		Body:     []byte("body"),
		RawBytes: []byte("raw"),
	}

	tests := []struct {
		name    string
		modify  func(e *exchange.Exchange)
		wantMod bool
	}{
		{
			name:    "identical",
			modify:  func(_ *exchange.Exchange) {},
			wantMod: false,
		},
		{
			name: "header name changed",
			modify: func(e *exchange.Exchange) {
				e.Headers[0].Name = "B"
			},
			wantMod: true,
		},
		{
			name: "header value changed",
			modify: func(e *exchange.Exchange) {
				e.Headers[0].Value = "2"
			},
			wantMod: true,
		},
		{
			name: "header added",
			modify: func(e *exchange.Exchange) {
				e.Headers = append(e.Headers, exchange.KeyValue{Name: "B", Value: "2"})
			},
			wantMod: true,
		},
		{
			name: "body changed",
			modify: func(e *exchange.Exchange) {
				e.Body = []byte("different")
			},
			wantMod: true,
		},
		{
			name: "raw bytes changed",
			modify: func(e *exchange.Exchange) {
				e.RawBytes = []byte("different raw")
			},
			wantMod: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := base.Clone()
			current := base.Clone()
			tt.modify(current)
			got := exchangeModified(snap, current)
			if got != tt.wantMod {
				t.Errorf("exchangeModified() = %v, want %v", got, tt.wantMod)
			}
		})
	}
}
