package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// fakeFlowWriter is a test double that records all calls to SaveStream,
// UpdateStream, and SaveFlow.
type fakeFlowWriter struct {
	savedStreams  []*flow.Stream
	updatedIDs    []string
	updates       []flow.StreamUpdate
	savedFlows    []*flow.Flow
	saveStreamErr error
}

func (f *fakeFlowWriter) SaveStream(_ context.Context, s *flow.Stream) error {
	if f.saveStreamErr != nil {
		return f.saveStreamErr
	}
	f.savedStreams = append(f.savedStreams, s)
	return nil
}

func (f *fakeFlowWriter) UpdateStream(_ context.Context, id string, u flow.StreamUpdate) error {
	f.updatedIDs = append(f.updatedIDs, id)
	f.updates = append(f.updates, u)
	return nil
}

func (f *fakeFlowWriter) SaveFlow(_ context.Context, fl *flow.Flow) error {
	f.savedFlows = append(f.savedFlows, fl)
	return nil
}

func TestRecordStep_SendCreatesFlowAndMessage(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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

	if len(store.savedStreams) != 1 {
		t.Fatalf("expected 1 saved stream, got %d", len(store.savedStreams))
	}
	st := store.savedStreams[0]
	if st.ID != "stream-1" {
		t.Errorf("stream ID = %q, want %q", st.ID, "stream-1")
	}
	if st.Protocol != "HTTP/1.x" {
		t.Errorf("stream protocol = %q, want %q", st.Protocol, "HTTP/1.x")
	}
	if st.State != "active" {
		t.Errorf("stream state = %q, want %q", st.State, "active")
	}
	if st.Scheme != "https" {
		t.Errorf("stream scheme = %q, want %q", st.Scheme, "https")
	}

	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.savedFlows))
	}
	fl := store.savedFlows[0]
	if fl.StreamID != "stream-1" {
		t.Errorf("flow stream ID = %q, want %q", fl.StreamID, "stream-1")
	}
	if fl.Direction != "send" {
		t.Errorf("flow direction = %q, want %q", fl.Direction, "send")
	}
	if fl.Method != "GET" {
		t.Errorf("flow method = %q, want %q", fl.Method, "GET")
	}
	if fl.Headers["Host"][0] != "example.com" {
		t.Errorf("flow Host header = %q, want %q", fl.Headers["Host"][0], "example.com")
	}
	if string(fl.Body) != "request body" {
		t.Errorf("flow body = %q, want %q", fl.Body, "request body")
	}
	if string(fl.RawBytes) != "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nrequest body" {
		t.Errorf("flow raw bytes mismatch")
	}
}

func TestRecordStep_ReceiveAppendsMessageAndCompletes(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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

	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.savedFlows))
	}
	fl := store.savedFlows[0]
	if fl.Direction != "receive" {
		t.Errorf("flow direction = %q, want %q", fl.Direction, "receive")
	}
	if fl.StatusCode != 200 {
		t.Errorf("status code = %d, want %d", fl.StatusCode, 200)
	}

	if len(store.updatedIDs) != 1 {
		t.Fatalf("expected 1 stream update, got %d", len(store.updatedIDs))
	}
	if store.updatedIDs[0] != "stream-1" {
		t.Errorf("updated stream ID = %q, want %q", store.updatedIDs[0], "stream-1")
	}
	if store.updates[0].State != "complete" {
		t.Errorf("stream update state = %q, want %q", store.updates[0].State, "complete")
	}
}

func TestRecordStep_VariantRecordedOnHeaderChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	original := &exchange.Exchange{
		StreamID:  "stream-1",
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

	// SaveStream + 2 variant flows (original + modified).
	if len(store.savedStreams) != 1 {
		t.Fatalf("expected 1 saved stream, got %d", len(store.savedStreams))
	}
	if len(store.savedFlows) != 2 {
		t.Fatalf("expected 2 flows (original + modified), got %d", len(store.savedFlows))
	}

	origFlow := store.savedFlows[0]
	if origFlow.Metadata["variant"] != "original" {
		t.Errorf("first flow variant = %q, want %q", origFlow.Metadata["variant"], "original")
	}
	if origFlow.Headers["X-Original"] == nil {
		t.Error("original flow should have X-Original header")
	}

	modFlow := store.savedFlows[1]
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("second flow variant = %q, want %q", modFlow.Metadata["variant"], "modified")
	}
	if modFlow.Headers["X-Modified"] == nil {
		t.Error("modified flow should have X-Modified header")
	}
}

func TestRecordStep_NoVariantWhenUnchanged(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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

	// Should produce exactly 1 flow (no variant).
	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 flow (no variant), got %d", len(store.savedFlows))
	}
	if store.savedFlows[0].Metadata != nil {
		t.Errorf("flow should have no variant metadata, got %v", store.savedFlows[0].Metadata)
	}
}

func TestRecordStep_NilStoreReturnsImmediately(t *testing.T) {
	step := NewRecordStep(nil, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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
		StreamID:  "stream-1",
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

	if len(store.savedFlows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(store.savedFlows))
	}
	if store.savedFlows[0].Body != nil {
		t.Errorf("flow body should be nil for passthrough, got %v", store.savedFlows[0].Body)
	}
}

func TestRecordStep_VariantOnBodyChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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

	if len(store.savedFlows) != 2 {
		t.Fatalf("expected 2 flows (variant), got %d", len(store.savedFlows))
	}
	if string(store.savedFlows[0].Body) != "original" {
		t.Errorf("original body = %q, want %q", store.savedFlows[0].Body, "original")
	}
	if string(store.savedFlows[1].Body) != "modified" {
		t.Errorf("modified body = %q, want %q", store.savedFlows[1].Body, "modified")
	}
}

func TestRecordStep_VariantOnRawBytesChange(t *testing.T) {
	store := &fakeFlowWriter{}
	step := NewRecordStep(store, nil)

	ex := &exchange.Exchange{
		StreamID:  "stream-1",
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

	if len(store.savedFlows) != 2 {
		t.Fatalf("expected 2 flows (variant), got %d", len(store.savedFlows))
	}
	if string(store.savedFlows[0].RawBytes) != "original raw" {
		t.Errorf("original raw = %q, want %q", store.savedFlows[0].RawBytes, "original raw")
	}
	if string(store.savedFlows[1].RawBytes) != "modified raw" {
		t.Errorf("modified raw = %q, want %q", store.savedFlows[1].RawBytes, "modified raw")
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
		StreamID:  "stream-1",
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

	// 2 flows (variant) + 1 stream update.
	if len(store.savedFlows) != 2 {
		t.Fatalf("expected 2 flows (variant), got %d", len(store.savedFlows))
	}
	if store.savedFlows[0].Metadata["variant"] != "original" {
		t.Errorf("first flow variant = %q, want %q", store.savedFlows[0].Metadata["variant"], "original")
	}
	if store.savedFlows[1].Metadata["variant"] != "modified" {
		t.Errorf("second flow variant = %q, want %q", store.savedFlows[1].Metadata["variant"], "modified")
	}
	if len(store.updatedIDs) != 1 {
		t.Fatalf("expected 1 stream update, got %d", len(store.updatedIDs))
	}
	if store.updates[0].State != "complete" {
		t.Errorf("stream update state = %q, want %q", store.updates[0].State, "complete")
	}
}

func TestExchangeModified_AllFields(t *testing.T) {
	base := &exchange.Exchange{
		Headers:  []exchange.KeyValue{{Name: "A", Value: "1"}},
		Trailers: []exchange.KeyValue{{Name: "T", Value: "1"}},
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
			name: "trailer changed",
			modify: func(e *exchange.Exchange) {
				e.Trailers[0].Value = "2"
			},
			wantMod: true,
		},
		{
			name: "trailer added",
			modify: func(e *exchange.Exchange) {
				e.Trailers = append(e.Trailers, exchange.KeyValue{Name: "T2", Value: "v"})
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
