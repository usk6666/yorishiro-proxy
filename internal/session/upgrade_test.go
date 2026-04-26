package session

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// --- UpgradeNotice mutex semantics ---

func TestUpgradeNotice_MarkSendUpgrade_LatchesIdempotently(t *testing.T) {
	n := &UpgradeNotice{}
	if n.hasSendUpgrade() {
		t.Fatal("zero-value notice must not report seenSendUpgrade")
	}
	n.markSendUpgrade()
	if !n.hasSendUpgrade() {
		t.Error("after markSendUpgrade, hasSendUpgrade should return true")
	}
	// Idempotent under repeated calls.
	n.markSendUpgrade()
	if !n.hasSendUpgrade() {
		t.Error("repeated markSendUpgrade should remain true")
	}
}

func TestUpgradeNotice_TrySetPending_OnlyFirstWins(t *testing.T) {
	n := &UpgradeNotice{}

	if n.Pending() != "" {
		t.Fatal("zero-value notice must report empty Pending")
	}

	if !n.trySetPending(UpgradeWS) {
		t.Error("first trySetPending should return true")
	}
	if n.Pending() != UpgradeWS {
		t.Errorf("Pending = %q, want %q", n.Pending(), UpgradeWS)
	}

	if n.trySetPending(UpgradeSSE) {
		t.Error("second trySetPending should return false (latched)")
	}
	if n.Pending() != UpgradeWS {
		t.Errorf("Pending after second set = %q, want %q (first wins)", n.Pending(), UpgradeWS)
	}
}

func TestUpgradeNotice_PendingNilSafe(t *testing.T) {
	var n *UpgradeNotice
	if got := n.Pending(); got != "" {
		t.Errorf("nil receiver Pending = %q, want empty", got)
	}
	if got := n.Upstream(); got != nil {
		t.Errorf("nil receiver Upstream = %v, want nil", got)
	}
}

// --- Context plumbing ---

func TestWithUpgradeNotice_Roundtrip(t *testing.T) {
	n := &UpgradeNotice{}
	ctx := WithUpgradeNotice(context.Background(), n)
	got := UpgradeNoticeFromContext(ctx)
	if got != n {
		t.Errorf("UpgradeNoticeFromContext returned %v, want %v", got, n)
	}
}

func TestWithUpgradeNotice_NilLeavesCtxUnchanged(t *testing.T) {
	base := context.Background()
	ctx := WithUpgradeNotice(base, nil)
	if ctx != base {
		t.Error("WithUpgradeNotice(nil) should return ctx unchanged")
	}
	if got := UpgradeNoticeFromContext(ctx); got != nil {
		t.Errorf("UpgradeNoticeFromContext on bare ctx = %v, want nil", got)
	}
}

func TestUpgradeNoticeFromContext_AbsentReturnsNil(t *testing.T) {
	if got := UpgradeNoticeFromContext(context.Background()); got != nil {
		t.Errorf("UpgradeNoticeFromContext on bare ctx = %v, want nil", got)
	}
}

// --- Helper: case-insensitive header lookups ---

func TestLookupHeader_CaseInsensitive(t *testing.T) {
	headers := []envelope.KeyValue{
		{Name: "Upgrade", Value: "websocket"},
		{Name: "content-TYPE", Value: "text/event-stream"},
	}
	if got := lookupHeader(headers, "upgrade"); got != "websocket" {
		t.Errorf("lookupHeader(Upgrade) = %q, want %q", got, "websocket")
	}
	if got := lookupHeader(headers, "Content-Type"); got != "text/event-stream" {
		t.Errorf("lookupHeader(Content-Type) = %q, want %q", got, "text/event-stream")
	}
	if got := lookupHeader(headers, "Missing"); got != "" {
		t.Errorf("lookupHeader missing should return empty, got %q", got)
	}
}

func TestHeaderHasToken_Cases(t *testing.T) {
	cases := []struct {
		name    string
		headers []envelope.KeyValue
		hdr     string
		token   string
		want    bool
	}{
		{
			name:    "exact token",
			headers: []envelope.KeyValue{{Name: "Upgrade", Value: "websocket"}},
			hdr:     "Upgrade", token: "websocket", want: true,
		},
		{
			name:    "case insensitive",
			headers: []envelope.KeyValue{{Name: "upgrade", Value: "WebSocket"}},
			hdr:     "Upgrade", token: "websocket", want: true,
		},
		{
			name:    "comma-separated, multi token",
			headers: []envelope.KeyValue{{Name: "Connection", Value: "keep-alive, Upgrade"}},
			hdr:     "Connection", token: "upgrade", want: true,
		},
		{
			name:    "no match",
			headers: []envelope.KeyValue{{Name: "Connection", Value: "close"}},
			hdr:     "Connection", token: "upgrade", want: false,
		},
		{
			name:    "duplicate header name (different casing) preserved",
			headers: []envelope.KeyValue{{Name: "Upgrade", Value: "h2c"}, {Name: "upgrade", Value: "websocket"}},
			hdr:     "Upgrade", token: "websocket", want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := headerHasToken(tc.headers, tc.hdr, tc.token); got != tc.want {
				t.Errorf("headerHasToken(%q,%q) = %v, want %v", tc.hdr, tc.token, got, tc.want)
			}
		})
	}
}

// --- Helper: detection predicates ---

func TestIsWSUpgradeRequest(t *testing.T) {
	good := &envelope.HTTPMessage{
		Method: "GET", Path: "/", Headers: []envelope.KeyValue{
			{Name: "Host", Value: "example.com"},
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		},
	}
	if !isWSUpgradeRequest(good) {
		t.Error("good WS request not detected")
	}

	missingUpgrade := &envelope.HTTPMessage{
		Headers: []envelope.KeyValue{{Name: "Connection", Value: "Upgrade"}},
	}
	if isWSUpgradeRequest(missingUpgrade) {
		t.Error("missing Upgrade header should not match")
	}

	missingConn := &envelope.HTTPMessage{
		Headers: []envelope.KeyValue{{Name: "Upgrade", Value: "websocket"}},
	}
	if isWSUpgradeRequest(missingConn) {
		t.Error("missing Connection header should not match")
	}
}

func TestIsWS101Response(t *testing.T) {
	good := &envelope.HTTPMessage{
		Status: 101, Headers: []envelope.KeyValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		},
	}
	if !isWS101Response(good) {
		t.Error("good 101 not detected")
	}

	wrongStatus := &envelope.HTTPMessage{
		Status: 200, Headers: good.Headers,
	}
	if isWS101Response(wrongStatus) {
		t.Error("non-101 status must not match")
	}
}

func TestIsSSEResponse(t *testing.T) {
	cases := []struct {
		name string
		msg  *envelope.HTTPMessage
		want bool
	}{
		{
			name: "200 + text/event-stream",
			msg: &envelope.HTTPMessage{Status: 200, Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/event-stream"},
			}},
			want: true,
		},
		{
			name: "200 + content-type with charset parameter",
			msg: &envelope.HTTPMessage{Status: 200, Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "text/event-stream; charset=utf-8"},
			}},
			want: true,
		},
		{
			name: "206 (partial 2xx) still matches",
			msg: &envelope.HTTPMessage{Status: 206, Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/event-stream"},
			}},
			want: true,
		},
		{
			name: "404 must not match",
			msg: &envelope.HTTPMessage{Status: 404, Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/event-stream"},
			}},
			want: false,
		},
		{
			name: "200 application/json must not match",
			msg: &envelope.HTTPMessage{Status: 200, Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/json"},
			}},
			want: false,
		},
		{
			name: "200 missing Content-Type must not match",
			msg:  &envelope.HTTPMessage{Status: 200, Headers: []envelope.KeyValue{}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSSEResponse(tc.msg); got != tc.want {
				t.Errorf("isSSEResponse = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- UpgradeStep observation ---

func TestUpgradeStep_NoNoticeNoOp(t *testing.T) {
	step := NewUpgradeStep()
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Headers: []envelope.KeyValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		}},
	}
	res := step.Process(context.Background(), env)
	if res.Action != pipeline.Continue {
		t.Errorf("UpgradeStep without notice returned Action %v, want Continue", res.Action)
	}
}

func TestUpgradeStep_WSRequestThen101_PendingWS(t *testing.T) {
	notice := &UpgradeNotice{}
	ctx := WithUpgradeNotice(context.Background(), notice)
	step := NewUpgradeStep()

	req := &envelope.Envelope{
		Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Headers: []envelope.KeyValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		}},
	}
	if r := step.Process(ctx, req); r.Action != pipeline.Continue {
		t.Errorf("send action = %v, want Continue", r.Action)
	}
	if !notice.hasSendUpgrade() {
		t.Error("notice should observe send upgrade")
	}
	if notice.Pending() != "" {
		t.Errorf("notice should NOT yet be pending after send-only, got %q", notice.Pending())
	}

	resp := &envelope.Envelope{
		Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: 101, Headers: []envelope.KeyValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		}},
	}
	step.Process(ctx, resp)
	if got := notice.Pending(); got != UpgradeWS {
		t.Errorf("notice.Pending = %q, want %q", got, UpgradeWS)
	}
}

func TestUpgradeStep_101WithoutPriorRequest_NoMatch(t *testing.T) {
	notice := &UpgradeNotice{}
	ctx := WithUpgradeNotice(context.Background(), notice)
	step := NewUpgradeStep()

	resp := &envelope.Envelope{
		Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: 101, Headers: []envelope.KeyValue{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
		}},
	}
	step.Process(ctx, resp)
	if got := notice.Pending(); got != "" {
		t.Errorf("notice.Pending = %q, want empty (no Send-side request)", got)
	}
}

func TestUpgradeStep_SSEResponse_PendingSSE(t *testing.T) {
	notice := &UpgradeNotice{}
	ctx := WithUpgradeNotice(context.Background(), notice)
	step := NewUpgradeStep()

	resp := &envelope.Envelope{
		Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: 200, Headers: []envelope.KeyValue{
			{Name: "Content-Type", Value: "text/event-stream; charset=utf-8"},
		}},
	}
	step.Process(ctx, resp)
	if got := notice.Pending(); got != UpgradeSSE {
		t.Errorf("notice.Pending = %q, want %q", got, UpgradeSSE)
	}
}

func TestUpgradeStep_NonHTTPEnvelopeIgnored(t *testing.T) {
	notice := &UpgradeNotice{}
	ctx := WithUpgradeNotice(context.Background(), notice)
	step := NewUpgradeStep()

	env := &envelope.Envelope{
		Direction: envelope.Send, Protocol: envelope.ProtocolRaw,
		Message: &envelope.RawMessage{Bytes: []byte("hi")},
	}
	r := step.Process(ctx, env)
	if r.Action != pipeline.Continue {
		t.Errorf("non-HTTP action = %v, want Continue", r.Action)
	}
	if notice.hasSendUpgrade() || notice.Pending() != "" {
		t.Error("non-HTTP envelope must not mutate notice")
	}
}

// --- drainedChannel and sseLayerAdapter unit tests ---

func TestDrainedChannel_NextReturnsEOF(t *testing.T) {
	d := newDrainedChannel("stream-x")
	if d.StreamID() != "stream-x" {
		t.Errorf("StreamID = %q, want stream-x", d.StreamID())
	}
	if env, err := d.Next(context.Background()); env != nil || !errors.Is(err, io.EOF) {
		t.Errorf("Next = (%v,%v), want (nil,EOF)", env, err)
	}
	if err := d.Send(context.Background(), &envelope.Envelope{}); err != nil {
		t.Errorf("Send error = %v, want nil", err)
	}
	select {
	case <-d.Closed():
	default:
		t.Error("Closed should fire immediately on a drained channel")
	}
	if !errors.Is(d.Err(), io.EOF) {
		t.Errorf("Err = %v, want EOF", d.Err())
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close error = %v, want nil", err)
	}
}

func TestDrainedChannel_NextHonorsCtxCancel(t *testing.T) {
	d := newDrainedChannel("x")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Next err = %v, want context.Canceled", err)
	}
}

func TestSSELayerAdapter_OneShotChannelAndCascadeClose(t *testing.T) {
	closed := false
	closer := &fakeChannelCloser{closeFn: func() error { closed = true; return nil }}
	adapter := newSSELayerAdapter(closer)

	out := adapter.Channels()
	first, ok := <-out
	if !ok || first == nil {
		t.Fatal("expected first Channel")
	}
	// One-shot: subsequent receive yields zero ok=false.
	if _, ok := <-out; ok {
		t.Error("Channels should be closed after one yield")
	}

	if err := adapter.Close(); err != nil {
		t.Errorf("Close error = %v", err)
	}
	if !closed {
		t.Error("Close did not cascade to wrapped Channel")
	}

	// Idempotent.
	closed = false
	if err := adapter.Close(); err != nil {
		t.Errorf("second Close error = %v", err)
	}
	if closed {
		t.Error("second Close should not re-cascade")
	}
}

// fakeChannelCloser is a minimal layer.Channel used to verify cascade Close.
type fakeChannelCloser struct {
	closeFn func() error
	mu      sync.Mutex
	done    chan struct{}
	once    sync.Once
}

func (f *fakeChannelCloser) StreamID() string                                   { return "fake" }
func (f *fakeChannelCloser) Next(_ context.Context) (*envelope.Envelope, error) { return nil, io.EOF }
func (f *fakeChannelCloser) Send(_ context.Context, _ *envelope.Envelope) error { return nil }
func (f *fakeChannelCloser) Close() error {
	f.once.Do(func() {
		if f.done == nil {
			f.done = make(chan struct{})
		}
		close(f.done)
	})
	return f.closeFn()
}
func (f *fakeChannelCloser) Closed() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done == nil {
		f.done = make(chan struct{})
	}
	return f.done
}
func (f *fakeChannelCloser) Err() error { return io.EOF }
