package http2

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestInterceptRequestSetsRawBytes verifies that interceptRequest attaches
// raw frame bytes to the enqueued intercepted item.
func TestInterceptRequestSetsRawBytes(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	handler.InterceptEngine = engine
	handler.InterceptQueue = queue

	// Add a catch-all rule.
	engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders, 1, []byte("hdr")),
		buildTestFrame(frame.TypeData, frame.FlagEndStream, 1, []byte("body")),
	}

	h2req := &h2Request{
		Method:    "GET",
		Scheme:    "http",
		Authority: "example.com",
		Path:      "/test",
		AllHeaders: []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/test"},
		},
	}

	// Release the intercept immediately in a goroutine.
	go func() {
		time.Sleep(10 * time.Millisecond)
		items := queue.List()
		if len(items) == 0 {
			return
		}
		item := items[0]
		// Verify raw bytes were set.
		if len(item.RawBytes) == 0 {
			t.Error("expected raw bytes to be set on intercepted item")
		}
		queue.Respond(item.ID, intercept.InterceptAction{Type: intercept.ActionRelease})
	}()

	action, intercepted := handler.interceptRequest(context.Background(), h2req, nil, rawFrames, testutil.DiscardLogger())
	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionRelease {
		t.Errorf("expected release action, got %v", action.Type)
	}
}

// TestInterceptRequestRawModeRelease verifies that raw mode release sets the
// interceptRawAction on the streamContext.
func TestInterceptRequestRawModeRelease(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	handler.InterceptEngine = engine
	handler.InterceptQueue = queue

	engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("hdr")),
	}

	h2req := &h2Request{
		Method:    "GET",
		Scheme:    "http",
		Authority: "example.com",
		Path:      "/test",
		AllHeaders: []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/test"},
		},
	}

	// Release in raw mode.
	go func() {
		time.Sleep(10 * time.Millisecond)
		items := queue.List()
		if len(items) == 0 {
			return
		}
		queue.Respond(items[0].ID, intercept.InterceptAction{
			Type: intercept.ActionRelease,
			Mode: intercept.ModeRaw,
		})
	}()

	action, intercepted := handler.interceptRequest(context.Background(), h2req, nil, rawFrames, testutil.DiscardLogger())
	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if !action.IsRawMode() {
		t.Error("expected raw mode action")
	}
	if action.Type != intercept.ActionRelease {
		t.Errorf("expected release, got %v", action.Type)
	}
}

// TestRecordRawSend_Unmodified verifies that recordRawSend for unmodified
// raw bytes records a single send message (no variant).
func TestRecordRawSend_Unmodified(t *testing.T) {
	store := &mockFlowStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("hdr")),
	}
	originalRawBytes := joinRawFrames(rawFrames)

	sc := &streamContext{
		ctx: context.Background(),
		h2req: &h2Request{
			Method: "GET", Scheme: "http", Authority: "example.com", Path: "/test",
			AllHeaders: []hpack.HeaderField{
				{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/test"},
			},
		},
		reqURL:       mustParseURL("http://example.com/test"),
		connID:       "conn-1",
		clientAddr:   "127.0.0.1:1234",
		start:        time.Now(),
		logger:       testutil.DiscardLogger(),
		reqRawFrames: rawFrames,
		connInfo:     &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		srp: sendRecordParams{
			connID:   "conn-1",
			connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		},
	}
	sc.srp.method = sc.h2req.Method
	sc.srp.host = sc.h2req.Authority
	sc.srp.headers = sc.h2req.AllHeaders
	sc.srp.reqURL = sc.reqURL
	sc.srp.rawFrames = rawFrames

	result := handler.recordRawSend(sc, originalRawBytes, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.recvSequence != 1 {
		t.Errorf("recvSequence = %d, want 1", result.recvSequence)
	}

	// Should have 1 flow and 1 message.
	if len(store.flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(store.flows))
	}
	if len(store.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(store.messages))
	}

	// The message should not have variant metadata.
	msg := store.messages[0]
	if _, ok := msg.Metadata["variant"]; ok {
		t.Error("expected no variant metadata for unmodified raw send")
	}
}

// TestRecordRawSend_Modified verifies that recordRawSend for modified
// raw bytes records two send messages (original + modified variants).
func TestRecordRawSend_Modified(t *testing.T) {
	store := &mockFlowStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("hdr")),
	}
	modifiedRawBytes := buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("modified-hdr"))

	sc := &streamContext{
		ctx: context.Background(),
		h2req: &h2Request{
			Method: "GET", Scheme: "http", Authority: "example.com", Path: "/test",
			AllHeaders: []hpack.HeaderField{
				{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/test"},
			},
		},
		reqURL:       mustParseURL("http://example.com/test"),
		connID:       "conn-1",
		clientAddr:   "127.0.0.1:1234",
		start:        time.Now(),
		logger:       testutil.DiscardLogger(),
		reqRawFrames: rawFrames,
		connInfo:     &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		srp: sendRecordParams{
			connID:   "conn-1",
			connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		},
	}
	sc.srp.method = sc.h2req.Method
	sc.srp.host = sc.h2req.Authority
	sc.srp.headers = sc.h2req.AllHeaders
	sc.srp.reqURL = sc.reqURL
	sc.srp.rawFrames = rawFrames

	result := handler.recordRawSend(sc, modifiedRawBytes, true)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2", result.recvSequence)
	}

	// Should have 1 flow and 2 messages.
	if len(store.flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(store.flows))
	}
	if len(store.messages) != 2 {
		t.Fatalf("messages = %d, want 2", len(store.messages))
	}

	// First message: original variant.
	origMsg := store.messages[0]
	if origMsg.Sequence != 0 {
		t.Errorf("original sequence = %d, want 0", origMsg.Sequence)
	}
	if origMsg.Metadata["variant"] != "original" {
		t.Errorf("original variant = %q, want %q", origMsg.Metadata["variant"], "original")
	}
	if !bytes.Equal(origMsg.RawBytes, joinRawFrames(rawFrames)) {
		t.Error("original raw bytes mismatch")
	}

	// Second message: modified variant.
	modMsg := store.messages[1]
	if modMsg.Sequence != 1 {
		t.Errorf("modified sequence = %d, want 1", modMsg.Sequence)
	}
	if modMsg.Metadata["variant"] != "modified" {
		t.Errorf("modified variant = %q, want %q", modMsg.Metadata["variant"], "modified")
	}
	if !bytes.Equal(modMsg.RawBytes, modifiedRawBytes) {
		t.Error("modified raw bytes mismatch")
	}
}

// TestHandleRequestIntercept_RawModeRelease verifies that handleRequestIntercept
// sets interceptRawAction with the original raw bytes when raw mode release is used.
func TestHandleRequestIntercept_RawModeRelease(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(200 * time.Millisecond)
	handler.InterceptEngine = engine
	handler.InterceptQueue = queue

	engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("hdr")),
	}

	sc := &streamContext{
		ctx: context.Background(),
		h2req: &h2Request{
			Method: "GET", Scheme: "http", Authority: "example.com", Path: "/test",
			AllHeaders: []hpack.HeaderField{
				{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/test"},
			},
		},
		reqURL:       mustParseURL("http://example.com/test"),
		logger:       testutil.DiscardLogger(),
		reqRawFrames: rawFrames,
		srp:          sendRecordParams{reqBody: nil},
	}
	sc.srp.method = sc.h2req.Method
	sc.srp.host = sc.h2req.Authority
	sc.srp.headers = sc.h2req.AllHeaders
	sc.srp.reqURL = sc.reqURL

	outHeaders := buildH2HeadersFromH2Req(sc.h2req)
	snap := snapshotRequest(sc.h2req.RegularHeaders(), nil)

	// Release in raw mode.
	go func() {
		time.Sleep(20 * time.Millisecond)
		items := queue.List()
		if len(items) == 0 {
			return
		}
		queue.Respond(items[0].ID, intercept.InterceptAction{
			Type: intercept.ActionRelease,
			Mode: intercept.ModeRaw,
		})
	}()

	_, ok := handler.handleRequestIntercept(sc, outHeaders, &snap)
	if !ok {
		t.Fatal("expected ok=true from handleRequestIntercept")
	}

	if sc.interceptRawAction == nil {
		t.Fatal("expected interceptRawAction to be set")
	}
	if !sc.interceptRawAction.IsRawMode() {
		t.Error("expected raw mode action")
	}
	// For raw release, RawOverride should be the original raw bytes.
	if !bytes.Equal(sc.interceptRawAction.RawOverride, joinRawFrames(rawFrames)) {
		t.Error("RawOverride should be the original raw frames for raw release")
	}
}

// TestHandleRequestIntercept_RawModeModifyAndForward verifies that
// handleRequestIntercept sets interceptRawAction with edited raw bytes.
func TestHandleRequestIntercept_RawModeModifyAndForward(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(200 * time.Millisecond)
	handler.InterceptEngine = engine
	handler.InterceptQueue = queue

	engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})

	rawFrames := [][]byte{
		buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("hdr")),
	}
	editedRaw := buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("edited"))

	sc := &streamContext{
		ctx: context.Background(),
		h2req: &h2Request{
			Method: "GET", Scheme: "http", Authority: "example.com", Path: "/test",
			AllHeaders: []hpack.HeaderField{
				{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/test"},
			},
		},
		reqURL:       mustParseURL("http://example.com/test"),
		logger:       testutil.DiscardLogger(),
		reqRawFrames: rawFrames,
		srp:          sendRecordParams{reqBody: nil},
	}
	sc.srp.method = sc.h2req.Method
	sc.srp.host = sc.h2req.Authority
	sc.srp.headers = sc.h2req.AllHeaders
	sc.srp.reqURL = sc.reqURL

	outHeaders := buildH2HeadersFromH2Req(sc.h2req)
	snap := snapshotRequest(sc.h2req.RegularHeaders(), nil)

	go func() {
		time.Sleep(20 * time.Millisecond)
		items := queue.List()
		if len(items) == 0 {
			return
		}
		queue.Respond(items[0].ID, intercept.InterceptAction{
			Type:        intercept.ActionModifyAndForward,
			Mode:        intercept.ModeRaw,
			RawOverride: editedRaw,
		})
	}()

	_, ok := handler.handleRequestIntercept(sc, outHeaders, &snap)
	if !ok {
		t.Fatal("expected ok=true")
	}

	if sc.interceptRawAction == nil {
		t.Fatal("expected interceptRawAction to be set")
	}
	if !bytes.Equal(sc.interceptRawAction.RawOverride, editedRaw) {
		t.Error("RawOverride should be the edited raw bytes")
	}
}

// --- helpers ---

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// mockFlowStore is a simple in-memory flow store for testing.
type mockFlowStore struct {
	flows    []*flow.Flow
	messages []*flow.Message
	updates  []mockFlowUpdate
}

type mockFlowUpdate struct {
	FlowID string
	Update flow.FlowUpdate
}

func (m *mockFlowStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	if f.ID == "" {
		f.ID = "flow-" + time.Now().Format("150405.000000")
	}
	m.flows = append(m.flows, f)
	return nil
}

func (m *mockFlowStore) AppendMessage(_ context.Context, msg *flow.Message) error {
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockFlowStore) UpdateFlow(_ context.Context, flowID string, update flow.FlowUpdate) error {
	m.updates = append(m.updates, mockFlowUpdate{FlowID: flowID, Update: update})
	return nil
}

func init() {
	// Suppress log output during tests.
	slog.SetDefault(slog.New(slog.NewTextHandler(
		&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError + 1},
	)))
}
