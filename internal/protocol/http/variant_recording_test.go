package http

import (
	"context"
	gohttp "net/http"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestSnapshotRequest(t *testing.T) {
	headers := gohttp.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
	}
	body := []byte(`{"key":"value"}`)

	snap := snapshotRequest(headers, body)

	// Verify deep copy: modifying original should not affect snapshot.
	headers.Set("Content-Type", "text/plain")
	body[0] = 'X'

	if snap.headers.Get("Content-Type") != "application/json" {
		t.Errorf("snapshot headers mutated: got %q", snap.headers.Get("Content-Type"))
	}
	if snap.body[0] != '{' {
		t.Errorf("snapshot body mutated: got %q", snap.body)
	}
}

func TestSnapshotRequest_NilInputs(t *testing.T) {
	snap := snapshotRequest(nil, nil)
	if snap.headers != nil {
		t.Errorf("expected nil headers, got %v", snap.headers)
	}
	if snap.body != nil {
		t.Errorf("expected nil body, got %v", snap.body)
	}
}

func TestRequestModified_NoChange(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	if requestModified(snap, headers, body) {
		t.Error("expected no modification, but requestModified returned true")
	}
}

func TestRequestModified_BodyChanged(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	modifiedBody := []byte("world")
	if !requestModified(snap, headers, modifiedBody) {
		t.Error("expected modification detected for changed body")
	}
}

func TestRequestModified_HeaderAdded(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	modifiedHeaders := headers.Clone()
	modifiedHeaders.Set("X-Modified", "true")

	if !requestModified(snap, modifiedHeaders, body) {
		t.Error("expected modification detected for added header")
	}
}

func TestRequestModified_HeaderValueChanged(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	modifiedHeaders := headers.Clone()
	modifiedHeaders.Set("Content-Type", "text/plain")

	if !requestModified(snap, modifiedHeaders, body) {
		t.Error("expected modification detected for changed header value")
	}
}

func TestRequestModified_HeaderRemoved(t *testing.T) {
	headers := gohttp.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token"},
	}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	modifiedHeaders := headers.Clone()
	modifiedHeaders.Del("Authorization")

	if !requestModified(snap, modifiedHeaders, body) {
		t.Error("expected modification detected for removed header")
	}
}

func TestRecordSendWithVariant_NoModification(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req.Header.Set("Content-Type", "text/plain")

	body := []byte("request body")

	// Snapshot matches the current state: no modification.
	snap := snapshotRequest(req.Header, body)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    body,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 1 {
		t.Errorf("recvSequence = %d, want 1 (no variant)", result.recvSequence)
	}

	// Verify: only 1 send message, no variant metadata.
	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Direction != "send" {
		t.Errorf("direction = %q, want %q", msgs[0].Direction, "send")
	}
	if msgs[0].Sequence != 0 {
		t.Errorf("sequence = %d, want 0", msgs[0].Sequence)
	}
	if msgs[0].Metadata != nil {
		t.Errorf("metadata should be nil for non-variant message, got %v", msgs[0].Metadata)
	}
	if string(msgs[0].Body) != "request body" {
		t.Errorf("body = %q, want %q", msgs[0].Body, "request body")
	}
}

func TestRecordSendWithVariant_BodyModified(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")

	originalBody := []byte(`{"key":"original"}`)
	modifiedBody := []byte(`{"key":"modified"}`)

	// Snapshot captures the original state.
	snap := snapshotRequest(req.Header, originalBody)

	// Simulate body modification by intercept/transform.
	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-2",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    modifiedBody,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2 (variant recording)", result.recvSequence)
	}

	// Verify: 2 send messages with variant metadata.
	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Message 0: original.
	original := msgs[0]
	if original.Sequence != 0 {
		t.Errorf("original sequence = %d, want 0", original.Sequence)
	}
	if original.Direction != "send" {
		t.Errorf("original direction = %q, want %q", original.Direction, "send")
	}
	if original.Metadata == nil || original.Metadata["variant"] != "original" {
		t.Errorf("original metadata = %v, want variant=original", original.Metadata)
	}
	if string(original.Body) != `{"key":"original"}` {
		t.Errorf("original body = %q, want %q", original.Body, `{"key":"original"}`)
	}

	// Message 1: modified.
	modified := msgs[1]
	if modified.Sequence != 1 {
		t.Errorf("modified sequence = %d, want 1", modified.Sequence)
	}
	if modified.Direction != "send" {
		t.Errorf("modified direction = %q, want %q", modified.Direction, "send")
	}
	if modified.Metadata == nil || modified.Metadata["variant"] != "modified" {
		t.Errorf("modified metadata = %v, want variant=modified", modified.Metadata)
	}
	if string(modified.Body) != `{"key":"modified"}` {
		t.Errorf("modified body = %q, want %q", modified.Body, `{"key":"modified"}`)
	}
	if modified.RawBytes != nil {
		t.Error("modified RawBytes should be nil (not wire-observed)")
	}
}

func TestRecordSendWithVariant_HeaderModified(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req.Header.Set("Authorization", "Bearer original-token")

	body := []byte("body")

	// Snapshot captures the original state.
	snap := snapshotRequest(req.Header, body)

	// Simulate header modification by intercept.
	req.Header.Set("Authorization", "Bearer modified-token")

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-3",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    body,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2 (variant recording)", result.recvSequence)
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Original should have the original token.
	if gohttp.Header(msgs[0].Headers).Get("Authorization") != "Bearer original-token" {
		t.Errorf("original Authorization = %q, want %q",
			gohttp.Header(msgs[0].Headers).Get("Authorization"), "Bearer original-token")
	}

	// Modified should have the modified token.
	if gohttp.Header(msgs[1].Headers).Get("Authorization") != "Bearer modified-token" {
		t.Errorf("modified Authorization = %q, want %q",
			gohttp.Header(msgs[1].Headers).Get("Authorization"), "Bearer modified-token")
	}
}

func TestRecordSendWithVariant_RawBytesOnOriginalOnly(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)
	originalBody := []byte("original")
	modifiedBody := []byte("modified")
	rawBytes := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal")

	snap := snapshotRequest(req.Header, originalBody)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-4",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    modifiedBody,
		rawRequest: rawBytes,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Original message should have RawBytes.
	if msgs[0].RawBytes == nil {
		t.Error("original RawBytes should not be nil")
	}

	// Modified message should NOT have RawBytes.
	if msgs[1].RawBytes != nil {
		t.Error("modified RawBytes should be nil (not wire-observed)")
	}
}

func TestRecordSendWithVariant_NilSnap(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)

	// Nil snapshot should behave like recordSend (no variant).
	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    start,
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
	}, nil, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 1 {
		t.Errorf("recvSequence = %d, want 1", result.recvSequence)
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Metadata != nil {
		t.Errorf("metadata should be nil, got %v", msgs[0].Metadata)
	}
}

func TestRecordSendWithVariant_NilStore(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	snap := snapshotRequest(req.Header, nil)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		req:      req,
	}, &snap, logger)

	if result != nil {
		t.Errorf("expected nil with nil store, got %v", result)
	}
}

func TestVariantRecording_FullLifecycle(t *testing.T) {
	// Test the full lifecycle with variant recording:
	// recordSendWithVariant (2 sends) → recordReceive (at sequence 2)
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")

	originalBody := []byte(`{"action":"original"}`)
	modifiedBody := []byte(`{"action":"modified"}`)

	snap := snapshotRequest(req.Header, originalBody)

	// Phase 1: Record send with variant (modification detected).
	sendResult := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-lifecycle",
		clientAddr: "10.0.0.1:5000",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "10.0.0.1:5000"},
		req:        req,
		reqBody:    modifiedBody,
		rawRequest: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}, &snap, logger)

	if sendResult == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if sendResult.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2", sendResult.recvSequence)
	}

	// Verify intermediate state: session is active, 2 send messages.
	sess, err := store.GetSession(ctx, sendResult.sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.State != "active" {
		t.Errorf("state = %q, want %q", sess.State, "active")
	}

	msgs, _ := store.GetMessages(ctx, sendResult.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("after send: expected 2 messages, got %d", len(msgs))
	}

	// Phase 2: Record receive (should use sequence 2).
	duration := 100 * time.Millisecond
	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{"Content-Type": {"application/json"}},
	}

	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:      start,
		duration:   duration,
		serverAddr: "93.184.216.34:80",
		resp:       resp,
		respBody:   []byte(`{"status":"ok"}`),
	}, logger)

	// Verify final state: 3 messages total.
	msgs, _ = store.GetMessages(ctx, sendResult.sessionID, session.MessageListOptions{})
	if len(msgs) != 3 {
		t.Fatalf("after receive: expected 3 messages, got %d", len(msgs))
	}

	// Verify sequence numbers: original=0, modified=1, receive=2.
	for _, m := range msgs {
		switch {
		case m.Direction == "send" && m.Metadata != nil && m.Metadata["variant"] == "original":
			if m.Sequence != 0 {
				t.Errorf("original sequence = %d, want 0", m.Sequence)
			}
		case m.Direction == "send" && m.Metadata != nil && m.Metadata["variant"] == "modified":
			if m.Sequence != 1 {
				t.Errorf("modified sequence = %d, want 1", m.Sequence)
			}
		case m.Direction == "receive":
			if m.Sequence != 2 {
				t.Errorf("receive sequence = %d, want 2", m.Sequence)
			}
			if m.StatusCode != 200 {
				t.Errorf("receive status = %d, want 200", m.StatusCode)
			}
		default:
			t.Errorf("unexpected message: direction=%q, metadata=%v", m.Direction, m.Metadata)
		}
	}

	// Session should be complete.
	sess, _ = store.GetSession(ctx, sendResult.sessionID)
	if sess.State != "complete" {
		t.Errorf("final state = %q, want %q", sess.State, "complete")
	}
}

func TestVariantRecording_NoModification_FullLifecycle(t *testing.T) {
	// When no modification occurs, lifecycle should be normal:
	// 1 send (seq=0, no variant) → 1 receive (seq=1)
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	body := []byte("unchanged")

	snap := snapshotRequest(req.Header, body)

	sendResult := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:     "conn-nomod",
		clientAddr: "10.0.0.1:5000",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &session.ConnectionInfo{ClientAddr: "10.0.0.1:5000"},
		req:        req,
		reqBody:    body,
	}, &snap, logger)

	if sendResult == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if sendResult.recvSequence != 1 {
		t.Errorf("recvSequence = %d, want 1", sendResult.recvSequence)
	}

	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{},
	}
	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:      start,
		duration:   50 * time.Millisecond,
		serverAddr: "93.184.216.34:80",
		resp:       resp,
		respBody:   []byte("ok"),
	}, logger)

	msgs, _ := store.GetMessages(ctx, sendResult.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Verify: send at seq=0, receive at seq=1, no variant metadata.
	for _, m := range msgs {
		if m.Direction == "send" {
			if m.Sequence != 0 {
				t.Errorf("send sequence = %d, want 0", m.Sequence)
			}
			if m.Metadata != nil {
				t.Errorf("send metadata should be nil, got %v", m.Metadata)
			}
		} else {
			if m.Sequence != 1 {
				t.Errorf("receive sequence = %d, want 1", m.Sequence)
			}
		}
	}
}

func TestRecordSendWithVariant_SelfContainedMessages(t *testing.T) {
	// Verify that each message is self-contained: the original message has
	// original headers+body, the modified message has modified headers+body.
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)
	req.Header.Set("X-Original", "yes")
	req.Header.Set("Content-Type", "text/plain")

	originalBody := []byte("original-body")
	snap := snapshotRequest(req.Header, originalBody)

	// Simulate modification: change header and body.
	req.Header.Del("X-Original")
	req.Header.Set("X-Modified", "yes")
	modifiedBody := []byte("modified-body")

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:   "conn-5",
		protocol: "HTTP/1.x",
		start:    start,
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqBody:  modifiedBody,
		reqURL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/api",
		},
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Original message: should have X-Original header and original body.
	original := msgs[0]
	if gohttp.Header(original.Headers).Get("X-Original") != "yes" {
		t.Error("original should have X-Original header")
	}
	if gohttp.Header(original.Headers).Get("X-Modified") != "" {
		t.Error("original should NOT have X-Modified header")
	}
	if string(original.Body) != "original-body" {
		t.Errorf("original body = %q, want %q", original.Body, "original-body")
	}

	// Modified message: should have X-Modified header and modified body.
	modified := msgs[1]
	if gohttp.Header(modified.Headers).Get("X-Modified") != "yes" {
		t.Error("modified should have X-Modified header")
	}
	if gohttp.Header(modified.Headers).Get("X-Original") != "" {
		t.Error("modified should NOT have X-Original header")
	}
	if string(modified.Body) != "modified-body" {
		t.Errorf("modified body = %q, want %q", modified.Body, "modified-body")
	}
}

func TestHeadersModified(t *testing.T) {
	tests := []struct {
		name string
		a, b gohttp.Header
		want bool
	}{
		{
			name: "identical",
			a:    gohttp.Header{"X-Key": {"val"}},
			b:    gohttp.Header{"X-Key": {"val"}},
			want: false,
		},
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: false,
		},
		{
			name: "both empty",
			a:    gohttp.Header{},
			b:    gohttp.Header{},
			want: false,
		},
		{
			name: "a has extra key",
			a:    gohttp.Header{"X-Key": {"val"}, "X-Extra": {"v"}},
			b:    gohttp.Header{"X-Key": {"val"}},
			want: true,
		},
		{
			name: "b has extra key",
			a:    gohttp.Header{"X-Key": {"val"}},
			b:    gohttp.Header{"X-Key": {"val"}, "X-Extra": {"v"}},
			want: true,
		},
		{
			name: "different value",
			a:    gohttp.Header{"X-Key": {"old"}},
			b:    gohttp.Header{"X-Key": {"new"}},
			want: true,
		},
		{
			name: "different multi-value count",
			a:    gohttp.Header{"X-Key": {"a", "b"}},
			b:    gohttp.Header{"X-Key": {"a"}},
			want: true,
		},
		{
			name: "different multi-value order",
			a:    gohttp.Header{"X-Key": {"a", "b"}},
			b:    gohttp.Header{"X-Key": {"b", "a"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := headersModified(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("headersModified() = %v, want %v", got, tt.want)
			}
		})
	}
}
