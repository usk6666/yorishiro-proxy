package http2

import (
	"context"
	gohttp "net/http"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestSnapshotRequest_H2(t *testing.T) {
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

func TestSnapshotRequest_NilInputs_H2(t *testing.T) {
	snap := snapshotRequest(nil, nil)
	if snap.headers != nil {
		t.Errorf("expected nil headers, got %v", snap.headers)
	}
	if snap.body != nil {
		t.Errorf("expected nil body, got %v", snap.body)
	}
}

func TestRequestModified_NoChange_H2(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	if requestModified(snap, headers, body) {
		t.Error("expected no modification, but requestModified returned true")
	}
}

func TestRequestModified_BodyChanged_H2(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	if !requestModified(snap, headers, []byte("world")) {
		t.Error("expected modification detected for changed body")
	}
}

func TestRequestModified_HeaderChanged_H2(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte("hello")
	snap := snapshotRequest(headers, body)

	modifiedHeaders := headers.Clone()
	modifiedHeaders.Set("X-New", "true")

	if !requestModified(snap, modifiedHeaders, body) {
		t.Error("expected modification detected for added header")
	}
}

func TestRecordSendWithVariant_NoModification_H2(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req := &gohttp.Request{
		Method: "GET",
		Header: gohttp.Header{"Content-Type": {"text/plain"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/path"}
	body := []byte("request body")

	snap := snapshotRequest(req.Header, body)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:   "conn-1",
		start:    time.Now(),
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  body,
	}, &snap, logger)

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

func TestRecordSendWithVariant_BodyModified_H2(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req := &gohttp.Request{
		Method: "POST",
		Header: gohttp.Header{"Content-Type": {"application/json"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/api"}

	originalBody := []byte(`{"key":"original"}`)
	modifiedBody := []byte(`{"key":"modified"}`)

	snap := snapshotRequest(req.Header, originalBody)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:   "conn-2",
		start:    time.Now(),
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  modifiedBody,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2", result.recvSequence)
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Message 0: original.
	if msgs[0].Metadata == nil || msgs[0].Metadata["variant"] != "original" {
		t.Errorf("original metadata = %v, want variant=original", msgs[0].Metadata)
	}
	if string(msgs[0].Body) != `{"key":"original"}` {
		t.Errorf("original body = %q", msgs[0].Body)
	}

	// Message 1: modified.
	if msgs[1].Metadata == nil || msgs[1].Metadata["variant"] != "modified" {
		t.Errorf("modified metadata = %v, want variant=modified", msgs[1].Metadata)
	}
	if string(msgs[1].Body) != `{"key":"modified"}` {
		t.Errorf("modified body = %q", msgs[1].Body)
	}
}

func TestRecordSendWithVariant_HeaderModified_H2(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req := &gohttp.Request{
		Method: "GET",
		Header: gohttp.Header{"Authorization": {"Bearer original"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/path"}
	body := []byte("body")

	snap := snapshotRequest(req.Header, body)

	// Simulate header modification.
	req.Header.Set("Authorization", "Bearer modified")

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:   "conn-3",
		start:    time.Now(),
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  body,
	}, &snap, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2", result.recvSequence)
	}

	msgs, _ := store.GetMessages(ctx, result.sessionID, session.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	if gohttp.Header(msgs[0].Headers).Get("Authorization") != "Bearer original" {
		t.Errorf("original Authorization = %q", gohttp.Header(msgs[0].Headers).Get("Authorization"))
	}
	if gohttp.Header(msgs[1].Headers).Get("Authorization") != "Bearer modified" {
		t.Errorf("modified Authorization = %q", gohttp.Header(msgs[1].Headers).Get("Authorization"))
	}
}

func TestRecordSendWithVariant_NilSnap_H2(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req := &gohttp.Request{Method: "GET", Header: gohttp.Header{}}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/"}

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		start:    time.Now(),
		connInfo: &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
	}, nil, logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if result.recvSequence != 1 {
		t.Errorf("recvSequence = %d, want 1", result.recvSequence)
	}
}

func TestRecordSendWithVariant_NilStore_H2(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	req := &gohttp.Request{Method: "GET", Header: gohttp.Header{}}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/"}
	snap := snapshotRequest(req.Header, nil)

	result := handler.recordSendWithVariant(context.Background(), sendRecordParams{
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}, &snap, testutil.DiscardLogger())

	if result != nil {
		t.Errorf("expected nil with nil store, got %v", result)
	}
}

func TestVariantRecording_FullLifecycle_H2(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req := &gohttp.Request{
		Method: "POST",
		Header: gohttp.Header{"Content-Type": {"application/json"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/api"}

	originalBody := []byte(`{"action":"original"}`)
	modifiedBody := []byte(`{"action":"modified"}`)

	snap := snapshotRequest(req.Header, originalBody)

	// Phase 1: Record send with variant.
	sendResult := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:   "conn-lifecycle",
		start:    start,
		connInfo: &session.ConnectionInfo{ClientAddr: "10.0.0.1:5000"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  modifiedBody,
	}, &snap, logger)

	if sendResult == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}
	if sendResult.recvSequence != 2 {
		t.Errorf("recvSequence = %d, want 2", sendResult.recvSequence)
	}

	// Phase 2: Record receive at sequence 2.
	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:      start,
		duration:   100 * time.Millisecond,
		serverAddr: "93.184.216.34:80",
		resp: &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{"Content-Type": {"application/json"}},
		},
		respBody: []byte(`{"status":"ok"}`),
	}, logger)

	// Verify: 3 messages total with correct sequences.
	msgs, _ := store.GetMessages(ctx, sendResult.sessionID, session.MessageListOptions{})
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

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
		default:
			t.Errorf("unexpected message: direction=%q, metadata=%v", m.Direction, m.Metadata)
		}
	}

	// Session should be complete.
	sess, _ := store.GetSession(ctx, sendResult.sessionID)
	if sess.State != "complete" {
		t.Errorf("state = %q, want %q", sess.State, "complete")
	}
}

func TestHeadersModified_H2(t *testing.T) {
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
			name: "a has extra key",
			a:    gohttp.Header{"X-Key": {"val"}, "X-Extra": {"v"}},
			b:    gohttp.Header{"X-Key": {"val"}},
			want: true,
		},
		{
			name: "different value",
			a:    gohttp.Header{"X-Key": {"old"}},
			b:    gohttp.Header{"X-Key": {"new"}},
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
