package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Unit tests for applyRequestTransform / applyResponseTransform ---

func TestApplyRequestTransform_NilPipeline(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	body := []byte(`{"token":"old-value"}`)
	outReq, _ := gohttp.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))
	outReq.Header.Set("Content-Type", "application/json")

	sc := &streamContext{
		reqBody: body,
		srp:     sendRecordParams{reqBody: body},
	}

	handler.applyRequestTransform(sc, outReq)

	// Body should remain unchanged.
	if string(sc.reqBody) != `{"token":"old-value"}` {
		t.Errorf("reqBody = %q, want original", sc.reqBody)
	}
}

func TestApplyRequestTransform_WithReplaceBody(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-token",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-value",
			Value:   "new-value",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	body := []byte(`{"token":"old-value"}`)
	outReq, _ := gohttp.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))
	outReq.Header.Set("Content-Type", "application/json")

	sc := &streamContext{
		reqBody: body,
		srp:     sendRecordParams{reqBody: body},
	}

	handler.applyRequestTransform(sc, outReq)

	want := `{"token":"new-value"}`
	if string(sc.reqBody) != want {
		t.Errorf("reqBody = %q, want %q", sc.reqBody, want)
	}
	if string(sc.srp.reqBody) != want {
		t.Errorf("srp.reqBody = %q, want %q", sc.srp.reqBody, want)
	}
	// Verify outReq body is also updated.
	reqBodyBytes, _ := io.ReadAll(outReq.Body)
	if string(reqBodyBytes) != want {
		t.Errorf("outReq.Body = %q, want %q", reqBodyBytes, want)
	}
	if outReq.ContentLength != int64(len(want)) {
		t.Errorf("outReq.ContentLength = %d, want %d", outReq.ContentLength, len(want))
	}
}

func TestApplyRequestTransform_AddHeader(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "add-header",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "X-Custom-Header",
			Value:  "injected",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	body := []byte("test-body")
	outReq, _ := gohttp.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))

	sc := &streamContext{
		reqBody: body,
		srp:     sendRecordParams{reqBody: body},
	}

	handler.applyRequestTransform(sc, outReq)

	if got := outReq.Header.Get("X-Custom-Header"); got != "injected" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "injected")
	}
}

func TestApplyResponseTransform_NilPipeline(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/plain"}},
	}
	body := []byte("original-body")

	gotHeader, gotBody := handler.applyResponseTransform(resp, body)

	if string(gotBody) != "original-body" {
		t.Errorf("body = %q, want %q", gotBody, "original-body")
	}
	if gotHeader.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", gotHeader.Get("Content-Type"), "text/plain")
	}
}

func TestApplyResponseTransform_WithReplaceBody(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-resp",
		Direction: rules.DirectionResponse,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "secret",
			Value:   "REDACTED",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"application/json"}},
	}
	body := []byte(`{"data":"secret-value"}`)

	_, gotBody := handler.applyResponseTransform(resp, body)

	want := `{"data":"REDACTED-value"}`
	if string(gotBody) != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
}

func TestApplyResponseTransform_SetHeader(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "set-resp-header",
		Direction: rules.DirectionResponse,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Transformed",
			Value:  "true",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{},
	}
	body := []byte("test")

	gotHeader, _ := handler.applyResponseTransform(resp, body)

	if got := gotHeader.Get("X-Transformed"); got != "true" {
		t.Errorf("X-Transformed = %q, want %q", got, "true")
	}
}

// --- Integration tests: end-to-end through handleStream ---

func TestHandleStream_RequestTransform_AppliedBeforeUpstream(t *testing.T) {
	// Verify that request body transform is applied before forwarding upstream.
	var receivedBody string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-token",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-token",
			Value:   "new-token",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	addr, cancel := startH2CProxyListener(t, handler, "conn-req-transform", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := `{"auth":"old-token"}`
	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The upstream should have received the transformed body.
	want := `{"auth":"new-token"}`
	if receivedBody != want {
		t.Errorf("upstream received body = %q, want %q", receivedBody, want)
	}

	// Verify the recorded messages include a modified variant with the
	// transformed body. When transform modifies the request, variant
	// recording creates two send messages: original (seq 0) and modified
	// (seq 1). We check that the modified variant has the transformed body.
	time.Sleep(200 * time.Millisecond)
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}
	// Find the modified send message (the one with the transformed body).
	store.mu.Lock()
	var foundModified bool
	for _, msg := range store.messages {
		if msg.Direction == "send" && string(msg.Body) == want {
			foundModified = true
			break
		}
	}
	store.mu.Unlock()
	if !foundModified {
		t.Errorf("no send message with transformed body %q found", want)
	}
}

func TestHandleStream_ResponseTransform_AppliedBeforeClient(t *testing.T) {
	// Verify that response body transform is applied before sending to client.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, `{"secret":"password123"}`)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "redact-secret",
		Direction: rules.DirectionResponse,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "password123",
			Value:   "REDACTED",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	addr, cancel := startH2CProxyListener(t, handler, "conn-resp-transform", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Client should receive the transformed body.
	want := `{"secret":"REDACTED"}`
	if string(body) != want {
		t.Errorf("client received body = %q, want %q", body, want)
	}
}

func TestHandleStream_BothDirectionTransform(t *testing.T) {
	// Verify that a "both" direction transform applies to both request and response.
	var receivedBody string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, `{"value":"test-marker"}`)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-marker",
		Direction: rules.DirectionBoth,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "test-marker",
			Value:   "REPLACED",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	addr, cancel := startH2CProxyListener(t, handler, "conn-both-transform", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := `{"input":"test-marker"}`
	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Request body should be transformed upstream.
	wantReqBody := `{"input":"REPLACED"}`
	if receivedBody != wantReqBody {
		t.Errorf("upstream received body = %q, want %q", receivedBody, wantReqBody)
	}

	// Response body should be transformed for client.
	wantRespBody := `{"value":"REPLACED"}`
	if string(body) != wantRespBody {
		t.Errorf("client received body = %q, want %q", body, wantRespBody)
	}
}

func TestHandleStream_RequestTransform_NoMatchDoesNotModify(t *testing.T) {
	// Verify that a transform rule that does not match leaves the body unchanged.
	var receivedBody string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "no-match",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "nonexistent-pattern",
			Value:   "replacement",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	addr, cancel := startH2CProxyListener(t, handler, "conn-no-match", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := `{"data":"original"}`
	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(reqBody))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Body should remain unchanged.
	if receivedBody != reqBody {
		t.Errorf("upstream received body = %q, want %q", receivedBody, reqBody)
	}
}

func TestHandleStream_RequestTransform_HeaderAddedToUpstream(t *testing.T) {
	// Verify that request header transform adds headers to upstream request.
	var receivedHeader string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "add-injected",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "X-Injected",
			Value:  "from-transform",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	addr, cancel := startH2CProxyListener(t, handler, "conn-header-transform", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedHeader != "from-transform" {
		t.Errorf("upstream X-Injected = %q, want %q", receivedHeader, "from-transform")
	}
}
