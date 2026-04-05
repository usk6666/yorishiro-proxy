package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestApplyIntercept_RawModeRelease(t *testing.T) {
	// When release+raw is selected, applyIntercept should return IsRaw=true
	// with the original raw bytes.
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	goReq, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq)
	reqURL := goReq.URL
	recordBody := []byte("test body")
	rawRequest := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		isRaw    bool
		rawBytes []byte
		dropped  bool
	}
	resultCh := make(chan result, 1)
	go func() {
		ir := handler.applyIntercept(ctx, serverConn, req, reqURL, recordBody, rawRequest, logger)
		resultCh <- result{ir.IsRaw, ir.RawBytes, ir.Dropped}
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Verify raw bytes were attached to the queue item.
	item, err := queue.Get(interceptedID)
	if err != nil {
		t.Fatalf("get intercepted item: %v", err)
	}
	if len(item.RawBytes) == 0 {
		t.Fatal("expected raw bytes to be attached to intercepted item")
	}

	// Respond with release+raw.
	err = queue.Respond(interceptedID, intercept.InterceptAction{
		Type: intercept.ActionRelease,
		Mode: intercept.ModeRaw,
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped")
	}
	if !res.isRaw {
		t.Fatal("expected raw mode to be true")
	}
	if string(res.rawBytes) != string(rawRequest) {
		t.Errorf("raw bytes = %q, want %q", res.rawBytes, rawRequest)
	}
}

func TestApplyIntercept_RawModeModifyAndForward(t *testing.T) {
	// When modify_and_forward+raw is selected, applyIntercept should return
	// IsRaw=true with the override raw bytes and original raw bytes.
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	goReq, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq)
	reqURL := goReq.URL
	recordBody := []byte("test body")
	rawRequest := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")
	modifiedRaw := []byte("GET /evil HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		isRaw            bool
		rawBytes         []byte
		originalRawBytes []byte
		dropped          bool
	}
	resultCh := make(chan result, 1)
	go func() {
		ir := handler.applyIntercept(ctx, serverConn, req, reqURL, recordBody, rawRequest, logger)
		resultCh <- result{ir.IsRaw, ir.RawBytes, ir.OriginalRawBytes, ir.Dropped}
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Respond with modify_and_forward+raw.
	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type:        intercept.ActionModifyAndForward,
		Mode:        intercept.ModeRaw,
		RawOverride: modifiedRaw,
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped")
	}
	if !res.isRaw {
		t.Fatal("expected raw mode to be true")
	}
	if string(res.rawBytes) != string(modifiedRaw) {
		t.Errorf("raw bytes = %q, want %q", res.rawBytes, modifiedRaw)
	}
	if string(res.originalRawBytes) != string(rawRequest) {
		t.Errorf("original raw bytes = %q, want %q", res.originalRawBytes, rawRequest)
	}
}

func TestApplyIntercept_StructuredModeDefault(t *testing.T) {
	// When no mode is specified (default), applyIntercept should return
	// IsRaw=false (backward compatible structured mode).
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	goReq, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq)
	reqURL := goReq.URL
	recordBody := []byte("test body")
	rawRequest := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		isRaw   bool
		dropped bool
	}
	resultCh := make(chan result, 1)
	go func() {
		ir := handler.applyIntercept(ctx, serverConn, req, reqURL, recordBody, rawRequest, logger)
		resultCh <- result{ir.IsRaw, ir.Dropped}
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Respond with release (no mode specified = structured).
	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type: intercept.ActionRelease,
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped")
	}
	if res.isRaw {
		t.Fatal("expected raw mode to be false for default structured mode")
	}
}

func TestApplyIntercept_RawModeRelease_NilRawBytes(t *testing.T) {
	// When release+raw is selected but rawRequest is nil, applyIntercept
	// should return IsRaw=true with nil RawBytes (the caller/upstream will
	// see an empty payload).
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	goReq2, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq2)
	reqURL := goReq2.URL
	recordBody := []byte("test body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		isRaw    bool
		rawBytes []byte
		dropped  bool
	}
	resultCh := make(chan result, 1)
	go func() {
		ir := handler.applyIntercept(ctx, serverConn, req, reqURL, recordBody, nil, logger)
		resultCh <- result{ir.IsRaw, ir.RawBytes, ir.Dropped}
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type: intercept.ActionRelease,
		Mode: intercept.ModeRaw,
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped")
	}
	if !res.isRaw {
		t.Fatal("expected raw mode to be true")
	}
	if res.rawBytes != nil {
		t.Errorf("raw bytes = %v, want nil", res.rawBytes)
	}
}

func TestInterceptRequest_AttachesRawBytes(t *testing.T) {
	// Verify that interceptRequest attaches raw bytes to the queued item.
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	goReq3, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq3)
	reqURL := goReq3.URL
	body := []byte("test body")
	rawBytes := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\ntest body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	// Run interceptRequest in a goroutine.
	go func() {
		handler.interceptRequest(ctx, serverConn, req, reqURL, body, rawBytes, logger)
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	item, err := queue.Get(interceptedID)
	if err != nil {
		t.Fatalf("get intercepted item: %v", err)
	}

	if string(item.RawBytes) != string(rawBytes) {
		t.Errorf("raw bytes = %q, want %q", item.RawBytes, rawBytes)
	}

	// Release to unblock the goroutine.
	queue.Respond(interceptedID, intercept.InterceptAction{Type: intercept.ActionRelease})
}

func TestRawForwardUpstream_Integration(t *testing.T) {
	// Integration test: raw forward to a real HTTP server and verify the
	// response is returned correctly.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Raw-Test", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "raw-forward-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Build a raw HTTP request targeting the upstream server.
	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		strings.TrimPrefix(upstream.URL, "http://"))

	goReqFwd, _ := gohttp.NewRequest("GET", upstream.URL+"/", nil)
	req := goRequestToRaw(goReqFwd)
	reqURL := goReqFwd.URL
	ctx := context.Background()

	result, err := handler.forwardRawUpstream(ctx, req, reqURL, []byte(rawReq), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("forwardRawUpstream: %v", err)
	}

	if len(result.rawResponse) == 0 {
		t.Fatal("expected non-empty raw response")
	}

	if result.resp == nil {
		t.Fatal("expected parsed response, got nil")
	}

	if result.resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", result.resp.StatusCode, gohttp.StatusOK)
	}

	if string(result.respBody) != "raw-forward-ok" {
		t.Errorf("body = %q, want %q", result.respBody, "raw-forward-ok")
	}

	if result.serverAddr == "" {
		t.Error("expected non-empty server address")
	}
}

func TestRawForwardUpstream_SmugglingPattern(t *testing.T) {
	// Verify that a CL+TE conflict pattern is sent as-is without normalization.
	// The upstream server receives the raw bytes exactly as provided.
	var receivedRaw []byte
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// The important thing is that the server received the request.
		// The actual smuggling behavior depends on the server implementation.
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	_ = receivedRaw // Not used in this simplified test.

	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	// CL+TE conflict pattern — this would normally be rejected/normalized by
	// net/http.Transport but raw forwarding sends it as-is.
	rawReq := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
		strings.TrimPrefix(upstream.URL, "http://"))

	goReqSmug, _ := gohttp.NewRequest("POST", upstream.URL+"/", nil)
	req := goRequestToRaw(goReqSmug)
	reqURL := goReqSmug.URL
	ctx := context.Background()

	result, err := handler.forwardRawUpstream(ctx, req, reqURL, []byte(rawReq), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("forwardRawUpstream: %v", err)
	}

	// We just verify the connection succeeded and we got a response back.
	if len(result.rawResponse) == 0 {
		t.Fatal("expected non-empty raw response")
	}
}

func TestHandleRawForward_EndToEnd(t *testing.T) {
	// End-to-end test: intercept a request with raw mode, forward raw bytes
	// to an upstream server, and verify the raw response is written back
	// to the client.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Raw-E2E", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "e2e-raw-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	// Build the raw request targeting the upstream server.
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	rawRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamHost)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start reading the client response.
	type clientResult struct {
		resp *gohttp.Response
		body string
		err  error
	}
	clientCh := make(chan clientResult, 1)
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := gohttp.ReadResponse(reader, nil)
		if err != nil {
			clientCh <- clientResult{err: err}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		clientCh <- clientResult{resp: resp, body: string(body)}
	}()

	// Build the request object.
	rawReqURL := upstream.URL + "/"
	goReqHRF, _ := gohttp.NewRequest("GET", rawReqURL, nil)
	req := goRequestToRaw(goReqHRF)
	reqURL := goReqHRF.URL

	sp := sendRecordParams{
		connID:     "test-conn",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      time.Now(),
		req:        req,
		reqBody:    nil,
		rawRequest: []byte(rawRequest),
	}
	snap := snapshotRawRequest(req.Headers, nil)

	iResult := interceptResult{
		IsRaw:    true,
		RawBytes: []byte(rawRequest),
		Req:      req,
	}

	// Run handleRawForward.
	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.handleRawForward(ctx, serverConn, req, reqURL, iResult, sp, &snap, time.Now(), testutil.DiscardLogger())
	}()

	// Read the response on the client side.
	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client read response: %v", cr.err)
	}

	if cr.resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", cr.resp.StatusCode, gohttp.StatusOK)
	}

	if cr.body != "e2e-raw-ok" {
		t.Errorf("body = %q, want %q", cr.body, "e2e-raw-ok")
	}

	// Verify no error from handleRawForward.
	err := <-errCh
	if err != nil {
		t.Fatalf("handleRawForward: %v", err)
	}
}

func TestReadRawResponse_MalformedResponse(t *testing.T) {
	// When the upstream sends a malformed response, readRawResponse should
	// capture the raw bytes and return nil for the parsed response.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Send a malformed response.
	go func() {
		server.Write([]byte("NOT-HTTP/GARBAGE\r\nfoo\r\n\r\n"))
		server.Close()
	}()

	rawResp, resp, _, err := readRawResponse(client)
	if err != nil {
		t.Fatalf("readRawResponse: %v", err)
	}

	if len(rawResp) == 0 {
		t.Fatal("expected non-empty raw response for malformed data")
	}

	// Response may or may not parse depending on Go's parser behavior.
	// The important thing is no crash and raw bytes are captured.
	_ = resp
}

func TestWriteRawResponseToClient(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	rawResponse := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

	go func() {
		err := writeRawResponseToClient(serverConn, rawResponse)
		if err != nil {
			t.Errorf("writeRawResponseToClient: %v", err)
		}
		serverConn.Close()
	}()

	received, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read from client: %v", err)
	}

	if string(received) != string(rawResponse) {
		t.Errorf("received = %q, want %q", received, rawResponse)
	}
}

func TestRawForward_VariantRecording(t *testing.T) {
	// Verify that raw modify_and_forward records both original and modified
	// variants in the flow store.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "variant-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	originalRaw := fmt.Sprintf("GET /original HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamHost)
	modifiedRaw := fmt.Sprintf("GET /modified HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamHost)

	goReqVar, _ := gohttp.NewRequest("GET", upstream.URL+"/original", nil)
	req := goRequestToRaw(goReqVar)
	reqURL := goReqVar.URL

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	sp := sendRecordParams{
		connID:     "test-variant",
		clientAddr: "127.0.0.1:5678",
		protocol:   "HTTP/1.x",
		start:      time.Now(),
		req:        req,
		reqBody:    nil,
		rawRequest: []byte(originalRaw),
	}
	snap := snapshotRawRequest(req.Headers, nil)

	iResult := interceptResult{
		IsRaw:            true,
		RawBytes:         []byte(modifiedRaw),
		OriginalRawBytes: []byte(originalRaw),
		Req:              req,
		RecordBody:       nil,
	}

	// Drain client side.
	go func() {
		io.ReadAll(clientConn)
	}()

	err := handler.handleRawForward(ctx, serverConn, req, reqURL, iResult, sp, &snap, time.Now(), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("handleRawForward: %v", err)
	}

	// Verify flow was recorded.
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	if len(store.messages) == 0 {
		t.Fatal("expected at least one message to be recorded")
	}

	// Collect send and receive messages separately.
	var sendMsgs, recvMsgs []*flow.Flow
	for _, msg := range store.messages {
		switch msg.Direction {
		case "send":
			sendMsgs = append(sendMsgs, msg)
		case "receive":
			recvMsgs = append(recvMsgs, msg)
		}
	}

	// Verify exactly 2 send messages (original + modified variants).
	if len(sendMsgs) != 2 {
		t.Fatalf("expected 2 send messages (original + modified), got %d", len(sendMsgs))
	}
	if len(recvMsgs) == 0 {
		t.Fatal("expected at least one receive message")
	}

	// Verify variant metadata on send messages.
	orig := sendMsgs[0]
	mod := sendMsgs[1]

	if got := orig.Metadata["variant"]; got != "original" {
		t.Errorf("first send message variant = %q, want %q", got, "original")
	}
	if got := mod.Metadata["variant"]; got != "modified" {
		t.Errorf("second send message variant = %q, want %q", got, "modified")
	}

	// Verify RawBytes: original should have the original raw bytes,
	// modified should have the modified raw bytes.
	if !bytes.Equal(orig.RawBytes, []byte(originalRaw)) {
		t.Errorf("original send RawBytes = %q, want %q", orig.RawBytes, originalRaw)
	}
	if !bytes.Equal(mod.RawBytes, []byte(modifiedRaw)) {
		t.Errorf("modified send RawBytes = %q, want %q", mod.RawBytes, modifiedRaw)
	}
}
