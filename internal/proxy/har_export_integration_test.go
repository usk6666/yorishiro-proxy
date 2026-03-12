//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ============================================================================
// HAR export integration tests
// ============================================================================

func TestHARExport_BasicHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, `{"result":"ok"}`)
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/api/data?key=val", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to persist.
	pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)

	// Export as HAR.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	// Parse and validate HAR structure.
	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR JSON: %v", err)
	}

	if har.Log == nil {
		t.Fatal("har.log is nil")
	}
	if har.Log.Version != "1.2" {
		t.Errorf("har.log.version = %q, want %q", har.Log.Version, "1.2")
	}
	if har.Log.Creator == nil || har.Log.Creator.Name != "yorishiro-proxy" {
		t.Error("har.log.creator.name is not 'yorishiro-proxy'")
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries count = %d, want 1", len(har.Log.Entries))
	}

	entry := har.Log.Entries[0]

	// Validate request.
	if entry.Request == nil {
		t.Fatal("entry.request is nil")
	}
	if entry.Request.Method != "GET" {
		t.Errorf("request.method = %q, want %q", entry.Request.Method, "GET")
	}
	if !strings.Contains(entry.Request.URL, "/api/data") {
		t.Errorf("request.url = %q, does not contain /api/data", entry.Request.URL)
	}
	if entry.Request.HTTPVersion != "HTTP/1.1" {
		t.Errorf("request.httpVersion = %q, want %q", entry.Request.HTTPVersion, "HTTP/1.1")
	}

	// Validate query string.
	foundKey := false
	for _, qs := range entry.Request.QueryString {
		if qs.Name == "key" && qs.Value == "val" {
			foundKey = true
		}
	}
	if !foundKey {
		t.Error("query string parameter key=val not found")
	}

	// Validate response.
	if entry.Response == nil {
		t.Fatal("entry.response is nil")
	}
	if entry.Response.Status != 200 {
		t.Errorf("response.status = %d, want 200", entry.Response.Status)
	}
	if entry.Response.Content == nil {
		t.Fatal("response.content is nil")
	}
	if entry.Response.Content.MimeType == "" {
		t.Error("response.content.mimeType is empty")
	}
	if entry.Response.Content.Text != `{"result":"ok"}` {
		t.Errorf("response.content.text = %q, want %q", entry.Response.Content.Text, `{"result":"ok"}`)
	}

	// Validate startedDateTime is RFC3339.
	if entry.StartedDateTime == "" {
		t.Error("startedDateTime is empty")
	}

	// Validate timings exist.
	if entry.Timings == nil {
		t.Fatal("entry.timings is nil")
	}
}

func TestHARExport_FilterByProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create flows of different protocols directly in the store.
	httpsFlow := &flow.Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, httpsFlow); err != nil {
		t.Fatalf("SaveFlow HTTPS: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpsFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("https://example.com/https"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpsFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Body: []byte("https-body"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	httpFlow := &flow.Flow{
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, httpFlow); err != nil {
		t.Fatalf("SaveFlow HTTP: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST",
		URL: mustParseURL("http://example.com/http"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 201,
		Body: []byte("http-body"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Export only HTTPS flows.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		Filter:        flow.ExportFilter{Protocol: "HTTPS"},
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Errorf("exported = %d, want 1 (only HTTPS)", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(har.Log.Entries))
	}
	if har.Log.Entries[0].Request.Method != "GET" {
		t.Errorf("filtered entry method = %q, want GET", har.Log.Entries[0].Request.Method)
	}
}

func TestHARExport_BinaryBodyBase64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create a flow with binary response body.
	binaryBody := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a} // PNG header
	fl := &flow.Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("https://example.com/image.png"),
	}); err != nil {
		t.Fatalf("AppendMessage send: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Headers: map[string][]string{"Content-Type": {"image/png"}},
		Body:    binaryBody,
	}); err != nil {
		t.Fatalf("AppendMessage recv: %v", err)
	}

	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Response.Content.Encoding != "base64" {
		t.Errorf("content.encoding = %q, want %q", entry.Response.Content.Encoding, "base64")
	}
	if entry.Response.Content.Text == "" {
		t.Error("content.text is empty for binary body")
	}
	if entry.Response.Content.MimeType != "image/png" {
		t.Errorf("content.mimeType = %q, want %q", entry.Response.Content.MimeType, "image/png")
	}
}

func TestHARExport_WebSocketMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create a WebSocket flow with upgrade request/response and data messages.
	wsFlow := &flow.Flow{
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  500 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, wsFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Upgrade request.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL:     mustParseURL("wss://example.com/ws"),
		Headers: map[string][]string{"Upgrade": {"websocket"}},
	}); err != nil {
		t.Fatalf("AppendMessage upgrade req: %v", err)
	}

	// Upgrade response.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
		Headers: map[string][]string{"Upgrade": {"websocket"}},
	}); err != nil {
		t.Fatalf("AppendMessage upgrade resp: %v", err)
	}

	// Data messages.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
		Metadata:  map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage ws send: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 3, Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      []byte("world"),
		Metadata:  map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage ws recv: %v", err)
	}

	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]

	// Verify _webSocketMessages custom field.
	if len(entry.WebSocketMessages) == 0 {
		t.Fatal("_webSocketMessages is empty")
	}
	if len(entry.WebSocketMessages) != 2 {
		t.Fatalf("_webSocketMessages count = %d, want 2", len(entry.WebSocketMessages))
	}

	// Verify send message.
	sendMsg := entry.WebSocketMessages[0]
	if sendMsg.Type != "send" {
		t.Errorf("ws msg[0].type = %q, want %q", sendMsg.Type, "send")
	}
	if sendMsg.Data != "hello" {
		t.Errorf("ws msg[0].data = %q, want %q", sendMsg.Data, "hello")
	}
	if sendMsg.Opcode != 1 {
		t.Errorf("ws msg[0].opcode = %d, want 1", sendMsg.Opcode)
	}

	// Verify receive message.
	recvMsg := entry.WebSocketMessages[1]
	if recvMsg.Type != "receive" {
		t.Errorf("ws msg[1].type = %q, want %q", recvMsg.Type, "receive")
	}
	if recvMsg.Data != "world" {
		t.Errorf("ws msg[1].data = %q, want %q", recvMsg.Data, "world")
	}
}
