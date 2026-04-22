package http1

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// testConn creates a pair of connected net.Conn for testing.
func testConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	return client, server
}

// --- Layer tests ---

func TestLayer_Channels_YieldsOneChannel(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send)
	defer l.Close()

	count := 0
	for range l.Channels() {
		count++
	}
	if count != 1 {
		t.Fatalf("expected 1 channel, got %d", count)
	}
}

func TestLayer_DetachStream_ReturnsError(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send)
	defer l.Close()

	_, _, _, err := l.DetachStream()
	if err == nil {
		t.Fatal("expected error from DetachStream")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Channel.Next() tests ---

func TestChannel_NextRequest(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send, WithScheme("https"))
	defer l.Close()

	// Write a request from the client side.
	req := "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("expected *HTTPMessage, got %T", env.Message)
	}

	// Verify request fields.
	if msg.Method != "GET" {
		t.Errorf("Method = %q, want GET", msg.Method)
	}
	if msg.Path != "/path" {
		t.Errorf("Path = %q, want /path", msg.Path)
	}
	if msg.RawQuery != "q=1" {
		t.Errorf("RawQuery = %q, want q=1", msg.RawQuery)
	}
	if msg.Authority != "example.com" {
		t.Errorf("Authority = %q, want example.com", msg.Authority)
	}
	if msg.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", msg.Scheme)
	}
	if string(msg.Body) != "hello" {
		t.Errorf("Body = %q, want hello", string(msg.Body))
	}

	// Verify envelope fields.
	if env.Protocol != envelope.ProtocolHTTP {
		t.Errorf("Protocol = %q, want http", env.Protocol)
	}
	if env.Direction != envelope.Send {
		t.Errorf("Direction = %v, want Send", env.Direction)
	}
	if env.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", env.Sequence)
	}
	if env.StreamID == "" {
		t.Error("StreamID is empty")
	}
	if env.FlowID == "" {
		t.Error("FlowID is empty")
	}
	if len(env.Raw) == 0 {
		t.Error("Raw is empty")
	}

	// Verify Raw contains headers only (not body).
	if bytes.Contains(env.Raw, []byte("hello")) {
		t.Error("Raw should not contain body")
	}
	if !bytes.Contains(env.Raw, []byte("GET /path")) {
		t.Error("Raw should contain request line")
	}

	// Verify Channel.StreamID() is connection-level.
	if ch.StreamID() != "conn-1" {
		t.Errorf("Channel.StreamID() = %q, want conn-1", ch.StreamID())
	}

	// Next call should return EOF (client closed).
	_, err = ch.Next(context.Background())
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestChannel_NextResponse(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	// Write a response from the "upstream" side.
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	go func() {
		client.Write([]byte(resp))
		client.Close()
	}()

	ch := <-l.Channels()

	// Set currentStreamID as Session would (via previous request).
	ch.(*channel).currentStreamID = "stream-req-1"
	ch.(*channel).sequence = 0

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Status != 200 {
		t.Errorf("Status = %d, want 200", msg.Status)
	}
	if msg.StatusReason != "OK" {
		t.Errorf("StatusReason = %q, want OK", msg.StatusReason)
	}
	if string(msg.Body) != "ok" {
		t.Errorf("Body = %q, want ok", string(msg.Body))
	}
	if env.Direction != envelope.Receive {
		t.Errorf("Direction = %v, want Receive", env.Direction)
	}
	if env.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", env.Sequence)
	}
}

func TestChannel_KeepAlive_MultipleRequests(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	// Write two keep-alive requests.
	reqs := "GET /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n" +
		"GET /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	go func() {
		client.Write([]byte(reqs))
		client.Close()
	}()

	ch := <-l.Channels()

	// First request.
	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	msg1 := env1.Message.(*envelope.HTTPMessage)
	if msg1.Path != "/first" {
		t.Errorf("Path = %q, want /first", msg1.Path)
	}

	// Second request.
	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	msg2 := env2.Message.(*envelope.HTTPMessage)
	if msg2.Path != "/second" {
		t.Errorf("Path = %q, want /second", msg2.Path)
	}

	// StreamIDs should differ between requests.
	if env1.StreamID == env2.StreamID {
		t.Error("keep-alive requests should have different StreamIDs")
	}

	// Sequences should both be 0 (reset per pair).
	if env1.Sequence != 0 || env2.Sequence != 0 {
		t.Errorf("Sequences = (%d, %d), want (0, 0)", env1.Sequence, env2.Sequence)
	}
}

func TestChannel_ConnectionClose_ReturnsEOF(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	// Write request with Connection: close.
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
	go func() {
		client.Write([]byte(req))
	}()

	ch := <-l.Channels()

	_, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Next call should return EOF due to Connection: close.
	_, err = ch.Next(context.Background())
	if err != io.EOF {
		t.Fatalf("expected io.EOF after Connection: close, got %v", err)
	}
}

func TestChannel_Anomaly_Detection(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	// Write a request with both Content-Length and Transfer-Encoding (CLTE anomaly).
	req := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if len(msg.Anomalies) == 0 {
		t.Fatal("expected anomalies for CLTE request")
	}

	found := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.AnomalyCLTE {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CLTE anomaly, got %v", msg.Anomalies)
	}
}

// --- Channel.Send() tests ---

func TestChannel_Send_ZeroCopyPath(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	// Build an envelope as if Next() produced it.
	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	body := []byte("hello")

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawBytes,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
			},
			Body: body,
		},
		Opaque: &opaqueHTTP1{
			rawReq: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Proto:      "HTTP/1.1",
				Headers:    parser.RawHeaders{{Name: "Host", Value: "example.com"}},
				RawBytes:   rawBytes,
			},
			origKV: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
			},
			origBody: body,
		},
	}

	// Create a channel that writes to the server side.
	l := New(server, "conn-1", envelope.Receive) // Receive direction → Send() writes requests
	defer l.Close()
	ch := <-l.Channels()

	// Read from the other side in a goroutine.
	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close() // signal EOF to reader

	result := <-resultCh
	expected := string(rawBytes) + string(body)
	if string(result) != expected {
		t.Errorf("got:\n%s\nwant:\n%s", string(result), expected)
	}
}

func TestChannel_Send_HeaderPatchPath(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom:  original-with-ows \r\n\r\n")
	body := []byte("hello")

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawBytes,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Custom", Value: "original-with-ows"},
				{Name: "X-New", Value: "added"},
			},
			Body: body,
		},
		Opaque: &opaqueHTTP1{
			rawReq: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Proto:      "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "X-Custom", Value: "original-with-ows", RawValue: "  original-with-ows "},
				},
				RawBytes: rawBytes,
			},
			origKV: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Custom", Value: "original-with-ows"},
			},
			origBody: body,
		},
	}

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := string(<-resultCh)

	// OWS should be preserved for X-Custom (value unchanged).
	if !strings.Contains(result, "X-Custom:  original-with-ows ") {
		t.Errorf("OWS not preserved: %s", result)
	}
	// New header should be added with standard spacing.
	if !strings.Contains(result, "X-New: added") {
		t.Errorf("new header not added: %s", result)
	}
	// Body should follow headers.
	if !strings.HasSuffix(result, "\r\n\r\nhello") {
		t.Errorf("body not at end: %s", result)
	}
}

func TestChannel_Send_SyntheticPath(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	// Envelope without Opaque — synthetic fallback.
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Path:      "/api/test",
			RawQuery:  "v=1",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
			},
			Body: []byte(`{"key":"value"}`),
		},
	}

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := string(<-resultCh)

	// Should have a valid request line.
	if !strings.HasPrefix(result, "POST /api/test?v=1 HTTP/1.1\r\n") {
		t.Errorf("unexpected request line: %s", result)
	}
	// Should have Content-Length auto-set.
	if !strings.Contains(result, "Content-Length: 15") {
		t.Errorf("Content-Length not auto-set: %s", result)
	}
	// Body should be present.
	if !strings.Contains(result, `{"key":"value"}`) {
		t.Errorf("body missing: %s", result)
	}
}

func TestChannel_Send_SyntheticResponse(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       404,
			StatusReason: "Not Found",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/plain"},
			},
			Body: []byte("not found"),
		},
	}

	l := New(server, "conn-1", envelope.Send) // Send direction → Send() writes responses
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := string(<-resultCh)

	if !strings.HasPrefix(result, "HTTP/1.1 404 Not Found\r\n") {
		t.Errorf("unexpected status line: %s", result)
	}
	if !strings.Contains(result, "Content-Length: 9") {
		t.Errorf("Content-Length not auto-set: %s", result)
	}
	if !strings.HasSuffix(result, "not found") {
		t.Errorf("body missing: %s", result)
	}
}

// --- applyHeaderPatch tests ---

func TestApplyHeaderPatch_Unchanged(t *testing.T) {
	origKV := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "Accept", Value: "*/*"},
	}
	raw := parser.RawHeaders{
		{Name: "Host", Value: "example.com", RawValue: " example.com"},
		{Name: "Accept", Value: "*/*", RawValue: "  */*  "},
	}

	result := applyHeaderPatch(origKV, origKV, raw)

	if len(result) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result))
	}
	// RawValue should be preserved (OWS preserved).
	if result[0].RawValue != " example.com" {
		t.Errorf("Host RawValue = %q, want \" example.com\"", result[0].RawValue)
	}
	if result[1].RawValue != "  */*  " {
		t.Errorf("Accept RawValue = %q, want \"  */*  \"", result[1].RawValue)
	}
}

func TestApplyHeaderPatch_ValueChanged(t *testing.T) {
	origKV := []envelope.KeyValue{
		{Name: "Host", Value: "old.com"},
	}
	newKV := []envelope.KeyValue{
		{Name: "Host", Value: "new.com"},
	}
	raw := parser.RawHeaders{
		{Name: "Host", Value: "old.com", RawValue: "  old.com  "},
	}

	result := applyHeaderPatch(origKV, newKV, raw)

	if result[0].Value != "new.com" {
		t.Errorf("Value = %q, want new.com", result[0].Value)
	}
	// RawValue should be cleared when value changes.
	if result[0].RawValue != "" {
		t.Errorf("RawValue = %q, want empty", result[0].RawValue)
	}
}

func TestApplyHeaderPatch_HeaderAdded(t *testing.T) {
	origKV := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
	}
	newKV := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "X-New", Value: "added"},
	}
	raw := parser.RawHeaders{
		{Name: "Host", Value: "example.com"},
	}

	result := applyHeaderPatch(origKV, newKV, raw)

	if len(result) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result))
	}
	if result[1].Name != "X-New" || result[1].Value != "added" {
		t.Errorf("added header = %+v", result[1])
	}
}

func TestApplyHeaderPatch_HeaderRemoved(t *testing.T) {
	origKV := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "X-Remove", Value: "bye"},
	}
	newKV := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
	}
	raw := parser.RawHeaders{
		{Name: "Host", Value: "example.com"},
		{Name: "X-Remove", Value: "bye"},
	}

	result := applyHeaderPatch(origKV, newKV, raw)

	if len(result) != 1 {
		t.Fatalf("expected 1 header, got %d", len(result))
	}
	if result[0].Name != "Host" {
		t.Errorf("remaining header = %s", result[0].Name)
	}
}

// --- Helper function tests ---

func TestReadBodyWithThreshold_SmallBody(t *testing.T) {
	r := strings.NewReader("hello world")
	bb, body, err := readBodyWithThreshold(r, "", 1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bb != nil {
		t.Error("expected nil BodyBuffer for small body")
	}
	if string(body) != "hello world" {
		t.Errorf("body = %q, want hello world", string(body))
	}
}

func TestReadBodyWithThreshold_NilReader(t *testing.T) {
	bb, body, err := readBodyWithThreshold(nil, "", 1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		t.Errorf("expected nil body, got %v", body)
	}
	if bb != nil {
		t.Error("expected nil BodyBuffer")
	}
}

func TestReadBodyWithThreshold_EmptyBody(t *testing.T) {
	r := strings.NewReader("")
	bb, body, err := readBodyWithThreshold(r, "", 1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bb != nil {
		t.Error("expected nil BodyBuffer for empty body")
	}
	if len(body) != 0 {
		t.Errorf("body = %v, want empty", body)
	}
}

// TestReadBodyWithThreshold_LargeBodyReturnsBuffer verifies that a body
// exceeding the spill threshold is returned as a file-backed BodyBuffer
// with msg.Body == nil.
func TestReadBodyWithThreshold_LargeBodyReturnsBuffer(t *testing.T) {
	const threshold = 64
	payload := bytes.Repeat([]byte("A"), threshold+1024)
	r := bytes.NewReader(payload)

	bb, body, err := readBodyWithThreshold(r, "", threshold, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bb == nil {
		t.Fatal("expected non-nil BodyBuffer for large body")
	}
	defer func() { _ = bb.Release() }()
	if body != nil {
		t.Errorf("expected nil body (buffer-backed), got %d bytes", len(body))
	}
	if got := bb.Len(); got != int64(len(payload)) {
		t.Errorf("BodyBuffer.Len() = %d, want %d", got, len(payload))
	}
	if !bb.IsFileBacked() {
		t.Error("expected file-backed BodyBuffer after overflow")
	}
}

// TestReadBodyWithThreshold_MaxBodyExceeded verifies that a body exceeding
// maxBody surfaces as *layer.StreamError with ErrorInternalError.
func TestReadBodyWithThreshold_MaxBodyExceeded(t *testing.T) {
	const threshold = 64
	const maxBody = 128
	payload := bytes.Repeat([]byte("A"), maxBody+1024)
	r := bytes.NewReader(payload)

	bb, body, err := readBodyWithThreshold(r, "", threshold, maxBody)
	if err == nil {
		t.Fatal("expected error for oversize body")
	}
	if bb != nil {
		t.Error("expected nil BodyBuffer on error path")
	}
	if body != nil {
		t.Error("expected nil body on error path")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("expected *layer.StreamError, got %T: %v", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
}

func TestExtractStatusReason(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"200 OK", "OK"},
		{"404 Not Found", "Not Found"},
		{"500", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractStatusReason(tt.status)
		if got != tt.want {
			t.Errorf("extractStatusReason(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestParseRequestURI(t *testing.T) {
	tests := []struct {
		uri       string
		host      string
		wantPath  string
		wantQuery string
		wantAuth  string
	}{
		{"/path?q=1", "example.com", "/path", "q=1", "example.com"},
		{"/", "example.com", "/", "", "example.com"},
		{"*", "example.com", "*", "", "example.com"},
		{"http://example.com/abs?k=v", "", "/abs", "k=v", "example.com"},
	}
	for _, tt := range tests {
		headers := parser.RawHeaders{}
		if tt.host != "" {
			headers = parser.RawHeaders{{Name: "Host", Value: tt.host}}
		}
		path, query, auth := parseRequestURI(tt.uri, headers)
		if path != tt.wantPath || query != tt.wantQuery || auth != tt.wantAuth {
			t.Errorf("parseRequestURI(%q, host=%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.uri, tt.host, path, query, auth, tt.wantPath, tt.wantQuery, tt.wantAuth)
		}
	}
}

func TestConvertAnomalies(t *testing.T) {
	parserAnomalies := []parser.Anomaly{
		{Type: parser.AnomalyCLTE, Detail: "both CL and TE present"},
	}
	result := convertAnomalies(parserAnomalies)
	if len(result) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(result))
	}
	if result[0].Type != envelope.AnomalyCLTE {
		t.Errorf("Type = %q, want CLTE", result[0].Type)
	}
	if result[0].Detail != "both CL and TE present" {
		t.Errorf("Detail = %q", result[0].Detail)
	}
}

func TestConvertAnomalies_Nil(t *testing.T) {
	result := convertAnomalies(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestKvEqual(t *testing.T) {
	a := []envelope.KeyValue{{Name: "Host", Value: "a.com"}}
	b := []envelope.KeyValue{{Name: "Host", Value: "a.com"}}
	if !kvEqual(a, b) {
		t.Error("expected equal")
	}

	c := []envelope.KeyValue{{Name: "Host", Value: "b.com"}}
	if kvEqual(a, c) {
		t.Error("expected not equal")
	}
}

func TestIsBodyChanged(t *testing.T) {
	// Shared BodyBuffer for buffer-backed cases. Retained so the test can
	// observe both "unchanged buffer-backed" and "buffer cleared" semantics
	// without disturbing the buffer state. Released at test end.
	origBB := bodybuf.NewMemory([]byte("buffered-body"))
	defer func() { _ = origBB.Release() }()

	tests := []struct {
		name     string
		msg      *envelope.HTTPMessage
		opaque   *opaqueHTTP1
		expected bool
	}{
		{
			name:     "both nil (no body)",
			msg:      &envelope.HTTPMessage{},
			opaque:   &opaqueHTTP1{},
			expected: false,
		},
		{
			name:     "memory body unchanged",
			msg:      &envelope.HTTPMessage{Body: []byte("same")},
			opaque:   &opaqueHTTP1{origBody: []byte("same")},
			expected: false,
		},
		{
			name:     "memory body changed",
			msg:      &envelope.HTTPMessage{Body: []byte("new")},
			opaque:   &opaqueHTTP1{origBody: []byte("old")},
			expected: true,
		},
		{
			name:     "body set where there was none",
			msg:      &envelope.HTTPMessage{Body: []byte("new")},
			opaque:   &opaqueHTTP1{origBody: nil},
			expected: true,
		},
		{
			name:     "body cleared",
			msg:      &envelope.HTTPMessage{Body: nil},
			opaque:   &opaqueHTTP1{origBody: []byte("old")},
			expected: true,
		},
		{
			name:     "buffer-backed unchanged (same pointer)",
			msg:      &envelope.HTTPMessage{BodyBuffer: origBB},
			opaque:   &opaqueHTTP1{origBodyBuffer: origBB},
			expected: false,
		},
		{
			name:     "buffer replaced by different pointer",
			msg:      &envelope.HTTPMessage{BodyBuffer: bodybuf.NewMemory([]byte("other"))},
			opaque:   &opaqueHTTP1{origBodyBuffer: origBB},
			expected: true,
		},
		{
			name:     "buffer dropped to nil (body cleared)",
			msg:      &envelope.HTTPMessage{},
			opaque:   &opaqueHTTP1{origBodyBuffer: origBB},
			expected: true,
		},
		{
			name:     "buffer materialized into Body",
			msg:      &envelope.HTTPMessage{Body: []byte("materialized"), BodyBuffer: origBB},
			opaque:   &opaqueHTTP1{origBodyBuffer: origBB},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBodyChanged(tt.msg, tt.opaque)
			if got != tt.expected {
				t.Errorf("isBodyChanged() = %v, want %v", got, tt.expected)
			}
			// Clean up per-case temporaries (the "other" buffer).
			if tt.msg.BodyBuffer != nil && tt.msg.BodyBuffer != origBB {
				_ = tt.msg.BodyBuffer.Release()
			}
		})
	}
}

// --- Serialize tests ---

func TestSerializeRequestHeader(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/test",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "X-OWS", Value: "trimmed", RawValue: "  trimmed  "},
		},
	}
	result := string(serializeRequestHeader(req))
	expected := "GET /test HTTP/1.1\r\nHost: example.com\r\nX-OWS:  trimmed  \r\n\r\n"
	if result != expected {
		t.Errorf("got:\n%q\nwant:\n%q", result, expected)
	}
}

func TestSerializeResponseHeader(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Headers: parser.RawHeaders{
			{Name: "Content-Length", Value: "0"},
		},
	}
	result := string(serializeResponseHeader(resp))
	expected := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	if result != expected {
		t.Errorf("got:\n%q\nwant:\n%q", result, expected)
	}
}

func TestStatusText(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "OK"},
		{404, "Not Found"},
		{500, "Internal Server Error"},
		{999, ""},
	}
	for _, tt := range tests {
		got := statusText(tt.code)
		if got != tt.want {
			t.Errorf("statusText(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// --- BodyBuffer Send tests (USK-631) ---

// TestChannel_Send_BodyBufferUnchanged_ZeroCopy verifies that an envelope
// whose BodyBuffer was populated at Next time and never mutated takes the
// zero-copy RawBytes fast path — the buffer content is NOT re-materialized
// through writeBody because RawBytes already includes it.
func TestChannel_Send_BodyBufferUnchanged_ZeroCopy(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	// Construct an envelope where Body is nil but BodyBuffer holds the
	// content. RawBytes is the headers-only block (matching parser output);
	// writeBody streams the BodyBuffer contents separately.
	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n")
	bb := bodybuf.NewMemory([]byte("hello"))

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawBytes,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "5"},
			},
			BodyBuffer: bb,
		},
		Opaque: &opaqueHTTP1{
			rawReq: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Proto:      "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Length", Value: "5"},
				},
				RawBytes: rawBytes,
			},
			origKV: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "5"},
			},
			origBody:       nil,
			origBodyBuffer: bb,
		},
	}

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := <-resultCh
	// Zero-copy writes RawBytes (headers-only) + BodyBuffer contents.
	expected := string(rawBytes) + "hello"
	if string(result) != expected {
		t.Errorf("zero-copy output mismatch:\ngot:  %q\nwant: %q", result, expected)
	}

	// Release the retained BodyBuffer so the test doesn't leak.
	_ = bb.Release()
}

// TestChannel_Send_BodyChangedToBytes verifies that when Pipeline replaces
// a buffer-backed body with msg.Body bytes, the encoded output re-stamps
// Content-Length from len(msg.Body) and writes the new body.
func TestChannel_Send_BodyChangedToBytes(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello")
	origBB := bodybuf.NewMemory([]byte("hello"))

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawBytes,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "5"},
			},
			// Pipeline dropped the buffer and set a new memory body.
			Body: []byte("world-replaced"),
		},
		Opaque: &opaqueHTTP1{
			rawReq: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Proto:      "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Length", Value: "5"},
				},
				RawBytes: rawBytes,
			},
			origKV: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "5"},
			},
			origBodyBuffer: origBB,
		},
	}

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := string(<-resultCh)

	// Content-Length must be re-stamped.
	if !strings.Contains(result, "Content-Length: 14\r\n") {
		t.Errorf("Content-Length not re-stamped to 14: %s", result)
	}
	// New body must be at the end.
	if !strings.HasSuffix(result, "\r\n\r\nworld-replaced") {
		t.Errorf("new body not appended: %s", result)
	}

	_ = origBB.Release()
}

// TestChannel_Send_BodyNilBothNoBodyBytes verifies that an envelope with
// neither msg.Body nor msg.BodyBuffer writes no body bytes after the header
// block.
func TestChannel_Send_BodyNilBothNoBodyBytes(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawBytes,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
			},
		},
		Opaque: &opaqueHTTP1{
			rawReq: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Proto:      "HTTP/1.1",
				Headers:    parser.RawHeaders{{Name: "Host", Value: "example.com"}},
				RawBytes:   rawBytes,
			},
			origKV: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
			},
		},
	}

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(client)
		resultCh <- data
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	server.Close()

	result := <-resultCh
	if string(result) != string(rawBytes) {
		t.Errorf("unexpected output:\ngot:  %q\nwant: %q", result, rawBytes)
	}
}

// --- Round-trip test (Next → Send zero-copy) ---

func TestChannel_RoundTrip_ZeroCopy(t *testing.T) {
	// Client → Server: parse request → send request to upstream (zero-copy).
	clientConn, serverConn := testConn(t)
	defer clientConn.Close()
	defer serverConn.Close()

	upstreamClient, upstreamServer := testConn(t)
	defer upstreamClient.Close()
	defer upstreamServer.Close()

	// Client-side layer (parses requests).
	clientLayer := New(serverConn, "conn-1", envelope.Send, WithScheme("https"))
	defer clientLayer.Close()
	clientCh := <-clientLayer.Channels()

	// Upstream-side layer (sends requests).
	upstreamLayer := New(upstreamServer, "conn-2", envelope.Receive, WithScheme("https"))
	defer upstreamLayer.Close()
	upstreamCh := <-upstreamLayer.Channels()

	// Original wire bytes.
	wireReq := "GET /path HTTP/1.1\r\nHost: example.com\r\nX-Custom:  spaced  \r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc"

	// Send request from client.
	go func() {
		clientConn.Write([]byte(wireReq))
		clientConn.Close()
	}()

	// Read from upstream side.
	resultCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(upstreamClient)
		resultCh <- data
	}()

	// Parse request.
	env, err := clientCh.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Forward without modification (zero-copy path).
	if err := upstreamCh.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	upstreamServer.Close()

	result := string(<-resultCh)

	// Wire bytes should be byte-for-byte identical.
	if result != wireReq {
		t.Errorf("round-trip mismatch:\ngot:\n%q\nwant:\n%q", result, wireReq)
	}
}
