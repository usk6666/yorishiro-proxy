package parser

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func newReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

func TestParseRequest_BasicGET(t *testing.T) {
	raw := "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.RequestURI != "/path?q=1" {
		t.Errorf("RequestURI = %q, want /path?q=1", req.RequestURI)
	}
	if req.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want HTTP/1.1", req.Proto)
	}
	if req.Headers.Get("Host") != "example.com" {
		t.Errorf("Host = %q, want example.com", req.Headers.Get("Host"))
	}
	if req.Headers.Get("Accept") != "*/*" {
		t.Errorf("Accept = %q, want */*", req.Headers.Get("Accept"))
	}
	if req.Close {
		t.Error("Close should be false for HTTP/1.1 without Connection: close")
	}
	if len(req.RawBytes) == 0 {
		t.Error("RawBytes should not be empty")
	}
	if string(req.RawBytes) != raw {
		t.Errorf("RawBytes = %q, want %q", string(req.RawBytes), raw)
	}
}

func TestParseRequest_POST_WithBody(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(Body) error: %v", err)
	}
	if string(body) != "hello world" {
		t.Errorf("Body = %q, want %q", string(body), "hello world")
	}
}

func TestParseRequest_HeaderOrderPreserved(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nZ-First: 1\r\nA-Second: 2\r\nM-Third: 3\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if len(req.Headers) != 3 {
		t.Fatalf("header count = %d, want 3", len(req.Headers))
	}
	if req.Headers[0].Name != "Z-First" {
		t.Errorf("headers[0].Name = %q, want Z-First", req.Headers[0].Name)
	}
	if req.Headers[1].Name != "A-Second" {
		t.Errorf("headers[1].Name = %q, want A-Second", req.Headers[1].Name)
	}
	if req.Headers[2].Name != "M-Third" {
		t.Errorf("headers[2].Name = %q, want M-Third", req.Headers[2].Name)
	}
}

func TestParseRequest_HeaderCasePreserved(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nX-CUSTOM-HEADER: value\r\nx-lowercase: val2\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Headers[0].Name != "X-CUSTOM-HEADER" {
		t.Errorf("name = %q, want X-CUSTOM-HEADER", req.Headers[0].Name)
	}
	if req.Headers[1].Name != "x-lowercase" {
		t.Errorf("name = %q, want x-lowercase", req.Headers[1].Name)
	}
}

func TestParseRequest_ConnectionClose(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantClose bool
	}{
		{
			name:      "HTTP/1.1 explicit close",
			raw:       "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
			wantClose: true,
		},
		{
			name:      "HTTP/1.1 default keep-alive",
			raw:       "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			wantClose: false,
		},
		{
			name:      "HTTP/1.0 default close",
			raw:       "GET / HTTP/1.0\r\nHost: x\r\n\r\n",
			wantClose: true,
		},
		{
			name:      "HTTP/1.0 keep-alive",
			raw:       "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
			wantClose: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest(newReader(tt.raw))
			if err != nil {
				t.Fatalf("ParseRequest() error: %v", err)
			}
			if req.Close != tt.wantClose {
				t.Errorf("Close = %v, want %v", req.Close, tt.wantClose)
			}
		})
	}
}

func TestParseRequest_ObsFold(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nX-Long: first\r\n second\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Headers.Get("X-Long") != "first second" {
		t.Errorf("header value = %q, want %q", req.Headers.Get("X-Long"), "first second")
	}
	hasObsFold := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyObsFold {
			hasObsFold = true
		}
	}
	if !hasObsFold {
		t.Error("expected ObsFold anomaly")
	}
}

func TestParseRequest_EmptyBody(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body len = %d, want 0", len(body))
	}
}

func TestParseRequest_MalformedRequestLine(t *testing.T) {
	// Only method, no URI or proto.
	raw := "FOOBAR\r\nHost: x\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Method != "FOOBAR" {
		t.Errorf("Method = %q, want FOOBAR", req.Method)
	}
}

func TestParseRequest_EOF(t *testing.T) {
	_, err := ParseRequest(newReader(""))
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseResponse_Basic(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want HTTP/1.1", resp.Proto)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Status != "200 OK" {
		t.Errorf("Status = %q, want %q", resp.Status, "200 OK")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", string(body))
	}
}

func TestParseResponse_NoBody(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "204 No Content",
			raw:  "HTTP/1.1 204 No Content\r\n\r\n",
		},
		{
			name: "304 Not Modified",
			raw:  "HTTP/1.1 304 Not Modified\r\n\r\n",
		},
		{
			name: "100 Continue",
			raw:  "HTTP/1.1 100 Continue\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(newReader(tt.raw))
			if err != nil {
				t.Fatalf("ParseResponse() error: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			if len(body) != 0 {
				t.Errorf("body len = %d, want 0", len(body))
			}
		})
	}
}

func TestParseResponse_HTTP10_EOFBody(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\neof body data"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(body) != "eof body data" {
		t.Errorf("body = %q, want %q", string(body), "eof body data")
	}
}

func TestParseResponse_ConnectionClose_EOFBody(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\neof body"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(body) != "eof body" {
		t.Errorf("body = %q, want %q", string(body), "eof body")
	}
}

func TestParseResponse_RawBytesCapture(t *testing.T) {
	headerPart := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"
	raw := headerPart + "abc"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	// RawBytes should contain only the header section.
	if string(resp.RawBytes) != headerPart {
		t.Errorf("RawBytes = %q, want %q", string(resp.RawBytes), headerPart)
	}
}

// --- Smuggling / Anomaly tests ---

func TestParseRequest_Smuggling_CLTE(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	hasCLTE := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyCLTE {
			hasCLTE = true
		}
	}
	if !hasCLTE {
		t.Error("expected CLTE anomaly when both CL and TE present")
	}
}

func TestParseRequest_Smuggling_DuplicateCL(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	hasDupCL := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyDuplicateCL {
			hasDupCL = true
		}
	}
	if !hasDupCL {
		t.Error("expected DuplicateCL anomaly")
	}
}

func TestParseRequest_Smuggling_InvalidTE(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	hasInvalid := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyInvalidTE {
			hasInvalid = true
		}
	}
	if !hasInvalid {
		t.Error("expected InvalidTE anomaly for non-standard TE value")
	}
}

func TestParseRequest_Smuggling_AmbiguousTE(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	hasAmbiguous := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyAmbiguousTE {
			hasAmbiguous = true
		}
	}
	if !hasAmbiguous {
		t.Error("expected AmbiguousTE anomaly for multiple TE headers")
	}
}

func TestParseRequest_Smuggling_TETE(t *testing.T) {
	// TE.TE: Two Transfer-Encoding headers where one is obfuscated.
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	var anomalyTypes []AnomalyType
	for _, a := range req.Anomalies {
		anomalyTypes = append(anomalyTypes, a.Type)
	}
	// Should detect both InvalidTE (for "cow") and AmbiguousTE (multiple TE).
	hasInvalid := false
	hasAmbiguous := false
	for _, at := range anomalyTypes {
		if at == AnomalyInvalidTE {
			hasInvalid = true
		}
		if at == AnomalyAmbiguousTE {
			hasAmbiguous = true
		}
	}
	if !hasInvalid {
		t.Error("expected InvalidTE anomaly for 'cow'")
	}
	if !hasAmbiguous {
		t.Error("expected AmbiguousTE anomaly for multiple TE headers")
	}
}

func TestParseRequest_HeaderInjection(t *testing.T) {
	// Space before colon in header name.
	raw := "GET / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	hasInjection := false
	for _, a := range req.Anomalies {
		if a.Type == AnomalyHeaderInjection {
			hasInjection = true
		}
	}
	if !hasInjection {
		t.Error("expected HeaderInjection anomaly for space before colon")
	}
}

// --- HTTP/1.0 compatibility ---

func TestParseRequest_HTTP10_NoChunked(t *testing.T) {
	// HTTP/1.0 should not use chunked TE — body should be empty (no CL).
	raw := "POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	// For HTTP/1.0, chunked TE is ignored; body should be empty (no CL).
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("HTTP/1.0 with chunked TE should have empty body, got %d bytes", len(body))
	}
}

func TestParseRequest_HTTP10_DefaultClose(t *testing.T) {
	raw := "GET / HTTP/1.0\r\nHost: x\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if !req.Close {
		t.Error("HTTP/1.0 should default to close")
	}
}

func TestParseRequest_HTTP10_NoHostRequired(t *testing.T) {
	// HTTP/1.0 without Host header should still parse.
	raw := "GET / HTTP/1.0\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Headers.Get("Host") != "" {
		t.Errorf("unexpected Host header: %q", req.Headers.Get("Host"))
	}
}

// --- Chunked body ---

func TestParseRequest_ChunkedBody(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	// Body should contain the raw chunked encoding (NOT decoded).
	want := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	if string(body) != want {
		t.Errorf("body = %q, want %q", string(body), want)
	}
}

func TestParseRequest_ChunkedBody_WithTrailers(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nTrailer-Key: val\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	want := "5\r\nhello\r\n0\r\nTrailer-Key: val\r\n\r\n"
	if string(body) != want {
		t.Errorf("body = %q, want %q", string(body), want)
	}
}

// --- Response chunked ---

func TestParseResponse_ChunkedBody(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	want := "4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n"
	if string(body) != want {
		t.Errorf("body = %q, want %q", string(body), want)
	}
}

// --- Multiple requests on same connection ---

func TestParseRequest_Pipeline(t *testing.T) {
	raw := "GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\nHost: y\r\n\r\n"
	r := newReader(raw)

	req1, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest() #1 error: %v", err)
	}
	if req1.RequestURI != "/first" {
		t.Errorf("req1.RequestURI = %q, want /first", req1.RequestURI)
	}

	req2, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest() #2 error: %v", err)
	}
	if req2.RequestURI != "/second" {
		t.Errorf("req2.RequestURI = %q, want /second", req2.RequestURI)
	}
}

func TestParseRequest_Pipeline_WithBody(t *testing.T) {
	raw := "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nHost: y\r\n\r\n"
	r := newReader(raw)

	req1, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest() #1 error: %v", err)
	}
	body1, err := io.ReadAll(req1.Body)
	if err != nil {
		t.Fatalf("ReadAll() #1 error: %v", err)
	}
	if string(body1) != "abc" {
		t.Errorf("body1 = %q, want abc", string(body1))
	}

	req2, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest() #2 error: %v", err)
	}
	if req2.RequestURI != "/b" {
		t.Errorf("req2.RequestURI = %q, want /b", req2.RequestURI)
	}
}

// --- Resource limits ---

func TestParseRequest_HeaderCountLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i <= maxHeaderCount; i++ {
		b.WriteString("X-H: v\r\n")
	}
	b.WriteString("\r\n")

	_, err := ParseRequest(newReader(b.String()))
	if err == nil {
		t.Error("expected error for exceeding header count limit")
	}
}

// --- Duplicate Content-Length with same values (not an anomaly) ---

func TestParseRequest_DuplicateCL_SameValue(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	for _, a := range req.Anomalies {
		if a.Type == AnomalyDuplicateCL {
			t.Error("should not flag DuplicateCL when values are identical")
		}
	}
}

// --- Absolute URI ---

func TestParseRequest_AbsoluteURI(t *testing.T) {
	raw := "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.RequestURI != "http://example.com/path" {
		t.Errorf("RequestURI = %q, want http://example.com/path", req.RequestURI)
	}
}

// --- CONNECT method ---

func TestParseRequest_CONNECT(t *testing.T) {
	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", req.Method)
	}
	if req.RequestURI != "example.com:443" {
		t.Errorf("RequestURI = %q, want example.com:443", req.RequestURI)
	}
}

// --- LF-only line endings ---

func TestParseRequest_LFOnly(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: x\n\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
}

// --- Invalid Content-Length ---

func TestParseRequest_InvalidContentLength(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("invalid CL should produce empty body, got %d bytes", len(body))
	}
}

// --- Response with no reason phrase ---

func TestParseResponse_NoReasonPhrase(t *testing.T) {
	raw := "HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok"
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// --- Truncated raw bytes ---

func TestParseRequest_RawBytesTruncation(t *testing.T) {
	// Create a request with headers exceeding maxRawCaptureSize.
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	// Write enough headers to exceed 2MB.
	line := "X-Pad: " + strings.Repeat("A", 1000) + "\r\n"
	for b.Len() < maxRawCaptureSize+1000 {
		b.WriteString(line)
	}
	b.WriteString("\r\n")

	req, err := ParseRequest(newReader(b.String()))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	if !req.Truncated {
		t.Error("expected Truncated=true for oversized headers")
	}
	if len(req.RawBytes) > maxRawCaptureSize {
		t.Errorf("RawBytes len = %d, should not exceed %d", len(req.RawBytes), maxRawCaptureSize)
	}
}
