package http2

import (
	"bytes"
	"context"
	"io"
	gohttp "net/http"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

func TestBuildH2Request_ValidGET(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/api/test"},
		{Name: "accept", Value: "application/json"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("Method = %q, want %q", req.Method, "GET")
	}
	if req.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", req.Scheme, "https")
	}
	if req.Authority != "example.com" {
		t.Errorf("Authority = %q, want %q", req.Authority, "example.com")
	}
	if req.Path != "/api/test" {
		t.Errorf("Path = %q, want %q", req.Path, "/api/test")
	}
	if !req.EndStream {
		t.Error("EndStream = false, want true")
	}
	if len(req.Anomalies) != 0 {
		t.Errorf("Anomalies = %v, want empty", req.Anomalies)
	}
	if len(req.AllHeaders) != 5 {
		t.Errorf("AllHeaders len = %d, want 5", len(req.AllHeaders))
	}
}

func TestBuildH2Request_MissingMethod(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}

	_, err := buildH2Request(headers, nil, true, nil)
	if err == nil {
		t.Fatal("expected error for missing :method")
	}
}

func TestBuildH2Request_MissingPath(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
	}

	_, err := buildH2Request(headers, nil, true, nil)
	if err == nil {
		t.Fatal("expected error for missing :path")
	}
}

func TestBuildH2Request_CONNECTWithoutPath(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "example.com:443"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "CONNECT" {
		t.Errorf("Method = %q, want %q", req.Method, "CONNECT")
	}
}

func TestBuildH2Request_DuplicatePseudoHeader(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First occurrence wins.
	if req.Method != "GET" {
		t.Errorf("Method = %q, want %q (first occurrence)", req.Method, "GET")
	}

	// Anomaly should be detected.
	found := false
	for _, a := range req.Anomalies {
		if a.Type == "duplicate_pseudo_header" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected duplicate_pseudo_header anomaly")
	}
}

func TestBuildH2Request_PseudoAfterRegular(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: "accept", Value: "text/html"},
		{Name: ":path", Value: "/"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, a := range req.Anomalies {
		if a.Type == "pseudo_header_order" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected pseudo_header_order anomaly")
	}
}

func TestBuildH2Request_UnknownPseudoHeader(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: ":foo", Value: "bar"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, a := range req.Anomalies {
		if a.Type == "unknown_pseudo_header" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected unknown_pseudo_header anomaly")
	}
}

func TestBuildH2Request_WithBody(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/api"},
		{Name: ":authority", Value: "example.com"},
	}
	body := io.NopCloser(bytes.NewReader([]byte("hello")))

	req, err := buildH2Request(headers, body, false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.EndStream {
		t.Error("EndStream = true, want false")
	}
	if req.Body == nil {
		t.Error("Body = nil, want non-nil")
	}
	data, _ := io.ReadAll(req.Body)
	if string(data) != "hello" {
		t.Errorf("Body = %q, want %q", data, "hello")
	}
}

func TestBuildH2Request_DefaultScheme(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Scheme != "http" {
		t.Errorf("Scheme = %q, want %q (default)", req.Scheme, "http")
	}
}

func TestH2Request_RegularHeaders(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "accept", Value: "text/html"},
		{Name: "x-custom", Value: "value"},
	}

	req, err := buildH2Request(headers, nil, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	regular := req.RegularHeaders()
	if len(regular) != 2 {
		t.Fatalf("RegularHeaders len = %d, want 2", len(regular))
	}
	if regular[0].Name != "accept" || regular[0].Value != "text/html" {
		t.Errorf("RegularHeaders[0] = %v, want accept:text/html", regular[0])
	}
	if regular[1].Name != "x-custom" || regular[1].Value != "value" {
		t.Errorf("RegularHeaders[1] = %v, want x-custom:value", regular[1])
	}
}

func TestH2RequestToGoHTTP(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/api/test?q=1"},
		{Name: "content-type", Value: "application/json"},
	}
	body := io.NopCloser(bytes.NewReader([]byte("body")))

	h2req, err := buildH2Request(headers, body, false, nil)
	if err != nil {
		t.Fatalf("buildH2Request: %v", err)
	}

	goReq, err := h2RequestToGoHTTP(context.Background(), h2req)
	if err != nil {
		t.Fatalf("h2RequestToGoHTTP: %v", err)
	}

	if goReq.Method != "POST" {
		t.Errorf("Method = %q, want POST", goReq.Method)
	}
	if goReq.URL.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", goReq.URL.Scheme)
	}
	if goReq.URL.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", goReq.URL.Host)
	}
	if goReq.URL.Path != "/api/test" {
		t.Errorf("Path = %q, want /api/test", goReq.URL.Path)
	}
	if goReq.URL.RawQuery != "q=1" {
		t.Errorf("RawQuery = %q, want q=1", goReq.URL.RawQuery)
	}
	if goReq.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", goReq.Host)
	}
	if goReq.Header.Get("content-type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", goReq.Header.Get("content-type"))
	}
}

func TestH2RequestToGoHTTP_NoBody(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	}

	h2req, _ := buildH2Request(headers, nil, true, nil)
	goReq, err := h2RequestToGoHTTP(context.Background(), h2req)
	if err != nil {
		t.Fatalf("h2RequestToGoHTTP: %v", err)
	}

	if goReq.Body == nil {
		t.Fatal("Body should not be nil")
	}
	if goReq.Body != gohttp.NoBody {
		t.Error("Body should be NoBody for GET with EndStream=true")
	}
}

func TestBuildH2HeadersFromGoHTTP(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "https://example.com/test", nil)
	req.Header.Set("Accept", "text/html")
	req.Host = "example.com"

	headers := buildH2HeadersFromGoHTTP(req)

	// Check pseudo-headers come first.
	if len(headers) < 4 {
		t.Fatalf("headers len = %d, want >= 4", len(headers))
	}

	expected := map[string]string{
		":method":    "GET",
		":scheme":    "https",
		":authority": "example.com",
		":path":      "/test",
	}
	for _, hf := range headers[:4] {
		want, ok := expected[hf.Name]
		if !ok {
			continue
		}
		if hf.Value != want {
			t.Errorf("%s = %q, want %q", hf.Name, hf.Value, want)
		}
	}
}

func TestGoHTTPHeaderToHpack(t *testing.T) {
	h := gohttp.Header{
		"Content-Type": []string{"application/json"},
		"X-Custom":     []string{"a", "b"},
	}

	fields := goHTTPHeaderToHpack(h)

	if len(fields) != 3 {
		t.Fatalf("fields len = %d, want 3", len(fields))
	}

	// All names should be lowercase.
	for _, f := range fields {
		lower := strings.ToLower(f.Name)
		if f.Name != lower {
			t.Errorf("name not lowercase: %q", f.Name)
		}
	}
}

func TestH2ResultToGoHTTPResponse(t *testing.T) {
	result := &RoundTripResult{
		StatusCode: 200,
		Headers: []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "text/plain"},
		},
		Body: bytes.NewReader([]byte("response body")),
	}

	resp := h2ResultToGoHTTPResponse(result)

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("content-type") != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", resp.Header.Get("content-type"))
	}
	// :status pseudo-header should be excluded from regular headers.
	if resp.Header.Get(":status") != "" {
		t.Error(":status should not be in response headers")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "response body" {
		t.Errorf("body = %q, want %q", body, "response body")
	}
}

func TestWriteErrorResponse_ViaAdapter(t *testing.T) {
	// Test writeErrorResponse through the goHTTPWriterAdapter to avoid
	// needing a fully initialized clientConn with writer.
	rec := &goHTTPWriterAdapter{ResponseWriter: &recordingResponseWriter{}}
	writeErrorResponse(rec, 502)
	// Verify via the adapter that WriteHeaders was called with the right status.
	inner := rec.ResponseWriter.(*recordingResponseWriter)
	if inner.statusCode != 502 {
		t.Errorf("statusCode = %d, want 502", inner.statusCode)
	}
}

// recordingResponseWriter is a minimal gohttp.ResponseWriter for testing.
type recordingResponseWriter struct {
	statusCode int
	headers    gohttp.Header
}

func (w *recordingResponseWriter) Header() gohttp.Header {
	if w.headers == nil {
		w.headers = make(gohttp.Header)
	}
	return w.headers
}
func (w *recordingResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordingResponseWriter) WriteHeader(code int)        { w.statusCode = code }

func TestAsGoHTTPResponseWriter(t *testing.T) {
	cc := &clientConn{
		h2conn:  NewConn(),
		encoder: hpack.NewEncoder(4096, true),
	}
	rw := &frameResponseWriter{
		cc:       cc,
		streamID: 1,
		headers:  make(gohttp.Header),
	}
	w := asGoHTTPResponseWriter(rw)
	if w == nil {
		t.Fatal("expected non-nil ResponseWriter")
	}
}
