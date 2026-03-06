package plugin

import (
	"bytes"
	gohttp "net/http"
	"testing"
)

func TestHTTPRequestToMap(t *testing.T) {
	req, _ := gohttp.NewRequest("POST", "https://example.com/api?key=val", nil)
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")
	body := []byte(`{"foo":"bar"}`)
	ci := &ConnInfo{ClientAddr: "10.0.0.1:1234", TLSVersion: "TLS 1.3"}

	m := HTTPRequestToMap(req, body, ci, "HTTP/1.x")

	if v := m["method"].(string); v != "POST" {
		t.Errorf("method = %q, want %q", v, "POST")
	}
	if v := m["scheme"].(string); v != "https" {
		t.Errorf("scheme = %q, want %q", v, "https")
	}
	if v := m["host"].(string); v != "example.com" {
		t.Errorf("host = %q, want %q", v, "example.com")
	}
	if v := m["path"].(string); v != "/api" {
		t.Errorf("path = %q, want %q", v, "/api")
	}
	if v := m["query"].(string); v != "key=val" {
		t.Errorf("query = %q, want %q", v, "key=val")
	}
	if v := m["protocol"].(string); v != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", v, "HTTP/1.x")
	}
	if v, ok := m["body"].([]byte); !ok || !bytes.Equal(v, body) {
		t.Errorf("body = %v, want %v", m["body"], body)
	}

	// Check headers include Host.
	headers, ok := m["headers"].(map[string]any)
	if !ok {
		t.Fatal("headers is not map[string]any")
	}
	hostVals, ok := headers["Host"].([]any)
	if !ok || len(hostVals) == 0 || hostVals[0] != "example.com" {
		t.Errorf("headers[Host] = %v, want [example.com]", headers["Host"])
	}

	// Check conn_info.
	connInfo, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info is not map[string]any")
	}
	if v := connInfo["client_addr"].(string); v != "10.0.0.1:1234" {
		t.Errorf("conn_info.client_addr = %q, want %q", v, "10.0.0.1:1234")
	}
}

func TestHTTPRequestToMap_NilRequest(t *testing.T) {
	m := HTTPRequestToMap(nil, nil, nil, "")
	if len(m) != 0 {
		t.Errorf("nil request should return empty map, got %v", m)
	}
}

func TestHTTPRequestToMap_NilConnInfo(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/", nil)
	m := HTTPRequestToMap(req, nil, nil, "HTTP/1.x")
	ci, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info should be present even when nil ConnInfo")
	}
	if len(ci) != 0 {
		t.Errorf("conn_info should be empty map, got %v", ci)
	}
}

func TestHTTPResponseToMap(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"application/json"}},
	}
	req, _ := gohttp.NewRequest("GET", "http://example.com/api", nil)
	req.Host = "example.com"
	body := []byte(`{"result":"ok"}`)
	ci := &ConnInfo{ServerAddr: "93.184.216.34:80"}

	m := HTTPResponseToMap(resp, body, req, ci, "HTTP/1.x")

	if v, ok := m["status_code"].(int); !ok || v != 200 {
		t.Errorf("status_code = %v, want 200", m["status_code"])
	}
	if v := m["protocol"].(string); v != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", v, "HTTP/1.x")
	}

	// Check request summary.
	reqSummary, ok := m["request"].(map[string]any)
	if !ok {
		t.Fatal("request should be map[string]any")
	}
	if v := reqSummary["method"].(string); v != "GET" {
		t.Errorf("request.method = %q, want %q", v, "GET")
	}

	// Check conn_info.
	connInfo, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info should be map[string]any")
	}
	if v := connInfo["server_addr"].(string); v != "93.184.216.34:80" {
		t.Errorf("conn_info.server_addr = %q, want %q", v, "93.184.216.34:80")
	}
}

func TestHTTPResponseToMap_NilResponse(t *testing.T) {
	m := HTTPResponseToMap(nil, nil, nil, nil, "")
	if len(m) != 0 {
		t.Errorf("nil response should return empty map, got %v", m)
	}
}

func TestApplyHTTPRequestChanges(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/old", nil)
	req.Host = "example.com"
	req.Header.Set("X-Original", "yes")

	data := map[string]any{
		"method": "POST",
		"url":    "http://example.com/new",
		"headers": map[string]any{
			"X-Modified": []any{"yes"},
		},
		"body": []byte("new-body"),
	}

	req, body, err := ApplyHTTPRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("method = %q, want %q", req.Method, "POST")
	}
	if req.URL.Path != "/new" {
		t.Errorf("path = %q, want %q", req.URL.Path, "/new")
	}
	if req.Header.Get("X-Modified") != "yes" {
		t.Errorf("X-Modified = %q, want %q", req.Header.Get("X-Modified"), "yes")
	}
	if !bytes.Equal(body, []byte("new-body")) {
		t.Errorf("body = %q, want %q", body, "new-body")
	}
}

func TestApplyHTTPRequestChanges_InvalidURL(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/", nil)
	data := map[string]any{
		"url": "://invalid",
	}
	_, _, err := ApplyHTTPRequestChanges(req, data)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestApplyHTTPRequestChanges_NilData(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/", nil)
	result, body, err := ApplyHTTPRequestChanges(req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != req {
		t.Error("nil data should return original request")
	}
	if body != nil {
		t.Error("nil data should return nil body")
	}
}

func TestApplyHTTPResponseChanges(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"X-Original": {"yes"}},
	}

	data := map[string]any{
		"status_code": int64(404),
		"headers": map[string]any{
			"X-Modified": []any{"yes"},
		},
		"body": []byte("not found"),
	}

	resp, body, err := ApplyHTTPResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 404 {
		t.Errorf("status_code = %d, want 404", resp.StatusCode)
	}
	if resp.Header.Get("X-Modified") != "yes" {
		t.Errorf("X-Modified = %q, want %q", resp.Header.Get("X-Modified"), "yes")
	}
	if !bytes.Equal(body, []byte("not found")) {
		t.Errorf("body = %q, want %q", body, "not found")
	}
}

func TestBuildRespondResponse(t *testing.T) {
	responseData := map[string]any{
		"status_code": int64(403),
		"headers": map[string]any{
			"Content-Type": []any{"text/plain"},
		},
		"body": "forbidden",
	}

	statusCode, headers, body := BuildRespondResponse(responseData)

	if statusCode != 403 {
		t.Errorf("statusCode = %d, want 403", statusCode)
	}
	if headers.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", headers.Get("Content-Type"), "text/plain")
	}
	if !bytes.Equal(body, []byte("forbidden")) {
		t.Errorf("body = %q, want %q", body, "forbidden")
	}
}

func TestBuildRespondResponse_Defaults(t *testing.T) {
	statusCode, headers, body := BuildRespondResponse(map[string]any{})

	if statusCode != 200 {
		t.Errorf("default statusCode = %d, want 200", statusCode)
	}
	if headers == nil {
		t.Error("headers should not be nil")
	}
	if body != nil {
		t.Errorf("body should be nil, got %v", body)
	}
}

func TestHeadersToMap_RoundTrip(t *testing.T) {
	original := gohttp.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer token123"},
		"Accept":        {"text/html", "application/json"},
	}

	m := headersToMap(original)
	restored := mapToHeaders(m)

	for key, wantVals := range original {
		gotVals := restored[key]
		if len(gotVals) != len(wantVals) {
			t.Errorf("header %q: got %d values, want %d", key, len(gotVals), len(wantVals))
			continue
		}
		for i, want := range wantVals {
			if gotVals[i] != want {
				t.Errorf("header %q[%d] = %q, want %q", key, i, gotVals[i], want)
			}
		}
	}
}

func TestSanitizeHeaderToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean value", "application/json", "application/json"},
		{"with CR", "value\rinjected", "valueinjected"},
		{"with LF", "value\ninjected", "valueinjected"},
		{"with CRLF", "value\r\ninjected: evil", "valueinjected: evil"},
		{"empty", "", ""},
		{"only CRLF", "\r\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHeaderToken(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeHeaderToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMapToHeaders_SanitizesCRLF(t *testing.T) {
	m := map[string]any{
		"X-Safe":             []any{"clean"},
		"X-Evil\r\nInjected": []any{"value"},
		"X-Evil-Value":       []any{"val\r\nInjected: yes"},
		"X-String-Val":       "single\r\nvalue",
		"X-String-Slice":     []string{"slice\r\nvalue"},
	}
	h := mapToHeaders(m)

	if v := h.Get("X-Safe"); v != "clean" {
		t.Errorf("X-Safe = %q, want %q", v, "clean")
	}
	// Key should have CRLF stripped.
	if v := h.Get("X-EvilInjected"); v != "value" {
		t.Errorf("X-EvilInjected = %q, want %q", v, "value")
	}
	// Value should have CRLF stripped.
	if v := h.Get("X-Evil-Value"); v != "valInjected: yes" {
		t.Errorf("X-Evil-Value = %q, want %q", v, "valInjected: yes")
	}
	if v := h.Get("X-String-Val"); v != "singlevalue" {
		t.Errorf("X-String-Val = %q, want %q", v, "singlevalue")
	}
	if v := h.Get("X-String-Slice"); v != "slicevalue" {
		t.Errorf("X-String-Slice = %q, want %q", v, "slicevalue")
	}
}

func TestValidStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		fallback int
		want     int
	}{
		{"valid 200", 200, 200, 200},
		{"valid 100", 100, 200, 100},
		{"valid 599", 599, 200, 599},
		{"zero", 0, 200, 200},
		{"negative", -1, 200, 200},
		{"too large", 1000, 200, 200},
		{"600", 600, 200, 200},
		{"99", 99, 200, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validStatusCode(tt.code, tt.fallback)
			if got != tt.want {
				t.Errorf("validStatusCode(%d, %d) = %d, want %d", tt.code, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestApplyHTTPResponseChanges_InvalidStatusCode(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{},
	}
	data := map[string]any{
		"status_code": 0,
	}
	resp, _, err := ApplyHTTPResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid status code 0 should preserve original 200.
	if resp.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200 (fallback)", resp.StatusCode)
	}
}

func TestApplyHTTPResponseChanges_NegativeStatusCode(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{},
	}
	data := map[string]any{
		"status_code": -1,
	}
	resp, _, err := ApplyHTTPResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200 (fallback)", resp.StatusCode)
	}
}

func TestBuildRespondResponse_InvalidStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode any
		want       int
	}{
		{"zero int", int(0), 200},
		{"negative int64", int64(-1), 200},
		{"too large float64", float64(1000), 200},
		{"valid int", int(403), 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"status_code": tt.statusCode}
			code, _, _ := BuildRespondResponse(data)
			if code != tt.want {
				t.Errorf("BuildRespondResponse status = %d, want %d", code, tt.want)
			}
		})
	}
}
