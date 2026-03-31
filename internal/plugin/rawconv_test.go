package plugin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

func TestRawRequestToMap(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "http://example.com/api?key=val",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom", Value: "first"},
			{Name: "X-Custom", Value: "second"},
		},
	}
	body := []byte(`{"foo":"bar"}`)
	ci := &ConnInfo{ClientAddr: "10.0.0.1:1234", TLSVersion: "TLS 1.3"}

	m := RawRequestToMap(req, body, ci, "HTTP/1.x")

	if v := m["method"].(string); v != "POST" {
		t.Errorf("method = %q, want %q", v, "POST")
	}
	if v := m["request_uri"].(string); v != "http://example.com/api?key=val" {
		t.Errorf("request_uri = %q, want %q", v, "http://example.com/api?key=val")
	}
	if v := m["url"].(string); v != "http://example.com/api?key=val" {
		t.Errorf("url = %q, want %q", v, "http://example.com/api?key=val")
	}
	if v := m["scheme"].(string); v != "http" {
		t.Errorf("scheme = %q, want %q", v, "http")
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
	if v := m["proto"].(string); v != "HTTP/1.1" {
		t.Errorf("proto = %q, want %q", v, "HTTP/1.1")
	}
	if v := m["protocol"].(string); v != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", v, "HTTP/1.x")
	}
	if v, ok := m["body"].([]byte); !ok || !bytes.Equal(v, body) {
		t.Errorf("body = %v, want %v", m["body"], body)
	}

	// Headers should be ordered array format.
	headers, ok := m["headers"].([]any)
	if !ok {
		t.Fatal("headers is not []any")
	}
	if len(headers) != 4 {
		t.Fatalf("headers length = %d, want 4", len(headers))
	}

	// Verify order and casing preserved.
	h0 := headers[0].(map[string]any)
	if h0["name"] != "Host" || h0["value"] != "example.com" {
		t.Errorf("headers[0] = %v, want Host: example.com", h0)
	}
	h1 := headers[1].(map[string]any)
	if h1["name"] != "Content-Type" || h1["value"] != "application/json" {
		t.Errorf("headers[1] = %v, want Content-Type: application/json", h1)
	}
	// Duplicate headers preserved separately.
	h2 := headers[2].(map[string]any)
	h3 := headers[3].(map[string]any)
	if h2["name"] != "X-Custom" || h2["value"] != "first" {
		t.Errorf("headers[2] = %v, want X-Custom: first", h2)
	}
	if h3["name"] != "X-Custom" || h3["value"] != "second" {
		t.Errorf("headers[3] = %v, want X-Custom: second", h3)
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

func TestRawRequestToMap_NilRequest(t *testing.T) {
	m := RawRequestToMap(nil, nil, nil, "")
	if len(m) != 0 {
		t.Errorf("nil request should return empty map, got %v", m)
	}
}

func TestRawRequestToMap_NilConnInfo(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/path",
		Proto:      "HTTP/1.1",
	}
	m := RawRequestToMap(req, nil, nil, "HTTP/1.x")
	ci, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info should be present even when nil ConnInfo")
	}
	if len(ci) != 0 {
		t.Errorf("conn_info should be empty map, got %v", ci)
	}
}

func TestRawRequestToMap_RelativeURI(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/path?q=1",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
		},
	}
	m := RawRequestToMap(req, nil, nil, "HTTP/1.x")

	if v := m["scheme"].(string); v != "" {
		t.Errorf("scheme = %q, want empty for relative URI", v)
	}
	if v := m["host"].(string); v != "example.com" {
		t.Errorf("host = %q, want %q (from Host header)", v, "example.com")
	}
	if v := m["path"].(string); v != "/path" {
		t.Errorf("path = %q, want %q", v, "/path")
	}
	if v := m["query"].(string); v != "q=1" {
		t.Errorf("query = %q, want %q", v, "q=1")
	}
}

func TestRawRequestToMap_HeaderCasingPreserved(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "x-lowercase", Value: "a"},
			{Name: "X-UPPERCASE", Value: "b"},
			{Name: "X-MiXeD-CaSe", Value: "c"},
		},
	}
	m := RawRequestToMap(req, nil, nil, "HTTP/1.x")
	headers := m["headers"].([]any)

	wantNames := []string{"x-lowercase", "X-UPPERCASE", "X-MiXeD-CaSe"}
	for i, want := range wantNames {
		h := headers[i].(map[string]any)
		if h["name"] != want {
			t.Errorf("headers[%d].name = %q, want %q", i, h["name"], want)
		}
	}
}

func TestRawResponseToMap(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom", Value: "value"},
		},
	}
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "http://example.com/api",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
		},
	}
	body := []byte(`{"result":"ok"}`)
	ci := &ConnInfo{ServerAddr: "93.184.216.34:80"}

	m := RawResponseToMap(resp, body, req, ci, "HTTP/1.x")

	if v, ok := m["status_code"].(int); !ok || v != 200 {
		t.Errorf("status_code = %v, want 200", m["status_code"])
	}
	if v := m["protocol"].(string); v != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", v, "HTTP/1.x")
	}

	// Headers in ordered array format.
	headers, ok := m["headers"].([]any)
	if !ok {
		t.Fatal("headers should be []any")
	}
	if len(headers) != 2 {
		t.Fatalf("headers length = %d, want 2", len(headers))
	}

	// Check request summary.
	reqSummary, ok := m["request"].(map[string]any)
	if !ok {
		t.Fatal("request should be map[string]any")
	}
	if v := reqSummary["method"].(string); v != "GET" {
		t.Errorf("request.method = %q, want %q", v, "GET")
	}
	if v := reqSummary["request_uri"].(string); v != "http://example.com/api" {
		t.Errorf("request.request_uri = %q, want %q", v, "http://example.com/api")
	}
	if v := reqSummary["host"].(string); v != "example.com" {
		t.Errorf("request.host = %q, want %q", v, "example.com")
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

func TestRawResponseToMap_NilResponse(t *testing.T) {
	m := RawResponseToMap(nil, nil, nil, nil, "")
	if len(m) != 0 {
		t.Errorf("nil response should return empty map, got %v", m)
	}
}

func TestRawResponseToMap_NilRequest(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Headers:    parser.RawHeaders{},
	}
	m := RawResponseToMap(resp, nil, nil, nil, "HTTP/1.x")
	if _, ok := m["request"]; ok {
		t.Error("request key should not be present when req is nil")
	}
}

func TestApplyRawRequestChanges(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "http://example.com/old",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "X-Original", Value: "yes"},
		},
	}

	data := map[string]any{
		"method": "POST",
		"url":    "http://example.com/new?q=1",
		"headers": []any{
			map[string]any{"name": "Host", "value": "example.com"},
			map[string]any{"name": "X-Modified", "value": "yes"},
		},
		"body": []byte("new-body"),
	}

	req, body, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("method = %q, want %q", req.Method, "POST")
	}
	if req.RequestURI != "http://example.com/new?q=1" {
		t.Errorf("request_uri = %q, want %q", req.RequestURI, "http://example.com/new?q=1")
	}
	if v := req.Headers.Get("X-Modified"); v != "yes" {
		t.Errorf("X-Modified = %q, want %q", v, "yes")
	}
	if !bytes.Equal(body, []byte("new-body")) {
		t.Errorf("body = %q, want %q", body, "new-body")
	}
	// Content-Length should be synced.
	if v := req.Headers.Get("Content-Length"); v != "8" {
		t.Errorf("Content-Length = %q, want %q", v, "8")
	}
}

func TestApplyRawRequestChanges_NilData(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
	}
	result, body, err := ApplyRawRequestChanges(req, nil)
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

func TestApplyRawRequestChanges_URLSchemeValidation(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantApplied bool
	}{
		{"http scheme allowed", "http://example.com/new", true},
		{"https scheme allowed", "https://example.com/new", true},
		{"empty scheme allowed (relative)", "/relative/path", true},
		{"file scheme rejected", "file:///etc/passwd", false},
		{"gopher scheme rejected", "gopher://evil.com/", false},
		{"ftp scheme rejected", "ftp://evil.com/file", false},
		{"javascript scheme rejected", "javascript:alert(1)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalURI := "http://example.com/original"
			req := &parser.RawRequest{
				Method:     "GET",
				RequestURI: originalURI,
				Proto:      "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
				},
			}
			data := map[string]any{
				"url": tt.url,
			}
			req, _, err := ApplyRawRequestChanges(req, data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantApplied {
				if req.RequestURI == originalURI {
					t.Errorf("RequestURI should have been updated to %q but was not", tt.url)
				}
			} else {
				if req.RequestURI != originalURI {
					t.Errorf("RequestURI should remain %q for disallowed scheme, got %q", originalURI, req.RequestURI)
				}
			}
		})
	}
}

func TestApplyRawRequestChanges_InvalidURL(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "http://example.com/",
		Proto:      "HTTP/1.1",
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"url": "://invalid",
	}
	_, _, err := ApplyRawRequestChanges(req, data)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestApplyRawRequestChanges_RequestURIFallback(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/old",
		Proto:      "HTTP/1.1",
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"request_uri": "/new-path?q=1",
	}
	req, _, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.RequestURI != "/new-path?q=1" {
		t.Errorf("RequestURI = %q, want %q", req.RequestURI, "/new-path?q=1")
	}
}

func TestApplyRawRequestChanges_HostOverridesHeader(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "original.com"},
		},
	}
	data := map[string]any{
		"host": "override.com",
	}
	req, _, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := req.Headers.Get("Host"); v != "override.com" {
		t.Errorf("Host = %q, want %q", v, "override.com")
	}
}

func TestApplyRawRequestChanges_LegacyMapHeaders(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "X-Original", Value: "yes"},
		},
	}
	// Legacy map format (backward compatibility).
	data := map[string]any{
		"headers": map[string]any{
			"X-Modified": []any{"yes"},
		},
	}
	req, _, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := req.Headers.Get("X-Modified"); v != "yes" {
		t.Errorf("X-Modified = %q, want %q", v, "yes")
	}
}

func TestApplyRawResponseChanges(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Headers: parser.RawHeaders{
			{Name: "X-Original", Value: "yes"},
		},
	}

	data := map[string]any{
		"status_code": int64(404),
		"headers": []any{
			map[string]any{"name": "X-Modified", "value": "yes"},
		},
		"body": []byte("not found"),
	}

	resp, body, err := ApplyRawResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 404 {
		t.Errorf("status_code = %d, want 404", resp.StatusCode)
	}
	if v := resp.Headers.Get("X-Modified"); v != "yes" {
		t.Errorf("X-Modified = %q, want %q", v, "yes")
	}
	if !bytes.Equal(body, []byte("not found")) {
		t.Errorf("body = %q, want %q", body, "not found")
	}
}

func TestApplyRawResponseChanges_NilData(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Headers:    parser.RawHeaders{},
	}
	result, body, err := ApplyRawResponseChanges(resp, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != resp {
		t.Error("nil data should return original response")
	}
	if body != nil {
		t.Error("nil data should return nil body")
	}
}

func TestApplyRawResponseChanges_InvalidStatusCode(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"status_code": 0,
	}
	resp, _, err := ApplyRawResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200 (fallback)", resp.StatusCode)
	}
}

func TestApplyRawResponseChanges_StringBody(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"body": "string-body",
	}
	_, body, err := ApplyRawResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(body, []byte("string-body")) {
		t.Errorf("body = %q, want %q", body, "string-body")
	}
}

func TestRawHeadersToOrderedList(t *testing.T) {
	tests := []struct {
		name    string
		headers parser.RawHeaders
		want    int
	}{
		{"nil headers", nil, 0},
		{"empty headers", parser.RawHeaders{}, 0},
		{
			"multiple headers",
			parser.RawHeaders{
				{Name: "A", Value: "1"},
				{Name: "B", Value: "2"},
				{Name: "A", Value: "3"},
			},
			3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := rawHeadersToOrderedList(tt.headers)
			if len(list) != tt.want {
				t.Errorf("list length = %d, want %d", len(list), tt.want)
			}
		})
	}
}

func TestOrderedArrayToRawHeaders(t *testing.T) {
	tests := []struct {
		name string
		list []any
		want parser.RawHeaders
	}{
		{
			name: "valid ordered array",
			list: []any{
				map[string]any{"name": "Host", "value": "example.com"},
				map[string]any{"name": "X-Custom", "value": "val"},
			},
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Custom", Value: "val"},
			},
		},
		{
			name: "empty array returns empty non-nil slice",
			list: []any{},
			want: parser.RawHeaders{},
		},
		{
			name: "skip invalid items",
			list: []any{
				map[string]any{"name": "Valid", "value": "yes"},
				"not-a-map",
				map[string]any{"name": "", "value": "empty-name-skipped"},
			},
			want: parser.RawHeaders{
				{Name: "Valid", Value: "yes"},
			},
		},
		{
			name: "CRLF sanitized",
			list: []any{
				map[string]any{"name": "X-Evil\r\nInjected", "value": "val\r\nmore"},
			},
			want: parser.RawHeaders{
				{Name: "X-EvilInjected", Value: "valmore"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orderedArrayToRawHeaders(tt.list)
			if len(got) != len(tt.want) {
				t.Fatalf("length = %d, want %d", len(got), len(tt.want))
			}
			for i, h := range got {
				if h.Name != tt.want[i].Name || h.Value != tt.want[i].Value {
					t.Errorf("headers[%d] = {%q, %q}, want {%q, %q}", i, h.Name, h.Value, tt.want[i].Name, tt.want[i].Value)
				}
			}
		})
	}
}

func TestRawRequestToMap_RoundTrip(t *testing.T) {
	// Verify that RawRequestToMap → ApplyRawRequestChanges preserves
	// header order and casing (lossless round-trip).
	original := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "http://example.com/api",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "content-type", Value: "application/json"},
			{Name: "X-First", Value: "a"},
			{Name: "X-Second", Value: "b"},
			{Name: "X-First", Value: "c"},
		},
		Body: strings.NewReader("body"),
	}
	body := []byte("body")

	m := RawRequestToMap(original, body, nil, "HTTP/1.x")

	// Apply the same data back (simulating a no-op plugin).
	target := &parser.RawRequest{
		Method:     original.Method,
		RequestURI: original.RequestURI,
		Proto:      original.Proto,
		Headers:    original.Headers.Clone(),
	}
	result, _, err := ApplyRawRequestChanges(target, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify header order and casing preserved.
	// Body is present in the data map, so Content-Length is synced (added/updated).
	// Filter out Content-Length for comparison.
	var resultHeaders parser.RawHeaders
	for _, h := range result.Headers {
		if h.Name != "Content-Length" {
			resultHeaders = append(resultHeaders, h)
		}
	}

	wantHeaders := []parser.RawHeader{
		{Name: "Host", Value: "example.com"},
		{Name: "content-type", Value: "application/json"},
		{Name: "X-First", Value: "a"},
		{Name: "X-Second", Value: "b"},
		{Name: "X-First", Value: "c"},
	}
	if len(resultHeaders) != len(wantHeaders) {
		t.Fatalf("headers count (excl Content-Length) = %d, want %d", len(resultHeaders), len(wantHeaders))
	}
	for i, h := range resultHeaders {
		if h.Name != wantHeaders[i].Name || h.Value != wantHeaders[i].Value {
			t.Errorf("headers[%d] = {%q, %q}, want {%q, %q}", i, h.Name, h.Value, wantHeaders[i].Name, wantHeaders[i].Value)
		}
	}
}

func TestMapToHeaders_OrderedArrayFormat(t *testing.T) {
	// Verify that mapToHeaders (used by BuildRespondResponse) also
	// handles the ordered array format.
	list := []any{
		map[string]any{"name": "Content-Type", "value": "text/plain"},
		map[string]any{"name": "X-Custom", "value": "val"},
	}

	h := mapToHeaders(list)
	if len(h) != 2 {
		t.Fatalf("length = %d, want 2", len(h))
	}
	if h[0].Name != "Content-Type" || h[0].Value != "text/plain" {
		t.Errorf("h[0] = {%q, %q}, want Content-Type: text/plain", h[0].Name, h[0].Value)
	}
	if h[1].Name != "X-Custom" || h[1].Value != "val" {
		t.Errorf("h[1] = {%q, %q}, want X-Custom: val", h[1].Name, h[1].Value)
	}
}

func TestMapToHeaders_LegacyMapFormat(t *testing.T) {
	// Ensure legacy map format still works.
	m := map[string]any{
		"Content-Type": []any{"text/plain"},
		"X-Multi":      []any{"a", "b"},
	}

	h := mapToHeaders(m)
	if h == nil {
		t.Fatal("expected non-nil headers")
	}
	if v := h.Get("Content-Type"); v != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", v, "text/plain")
	}
	vals := h.Values("X-Multi")
	if len(vals) != 2 {
		t.Fatalf("X-Multi values = %d, want 2", len(vals))
	}
}

func TestApplyRawRequestChanges_NilRequest(t *testing.T) {
	_, _, err := ApplyRawRequestChanges(nil, map[string]any{"method": "POST"})
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestApplyRawResponseChanges_NilResponse(t *testing.T) {
	_, _, err := ApplyRawResponseChanges(nil, map[string]any{"status_code": 404})
	if err == nil {
		t.Error("expected error for nil response")
	}
}

func TestApplyRawResponseChanges_StatusStringSynced(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"status_code": 404,
	}
	resp, _, err := ApplyRawResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status_code = %d, want 404", resp.StatusCode)
	}
	if resp.Status != "404 Not Found" {
		t.Errorf("status = %q, want %q", resp.Status, "404 Not Found")
	}
}

func TestApplyRawResponseChanges_StatusUnchangedWhenCodeSame(t *testing.T) {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 Custom Reason",
		Headers:    parser.RawHeaders{},
	}
	data := map[string]any{
		"status_code": 200,
	}
	resp, _, err := ApplyRawResponseChanges(resp, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Custom reason should be preserved when code doesn't change.
	if resp.Status != "200 Custom Reason" {
		t.Errorf("status = %q, want %q (preserved)", resp.Status, "200 Custom Reason")
	}
}

func TestApplyRawRequestChanges_EmptyHeadersClears(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "X-Custom", Value: "val"},
		},
	}
	data := map[string]any{
		"headers": []any{}, // empty array should clear all headers
	}
	req, _, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.Headers) != 0 {
		t.Errorf("headers length = %d, want 0 (cleared)", len(req.Headers))
	}
}

func TestApplyRawRequestChanges_EmptyBody(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Length", Value: "10"},
		},
	}
	data := map[string]any{
		"body": []byte{},
	}
	req, body, err := ApplyRawRequestChanges(req, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body length = %d, want 0", len(body))
	}
	// Content-Length should be removed for empty body.
	if v := req.Headers.Get("Content-Length"); v != "" {
		t.Errorf("Content-Length = %q, want empty (removed)", v)
	}
}
