package plugin

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

func TestH2RequestToMap(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/api?key=val"},
		{Name: "content-type", Value: "application/json"},
		{Name: "x-custom", Value: "first"},
		{Name: "x-custom", Value: "second"},
	}
	body := []byte(`{"foo":"bar"}`)
	ci := &ConnInfo{ClientAddr: "10.0.0.1:1234", TLSVersion: "TLS 1.3"}

	m := H2RequestToMap("POST", "https", "example.com", "/api?key=val", headers, body, ci, "h2")

	if v := m["method"].(string); v != "POST" {
		t.Errorf("method = %q, want %q", v, "POST")
	}
	if v := m["scheme"].(string); v != "https" {
		t.Errorf("scheme = %q, want %q", v, "https")
	}
	if v := m["host"].(string); v != "example.com" {
		t.Errorf("host = %q, want %q", v, "example.com")
	}
	if v := m["authority"].(string); v != "example.com" {
		t.Errorf("authority = %q, want %q", v, "example.com")
	}
	if v := m["path"].(string); v != "/api" {
		t.Errorf("path = %q, want %q", v, "/api")
	}
	if v := m["query"].(string); v != "key=val" {
		t.Errorf("query = %q, want %q", v, "key=val")
	}
	if v := m["url"].(string); v != "https://example.com/api?key=val" {
		t.Errorf("url = %q, want %q", v, "https://example.com/api?key=val")
	}
	if v := m["protocol"].(string); v != "h2" {
		t.Errorf("protocol = %q, want %q", v, "h2")
	}
	if v, ok := m["body"].([]byte); !ok || !bytes.Equal(v, body) {
		t.Errorf("body = %v, want %v", m["body"], body)
	}

	// Headers should be ordered array format, excluding pseudo-headers.
	hdrs, ok := m["headers"].([]any)
	if !ok {
		t.Fatal("headers is not []any")
	}
	if len(hdrs) != 3 {
		t.Fatalf("headers length = %d, want 3 (pseudo-headers excluded)", len(hdrs))
	}

	h0 := hdrs[0].(map[string]any)
	if h0["name"] != "content-type" || h0["value"] != "application/json" {
		t.Errorf("headers[0] = %v, want content-type: application/json", h0)
	}
	// Duplicate headers preserved separately.
	h1 := hdrs[1].(map[string]any)
	h2 := hdrs[2].(map[string]any)
	if h1["name"] != "x-custom" || h1["value"] != "first" {
		t.Errorf("headers[1] = %v, want x-custom: first", h1)
	}
	if h2["name"] != "x-custom" || h2["value"] != "second" {
		t.Errorf("headers[2] = %v, want x-custom: second", h2)
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

func TestH2RequestToMap_NilConnInfo(t *testing.T) {
	m := H2RequestToMap("GET", "https", "example.com", "/", nil, nil, nil, "h2")
	ci, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info should be present even when nil ConnInfo")
	}
	if len(ci) != 0 {
		t.Errorf("conn_info should be empty map, got %v", ci)
	}
}

func TestH2RequestToMap_PathOnly(t *testing.T) {
	// When scheme or authority is empty, URL should just be the path.
	m := H2RequestToMap("GET", "", "", "/path?q=1", nil, nil, nil, "h2")
	if v := m["url"].(string); v != "/path?q=1" {
		t.Errorf("url = %q, want %q", v, "/path?q=1")
	}
	if v := m["path"].(string); v != "/path" {
		t.Errorf("path = %q, want %q", v, "/path")
	}
	if v := m["query"].(string); v != "q=1" {
		t.Errorf("query = %q, want %q", v, "q=1")
	}
}

func TestH2ResponseToMap(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-custom", Value: "value"},
	}
	trailers := []hpack.HeaderField{
		{Name: "grpc-status", Value: "0"},
	}
	body := []byte(`{"result":"ok"}`)
	ci := &ConnInfo{ServerAddr: "93.184.216.34:443"}

	m := H2ResponseToMap(200, headers, trailers, body, "GET", "example.com", "/api", ci, "h2")

	if v, ok := m["status_code"].(int); !ok || v != 200 {
		t.Errorf("status_code = %v, want 200", m["status_code"])
	}
	if v := m["protocol"].(string); v != "h2" {
		t.Errorf("protocol = %q, want %q", v, "h2")
	}

	// Headers in ordered array format.
	hdrs, ok := m["headers"].([]any)
	if !ok {
		t.Fatal("headers should be []any")
	}
	if len(hdrs) != 2 {
		t.Fatalf("headers length = %d, want 2", len(hdrs))
	}

	// Trailers in ordered array format.
	trlrs, ok := m["trailers"].([]any)
	if !ok {
		t.Fatal("trailers should be []any")
	}
	if len(trlrs) != 1 {
		t.Fatalf("trailers length = %d, want 1", len(trlrs))
	}
	t0 := trlrs[0].(map[string]any)
	if t0["name"] != "grpc-status" || t0["value"] != "0" {
		t.Errorf("trailers[0] = %v, want grpc-status: 0", t0)
	}

	// Check request summary.
	reqSummary, ok := m["request"].(map[string]any)
	if !ok {
		t.Fatal("request should be map[string]any")
	}
	if v := reqSummary["method"].(string); v != "GET" {
		t.Errorf("request.method = %q, want %q", v, "GET")
	}
	if v := reqSummary["host"].(string); v != "example.com" {
		t.Errorf("request.host = %q, want %q", v, "example.com")
	}

	// Check conn_info.
	connInfo, ok := m["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info should be map[string]any")
	}
	if v := connInfo["server_addr"].(string); v != "93.184.216.34:443" {
		t.Errorf("conn_info.server_addr = %q, want %q", v, "93.184.216.34:443")
	}
}

func TestH2ResponseToMap_NoRequestSummary(t *testing.T) {
	m := H2ResponseToMap(200, nil, nil, nil, "", "", "", nil, "h2")
	if _, ok := m["request"]; ok {
		t.Error("request key should not be present when reqMethod is empty")
	}
}

func TestH2ResponseToMap_NilTrailers(t *testing.T) {
	m := H2ResponseToMap(200, nil, nil, nil, "GET", "", "/", nil, "h2")
	trlrs, ok := m["trailers"].([]any)
	if !ok {
		t.Fatal("trailers should be []any even when nil")
	}
	if len(trlrs) != 0 {
		t.Errorf("trailers should be empty, got %v", trlrs)
	}
}

func TestApplyH2RequestChanges(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "text/html"},
		{Name: "x-original", Value: "yes"},
	}

	data := map[string]any{
		"method": "POST",
		"url":    "https://new.example.com/new?q=1",
		"headers": []any{
			map[string]any{"name": "content-type", "value": "application/json"},
			map[string]any{"name": "x-modified", "value": "yes"},
		},
		"body": []byte("new-body"),
	}

	newMethod, newScheme, newAuthority, newPath, newHeaders, body, err := ApplyH2RequestChanges(
		"GET", "https", "example.com", "/old", headers, data,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if newMethod != "POST" {
		t.Errorf("method = %q, want %q", newMethod, "POST")
	}
	if newScheme != "https" {
		t.Errorf("scheme = %q, want %q", newScheme, "https")
	}
	if newAuthority != "new.example.com" {
		t.Errorf("authority = %q, want %q", newAuthority, "new.example.com")
	}
	if newPath != "/new?q=1" {
		t.Errorf("path = %q, want %q", newPath, "/new?q=1")
	}
	if len(newHeaders) != 2 {
		t.Fatalf("headers length = %d, want 2", len(newHeaders))
	}
	// HTTP/2 headers should be lowercased.
	if newHeaders[0].Name != "content-type" || newHeaders[0].Value != "application/json" {
		t.Errorf("headers[0] = {%q, %q}, want content-type: application/json", newHeaders[0].Name, newHeaders[0].Value)
	}
	if newHeaders[1].Name != "x-modified" || newHeaders[1].Value != "yes" {
		t.Errorf("headers[1] = {%q, %q}, want x-modified: yes", newHeaders[1].Name, newHeaders[1].Value)
	}
	if !bytes.Equal(body, []byte("new-body")) {
		t.Errorf("body = %q, want %q", body, "new-body")
	}
}

func TestApplyH2RequestChanges_NilData(t *testing.T) {
	newMethod, _, _, _, _, body, err := ApplyH2RequestChanges("GET", "https", "example.com", "/", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newMethod != "GET" {
		t.Errorf("method = %q, want %q (unchanged)", newMethod, "GET")
	}
	if body != nil {
		t.Error("body should be nil for nil data")
	}
}

func TestApplyH2RequestChanges_URLSchemeValidation(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"url": tt.url}
			_, _, newAuthority, newPath, _, _, err := ApplyH2RequestChanges(
				"GET", "https", "original.com", "/original", nil, data,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantApplied {
				if newPath == "/original" && newAuthority == "original.com" {
					t.Errorf("URL should have been updated for %q but was not", tt.url)
				}
			} else {
				if newPath != "/original" || newAuthority != "original.com" {
					t.Errorf("URL should remain unchanged for disallowed scheme, got authority=%q path=%q", newAuthority, newPath)
				}
			}
		})
	}
}

func TestApplyH2RequestChanges_InvalidURL(t *testing.T) {
	data := map[string]any{"url": "://invalid"}
	_, _, _, _, _, _, err := ApplyH2RequestChanges("GET", "https", "example.com", "/", nil, data)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestApplyH2RequestChanges_AuthorityOverride(t *testing.T) {
	data := map[string]any{
		"authority": "override.com",
	}
	_, _, newAuthority, _, _, _, err := ApplyH2RequestChanges("GET", "https", "original.com", "/", nil, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newAuthority != "override.com" {
		t.Errorf("authority = %q, want %q", newAuthority, "override.com")
	}
}

func TestApplyH2RequestChanges_HostFallback(t *testing.T) {
	data := map[string]any{
		"host": "host-override.com",
	}
	_, _, newAuthority, _, _, _, err := ApplyH2RequestChanges("GET", "https", "original.com", "/", nil, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newAuthority != "host-override.com" {
		t.Errorf("authority = %q, want %q", newAuthority, "host-override.com")
	}
}

func TestApplyH2RequestChanges_LegacyMapHeaders(t *testing.T) {
	data := map[string]any{
		"headers": map[string]any{
			"X-Modified": []any{"yes"},
		},
	}
	_, _, _, _, newHeaders, _, err := ApplyH2RequestChanges("GET", "https", "example.com", "/", nil, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(newHeaders) != 1 {
		t.Fatalf("headers length = %d, want 1", len(newHeaders))
	}
	// Legacy map headers should be lowercased for HTTP/2.
	if newHeaders[0].Name != "x-modified" {
		t.Errorf("header name = %q, want %q (lowercased)", newHeaders[0].Name, "x-modified")
	}
}

func TestApplyH2ResponseChanges(t *testing.T) {
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "text/html"},
	}

	data := map[string]any{
		"status_code": int64(404),
		"headers": []any{
			map[string]any{"name": "content-type", "value": "application/json"},
		},
		"body": []byte("not found"),
	}

	newStatus, newHeaders, _, body, err := ApplyH2ResponseChanges(200, headers, nil, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if newStatus != 404 {
		t.Errorf("status_code = %d, want 404", newStatus)
	}
	if len(newHeaders) != 1 {
		t.Fatalf("headers length = %d, want 1", len(newHeaders))
	}
	if newHeaders[0].Name != "content-type" || newHeaders[0].Value != "application/json" {
		t.Errorf("headers[0] = {%q, %q}, want content-type: application/json", newHeaders[0].Name, newHeaders[0].Value)
	}
	if !bytes.Equal(body, []byte("not found")) {
		t.Errorf("body = %q, want %q", body, "not found")
	}
}

func TestApplyH2ResponseChanges_NilData(t *testing.T) {
	newStatus, _, _, body, err := ApplyH2ResponseChanges(200, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newStatus != 200 {
		t.Errorf("status_code = %d, want 200 (unchanged)", newStatus)
	}
	if body != nil {
		t.Error("body should be nil for nil data")
	}
}

func TestApplyH2ResponseChanges_InvalidStatusCode(t *testing.T) {
	data := map[string]any{"status_code": 0}
	newStatus, _, _, _, err := ApplyH2ResponseChanges(200, nil, nil, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newStatus != 200 {
		t.Errorf("status_code = %d, want 200 (fallback)", newStatus)
	}
}

func TestApplyH2ResponseChanges_Trailers(t *testing.T) {
	trailers := []hpack.HeaderField{
		{Name: "grpc-status", Value: "0"},
	}
	data := map[string]any{
		"trailers": []any{
			map[string]any{"name": "grpc-status", "value": "13"},
			map[string]any{"name": "grpc-message", "value": "internal error"},
		},
	}
	_, _, newTrailers, _, err := ApplyH2ResponseChanges(200, nil, trailers, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(newTrailers) != 2 {
		t.Fatalf("trailers length = %d, want 2", len(newTrailers))
	}
	if newTrailers[0].Name != "grpc-status" || newTrailers[0].Value != "13" {
		t.Errorf("trailers[0] = {%q, %q}, want grpc-status: 13", newTrailers[0].Name, newTrailers[0].Value)
	}
}

func TestH2HeadersToOrderedList(t *testing.T) {
	tests := []struct {
		name    string
		fields  []hpack.HeaderField
		wantLen int
	}{
		{"nil fields", nil, 0},
		{"empty fields", []hpack.HeaderField{}, 0},
		{
			"excludes pseudo-headers",
			[]hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":path", Value: "/"},
				{Name: "content-type", Value: "text/html"},
				{Name: "x-custom", Value: "val"},
			},
			2, // pseudo-headers excluded
		},
		{
			"preserves duplicates",
			[]hpack.HeaderField{
				{Name: "x-custom", Value: "a"},
				{Name: "x-custom", Value: "b"},
			},
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := h2HeadersToOrderedList(tt.fields)
			if len(list) != tt.wantLen {
				t.Errorf("list length = %d, want %d", len(list), tt.wantLen)
			}
		})
	}
}

func TestMapToH2Headers_OrderedArray(t *testing.T) {
	list := []any{
		map[string]any{"name": "Content-Type", "value": "text/html"},
		map[string]any{"name": "X-Custom", "value": "val"},
	}
	fields := mapToH2Headers(list)
	if len(fields) != 2 {
		t.Fatalf("length = %d, want 2", len(fields))
	}
	// Names should be lowercased for HTTP/2.
	if fields[0].Name != "content-type" || fields[0].Value != "text/html" {
		t.Errorf("fields[0] = {%q, %q}, want content-type: text/html", fields[0].Name, fields[0].Value)
	}
	if fields[1].Name != "x-custom" || fields[1].Value != "val" {
		t.Errorf("fields[1] = {%q, %q}, want x-custom: val", fields[1].Name, fields[1].Value)
	}
}

func TestMapToH2Headers_LegacyMap(t *testing.T) {
	m := map[string]any{
		"Content-Type": []any{"text/html"},
	}
	fields := mapToH2Headers(m)
	if len(fields) != 1 {
		t.Fatalf("length = %d, want 1", len(fields))
	}
	if fields[0].Name != "content-type" || fields[0].Value != "text/html" {
		t.Errorf("fields[0] = {%q, %q}, want content-type: text/html", fields[0].Name, fields[0].Value)
	}
}

func TestMapToH2Headers_Nil(t *testing.T) {
	fields := mapToH2Headers(nil)
	if fields != nil {
		t.Errorf("nil input should return nil, got %v", fields)
	}
}

func TestMapToH2Headers_SanitizesCRLF(t *testing.T) {
	list := []any{
		map[string]any{"name": "x-evil\r\ninjected", "value": "val\r\nmore"},
	}
	fields := mapToH2Headers(list)
	if len(fields) != 1 {
		t.Fatalf("length = %d, want 1", len(fields))
	}
	if fields[0].Name != "x-evilinjected" {
		t.Errorf("name = %q, want %q (CRLF sanitized)", fields[0].Name, "x-evilinjected")
	}
	if fields[0].Value != "valmore" {
		t.Errorf("value = %q, want %q (CRLF sanitized)", fields[0].Value, "valmore")
	}
}

func TestH2RequestToMap_RoundTrip(t *testing.T) {
	// Verify that H2RequestToMap → ApplyH2RequestChanges preserves
	// header order and casing (lossless round-trip for HTTP/2).
	origHeaders := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-first", Value: "a"},
		{Name: "x-second", Value: "b"},
		{Name: "x-first", Value: "c"},
	}

	m := H2RequestToMap("POST", "https", "example.com", "/api", origHeaders, []byte("body"), nil, "h2")

	// Apply the same data back (simulating a no-op plugin).
	newMethod, newScheme, newAuthority, newPath, newHeaders, _, err := ApplyH2RequestChanges(
		"POST", "https", "example.com", "/api", origHeaders, m,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if newMethod != "POST" {
		t.Errorf("method = %q, want %q", newMethod, "POST")
	}
	if newScheme != "https" {
		t.Errorf("scheme = %q, want %q", newScheme, "https")
	}
	if newAuthority != "example.com" {
		t.Errorf("authority = %q, want %q", newAuthority, "example.com")
	}
	if newPath != "/api" {
		t.Errorf("path = %q, want %q", newPath, "/api")
	}

	// Verify header order preserved (pseudo-headers excluded in headers list).
	if len(newHeaders) != len(origHeaders) {
		t.Fatalf("headers count = %d, want %d", len(newHeaders), len(origHeaders))
	}
	for i, h := range newHeaders {
		if h.Name != origHeaders[i].Name || h.Value != origHeaders[i].Value {
			t.Errorf("headers[%d] = {%q, %q}, want {%q, %q}", i, h.Name, h.Value, origHeaders[i].Name, origHeaders[i].Value)
		}
	}
}
