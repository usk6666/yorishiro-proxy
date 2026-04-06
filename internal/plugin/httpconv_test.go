package plugin

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
)

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
	// When no headers are provided in responseData, RawHeaders is nil.
	if headers != nil {
		t.Errorf("headers should be nil when not provided, got %v", headers)
	}
	if body != nil {
		t.Errorf("body should be nil, got %v", body)
	}
}

func TestBuildRespondResponse_OrderedArrayHeaders(t *testing.T) {
	responseData := map[string]any{
		"status_code": int64(200),
		"headers": []any{
			map[string]any{"name": "content-type", "value": "text/html"},
			map[string]any{"name": "x-custom", "value": "val"},
		},
		"body": []byte("hello"),
	}

	statusCode, headers, body := BuildRespondResponse(responseData)

	if statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", statusCode)
	}
	if len(headers) != 2 {
		t.Fatalf("headers length = %d, want 2", len(headers))
	}
	if headers[0].Name != "content-type" || headers[0].Value != "text/html" {
		t.Errorf("headers[0] = {%q, %q}, want content-type: text/html", headers[0].Name, headers[0].Value)
	}
	if !bytes.Equal(body, []byte("hello")) {
		t.Errorf("body = %q, want %q", body, "hello")
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
	if v := h.Get("X-EvilInjected"); v != "value" {
		t.Errorf("X-EvilInjected = %q, want %q", v, "value")
	}
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

func TestMapToHeaders_NilInput(t *testing.T) {
	h := mapToHeaders(nil)
	if h != nil {
		t.Errorf("nil input should return nil, got %v", h)
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

func TestInjectRawFrames(t *testing.T) {
	tests := []struct {
		name      string
		rawFrames [][]byte
		wantKey   bool
		wantLen   int
	}{
		{
			name:      "nil raw frames does not add key",
			rawFrames: nil,
			wantKey:   false,
		},
		{
			name:      "empty raw frames does not add key",
			rawFrames: [][]byte{},
			wantKey:   false,
		},
		{
			name:      "single frame",
			rawFrames: [][]byte{{0x00, 0x01, 0x02}},
			wantKey:   true,
			wantLen:   1,
		},
		{
			name:      "multiple frames",
			rawFrames: [][]byte{{0x00, 0x01}, {0x03, 0x04, 0x05}, {0x06}},
			wantKey:   true,
			wantLen:   3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"method": "GET"}
			InjectRawFrames(data, tt.rawFrames)

			frames, ok := data["raw_frames"]
			if tt.wantKey {
				if !ok {
					t.Fatal("expected raw_frames key in data map")
				}
				list, ok := frames.([]any)
				if !ok {
					t.Fatalf("raw_frames is %T, want []any", frames)
				}
				if len(list) != tt.wantLen {
					t.Errorf("raw_frames length = %d, want %d", len(list), tt.wantLen)
				}
				for i, item := range list {
					b, ok := item.([]byte)
					if !ok {
						t.Errorf("raw_frames[%d] is %T, want []byte", i, item)
						continue
					}
					if !bytes.Equal(b, tt.rawFrames[i]) {
						t.Errorf("raw_frames[%d] = %v, want %v", i, b, tt.rawFrames[i])
					}
				}
			} else {
				if ok {
					t.Error("raw_frames key should not be present")
				}
			}
		})
	}
}

func TestExtractBody(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
		want []byte
	}{
		{"bytes body", map[string]any{"body": []byte("hello")}, []byte("hello")},
		{"string body", map[string]any{"body": "hello"}, []byte("hello")},
		{"no body key", map[string]any{}, nil},
		{"int body ignored", map[string]any{"body": 42}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBody(tt.data)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("extractBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapFormatToHeaders(t *testing.T) {
	m := map[string]any{
		"Content-Type": []any{"text/html"},
		"Accept":       []string{"text/plain", "application/json"},
		"X-Single":     "value",
	}
	h := mapFormatToHeaders(m)

	if v := h.Get("Content-Type"); v != "text/html" {
		t.Errorf("Content-Type = %q, want %q", v, "text/html")
	}
	acceptVals := h.Values("Accept")
	if len(acceptVals) != 2 {
		t.Fatalf("Accept values = %d, want 2", len(acceptVals))
	}
	if v := h.Get("X-Single"); v != "value" {
		t.Errorf("X-Single = %q, want %q", v, "value")
	}
}

func TestMapToHeaders_RoundTripWithOrderedArray(t *testing.T) {
	// Verify ordered array → RawHeaders → ordered array round trip.
	original := parser.RawHeaders{
		{Name: "Content-Type", Value: "text/html"},
		{Name: "Set-Cookie", Value: "a=1"},
		{Name: "set-cookie", Value: "b=2"},
	}
	// Convert to ordered list (like RawRequestToMap does).
	list := rawHeadersToOrderedList(original)
	// Convert back via mapToHeaders (simulating plugin return).
	restored := mapToHeaders(list)
	if len(restored) != len(original) {
		t.Fatalf("length = %d, want %d", len(restored), len(original))
	}
	for i, h := range restored {
		if h.Name != original[i].Name || h.Value != original[i].Value {
			t.Errorf("headers[%d] = {%q, %q}, want {%q, %q}", i, h.Name, h.Value, original[i].Name, original[i].Value)
		}
	}
}
