package exchange

import (
	"net/url"
	"testing"
)

func TestDirection_String(t *testing.T) {
	tests := []struct {
		d    Direction
		want string
	}{
		{Send, "Send"},
		{Receive, "Receive"},
		{Direction(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Direction(%d).String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		p    Protocol
		want string
	}{
		{HTTP1, "HTTP/1.x"},
		{HTTP2, "HTTP/2"},
		{GRPC, "gRPC"},
		{GRPCWeb, "gRPC-Web"},
		{WS, "WebSocket"},
		{SSE, "SSE"},
		{TCP, "TCP"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Protocol(%q).String() = %q, want %q", string(tt.p), got, tt.want)
		}
	}
}

func TestClone_DeepCopy(t *testing.T) {
	orig := &Exchange{
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: Send,
		Method:    "POST",
		URL:       &url.URL{Scheme: "https", Host: "example.com", Path: "/api"},
		Status:    0,
		Headers: []KeyValue{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom", Value: "foo"},
		},
		Trailers: []KeyValue{
			{Name: "Grpc-Status", Value: "0"},
		},
		Body:     []byte(`{"key":"value"}`),
		Protocol: HTTP1,
		RawBytes: []byte("POST /api HTTP/1.1\r\n"),
		Opaque:   "opaque-data",
		Metadata: map[string]any{
			"ws_opcode": 1,
		},
	}

	cloned := orig.Clone()

	// Verify values match
	if cloned.FlowID != orig.FlowID {
		t.Errorf("FlowID mismatch: got %q, want %q", cloned.FlowID, orig.FlowID)
	}
	if cloned.Sequence != orig.Sequence {
		t.Errorf("Sequence mismatch: got %d, want %d", cloned.Sequence, orig.Sequence)
	}
	if cloned.Direction != orig.Direction {
		t.Errorf("Direction mismatch: got %v, want %v", cloned.Direction, orig.Direction)
	}
	if cloned.Method != orig.Method {
		t.Errorf("Method mismatch: got %q, want %q", cloned.Method, orig.Method)
	}
	if cloned.URL.String() != orig.URL.String() {
		t.Errorf("URL mismatch: got %q, want %q", cloned.URL.String(), orig.URL.String())
	}
	if cloned.Protocol != orig.Protocol {
		t.Errorf("Protocol mismatch: got %q, want %q", cloned.Protocol, orig.Protocol)
	}

	// Mutate original and verify clone is unaffected
	orig.Headers[0].Value = "text/plain"
	if cloned.Headers[0].Value != "application/json" {
		t.Error("Clone Headers affected by mutating original")
	}

	orig.Trailers[0].Value = "1"
	if cloned.Trailers[0].Value != "0" {
		t.Error("Clone Trailers affected by mutating original")
	}

	orig.Body[0] = 'X'
	if cloned.Body[0] == 'X' {
		t.Error("Clone Body affected by mutating original")
	}

	orig.RawBytes[0] = 'X'
	if cloned.RawBytes[0] == 'X' {
		t.Error("Clone RawBytes affected by mutating original")
	}

	orig.Metadata["ws_opcode"] = 2
	if cloned.Metadata["ws_opcode"] != 1 {
		t.Error("Clone Metadata affected by mutating original")
	}

	orig.URL.Host = "modified.com"
	if cloned.URL.Host != "example.com" {
		t.Error("Clone URL affected by mutating original")
	}
}

func TestClone_Nil(t *testing.T) {
	var e *Exchange
	if got := e.Clone(); got != nil {
		t.Errorf("nil.Clone() = %v, want nil", got)
	}
}

func TestClone_NilFields(t *testing.T) {
	orig := &Exchange{
		FlowID:   "flow-2",
		Protocol: TCP,
	}
	cloned := orig.Clone()

	if cloned.Headers != nil {
		t.Error("Clone of nil Headers should be nil")
	}
	if cloned.Trailers != nil {
		t.Error("Clone of nil Trailers should be nil")
	}
	if cloned.Body != nil {
		t.Error("Clone of nil Body should be nil")
	}
	if cloned.RawBytes != nil {
		t.Error("Clone of nil RawBytes should be nil")
	}
	if cloned.Metadata != nil {
		t.Error("Clone of nil Metadata should be nil")
	}
	if cloned.URL != nil {
		t.Error("Clone of nil URL should be nil")
	}
}

func TestClone_OpaqueShallowCopy(t *testing.T) {
	type codecData struct {
		FrameID int
	}
	data := &codecData{FrameID: 42}
	orig := &Exchange{
		FlowID: "flow-3",
		Opaque: data,
	}
	cloned := orig.Clone()

	// Opaque should be the same pointer (shallow copy)
	if cloned.Opaque != orig.Opaque {
		t.Error("Clone Opaque should be shallow copy (same pointer)")
	}
}

func TestHeaderValue(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom", Value: "first"},
			{Name: "x-custom", Value: "second"},
		},
	}

	tests := []struct {
		name string
		want string
	}{
		{"Content-Type", "application/json"},
		{"content-type", "application/json"},
		{"CONTENT-TYPE", "application/json"},
		{"X-Custom", "first"}, // returns first match
		{"x-custom", "first"}, // case-insensitive, returns first
		{"X-Missing", ""},     // not found
		{"", ""},              // empty name
	}
	for _, tt := range tests {
		if got := e.HeaderValue(tt.name); got != tt.want {
			t.Errorf("HeaderValue(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestHeaderValue_EmptyHeaders(t *testing.T) {
	e := &Exchange{}
	if got := e.HeaderValue("anything"); got != "" {
		t.Errorf("HeaderValue on empty Headers = %q, want %q", got, "")
	}
}

func TestSetHeader_Update(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Accept", Value: "*/*"},
		},
	}

	e.SetHeader("content-type", "application/json")

	if len(e.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(e.Headers))
	}
	// Preserves original casing of the name
	if e.Headers[0].Name != "Content-Type" {
		t.Errorf("SetHeader should preserve original name casing, got %q", e.Headers[0].Name)
	}
	if e.Headers[0].Value != "application/json" {
		t.Errorf("SetHeader value = %q, want %q", e.Headers[0].Value, "application/json")
	}
}

func TestSetHeader_Append(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Accept", Value: "*/*"},
		},
	}

	e.SetHeader("X-New", "value")

	if len(e.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(e.Headers))
	}
	if e.Headers[1].Name != "X-New" || e.Headers[1].Value != "value" {
		t.Errorf("SetHeader append: got {%q, %q}, want {%q, %q}",
			e.Headers[1].Name, e.Headers[1].Value, "X-New", "value")
	}
}

func TestSetHeader_EmptyHeaders(t *testing.T) {
	e := &Exchange{}
	e.SetHeader("X-New", "value")

	if len(e.Headers) != 1 {
		t.Fatalf("expected 1 header, got %d", len(e.Headers))
	}
	if e.Headers[0].Name != "X-New" || e.Headers[0].Value != "value" {
		t.Errorf("SetHeader on nil Headers: got {%q, %q}", e.Headers[0].Name, e.Headers[0].Value)
	}
}

func TestAddHeader(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Set-Cookie", Value: "a=1"},
		},
	}

	e.AddHeader("Set-Cookie", "b=2")

	if len(e.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(e.Headers))
	}
	if e.Headers[0].Value != "a=1" {
		t.Errorf("first Set-Cookie = %q, want %q", e.Headers[0].Value, "a=1")
	}
	if e.Headers[1].Value != "b=2" {
		t.Errorf("second Set-Cookie = %q, want %q", e.Headers[1].Value, "b=2")
	}
}

func TestAddHeader_NilHeaders(t *testing.T) {
	e := &Exchange{}
	e.AddHeader("X-First", "value")

	if len(e.Headers) != 1 {
		t.Fatalf("expected 1 header, got %d", len(e.Headers))
	}
}

func TestDelHeader(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Set-Cookie", Value: "a=1"},
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "set-cookie", Value: "b=2"},
		},
	}

	e.DelHeader("Set-Cookie")

	if len(e.Headers) != 1 {
		t.Fatalf("expected 1 header after delete, got %d", len(e.Headers))
	}
	if e.Headers[0].Name != "Content-Type" {
		t.Errorf("remaining header = %q, want %q", e.Headers[0].Name, "Content-Type")
	}
}

func TestDelHeader_NotFound(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Accept", Value: "*/*"},
		},
	}

	e.DelHeader("X-Missing")

	if len(e.Headers) != 1 {
		t.Fatalf("expected 1 header (unchanged), got %d", len(e.Headers))
	}
}

func TestDelHeader_EmptyHeaders(t *testing.T) {
	e := &Exchange{}
	e.DelHeader("anything") // should not panic
	if e.Headers != nil {
		t.Errorf("DelHeader on nil Headers should remain nil, got %v", e.Headers)
	}
}

func TestClone_URLWithUserInfo(t *testing.T) {
	orig := &Exchange{
		FlowID: "flow-url",
		URL:    &url.URL{Scheme: "https", Host: "example.com", User: url.UserPassword("user", "pass")},
	}
	cloned := orig.Clone()

	// Verify user info is preserved
	if cloned.URL.User.Username() != "user" {
		t.Errorf("cloned URL username = %q, want %q", cloned.URL.User.Username(), "user")
	}
	p, ok := cloned.URL.User.Password()
	if !ok || p != "pass" {
		t.Errorf("cloned URL password = %q (ok=%v), want %q", p, ok, "pass")
	}
}
