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
		StreamID:  "stream-1",
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
	if cloned.StreamID != orig.StreamID {
		t.Errorf("StreamID mismatch: got %q, want %q", cloned.StreamID, orig.StreamID)
	}
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
		StreamID: "stream-2",
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
		StreamID: "flow-3",
		Opaque:   data,
	}
	cloned := orig.Clone()

	// Opaque should be the same pointer (shallow copy)
	if cloned.Opaque != orig.Opaque {
		t.Error("Clone Opaque should be shallow copy (same pointer)")
	}
}

func TestGetHeaders(t *testing.T) {
	headers := []KeyValue{
		{Name: "Host", Value: "aaa"},
		{Name: "Host", Value: "bbb"},
		{Name: "Accept", Value: "*/*"},
	}
	e := &Exchange{Headers: headers}

	got := e.GetHeaders()
	if len(got) != 3 {
		t.Fatalf("GetHeaders() len = %d, want 3", len(got))
	}
	if got[0].Name != "Host" || got[0].Value != "aaa" {
		t.Errorf("GetHeaders()[0] = {%q, %q}, want {Host, aaa}", got[0].Name, got[0].Value)
	}
	if got[1].Name != "Host" || got[1].Value != "bbb" {
		t.Errorf("GetHeaders()[1] = {%q, %q}, want {Host, bbb}", got[1].Name, got[1].Value)
	}
}

func TestGetHeaders_Nil(t *testing.T) {
	e := &Exchange{}
	if got := e.GetHeaders(); got != nil {
		t.Errorf("GetHeaders() on nil = %v, want nil", got)
	}
}

func TestHeaderValues(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Set-Cookie", Value: "a=1"},
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "set-cookie", Value: "b=2"},
			{Name: "SET-COOKIE", Value: "c=3"},
		},
	}

	got := e.HeaderValues("Set-Cookie")
	want := []string{"a=1", "b=2", "c=3"}
	if len(got) != len(want) {
		t.Fatalf("HeaderValues() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("HeaderValues()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHeaderValues_NotFound(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{{Name: "Accept", Value: "*/*"}},
	}
	if got := e.HeaderValues("X-Missing"); got != nil {
		t.Errorf("HeaderValues(missing) = %v, want nil", got)
	}
}

func TestHeaderValues_EmptyHeaders(t *testing.T) {
	e := &Exchange{}
	if got := e.HeaderValues("anything"); got != nil {
		t.Errorf("HeaderValues on empty = %v, want nil", got)
	}
}

func TestSetHeaders_Replace(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
		},
	}

	e.SetHeaders([]KeyValue{
		{Name: "Host", Value: "aaa"},
		{Name: "Host", Value: "bbb"},
		{Name: "Accept", Value: "*/*"},
	})

	if len(e.Headers) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(e.Headers))
	}
	// Duplicate Host headers coexist
	if e.Headers[0].Name != "Host" || e.Headers[0].Value != "aaa" {
		t.Errorf("headers[0] = {%q, %q}, want {Host, aaa}", e.Headers[0].Name, e.Headers[0].Value)
	}
	if e.Headers[1].Name != "Host" || e.Headers[1].Value != "bbb" {
		t.Errorf("headers[1] = {%q, %q}, want {Host, bbb}", e.Headers[1].Name, e.Headers[1].Value)
	}
}

func TestSetHeaders_Nil(t *testing.T) {
	e := &Exchange{
		Headers: []KeyValue{{Name: "X", Value: "1"}},
	}
	e.SetHeaders(nil)
	if e.Headers != nil {
		t.Errorf("SetHeaders(nil) should clear headers, got %v", e.Headers)
	}
}

func TestGetTrailers(t *testing.T) {
	trailers := []KeyValue{
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: "OK"},
	}
	e := &Exchange{Trailers: trailers}

	got := e.GetTrailers()
	if len(got) != 2 {
		t.Fatalf("GetTrailers() len = %d, want 2", len(got))
	}
	if got[0].Name != "grpc-status" || got[1].Name != "grpc-message" {
		t.Errorf("GetTrailers() = %v", got)
	}
}

func TestGetTrailers_Nil(t *testing.T) {
	e := &Exchange{}
	if got := e.GetTrailers(); got != nil {
		t.Errorf("GetTrailers() on nil = %v, want nil", got)
	}
}

func TestTrailerValues(t *testing.T) {
	e := &Exchange{
		Trailers: []KeyValue{
			{Name: "grpc-status", Value: "0"},
			{Name: "Grpc-Status", Value: "14"},
		},
	}
	got := e.TrailerValues("grpc-status")
	if len(got) != 2 || got[0] != "0" || got[1] != "14" {
		t.Errorf("TrailerValues() = %v, want [0, 14]", got)
	}
}

func TestTrailerValues_NotFound(t *testing.T) {
	e := &Exchange{Trailers: []KeyValue{{Name: "grpc-status", Value: "0"}}}
	if got := e.TrailerValues("x-missing"); got != nil {
		t.Errorf("TrailerValues(missing) = %v, want nil", got)
	}
}

func TestSetTrailers(t *testing.T) {
	e := &Exchange{Trailers: []KeyValue{{Name: "old", Value: "val"}}}
	e.SetTrailers([]KeyValue{
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: "OK"},
	})
	if len(e.Trailers) != 2 {
		t.Fatalf("SetTrailers len = %d, want 2", len(e.Trailers))
	}
	if e.Trailers[0].Name != "grpc-status" {
		t.Errorf("Trailers[0] = %v", e.Trailers[0])
	}
}

func TestClone_StreamIDCopied(t *testing.T) {
	orig := &Exchange{
		StreamID: "stream-abc",
		FlowID:   "flow-abc",
	}
	cloned := orig.Clone()

	if cloned.StreamID != "stream-abc" {
		t.Errorf("StreamID = %q, want %q", cloned.StreamID, "stream-abc")
	}
	if cloned.FlowID != "flow-abc" {
		t.Errorf("FlowID = %q, want %q", cloned.FlowID, "flow-abc")
	}

	// StreamID is a string (value type), so mutation of orig should not affect clone
	orig.StreamID = "stream-modified"
	if cloned.StreamID != "stream-abc" {
		t.Error("Clone StreamID affected by mutating original")
	}
}

func TestClone_URLWithUserInfo(t *testing.T) {
	orig := &Exchange{
		StreamID: "flow-url",
		URL:      &url.URL{Scheme: "https", Host: "example.com", User: url.UserPassword("user", "pass")},
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
