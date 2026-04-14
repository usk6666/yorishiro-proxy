package job

import (
	"context"
	"errors"
	"io"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- Mock flow.Reader ---

type mockFlowReader struct {
	streams map[string]*flow.Stream
	flows   map[string][]*flow.Flow
	flowMap map[string]*flow.Flow
	err     error
}

func (r *mockFlowReader) GetStream(_ context.Context, id string) (*flow.Stream, error) {
	if r.err != nil {
		return nil, r.err
	}
	s, ok := r.streams[id]
	if !ok {
		return nil, errors.New("stream not found")
	}
	return s, nil
}

func (r *mockFlowReader) ListStreams(_ context.Context, _ flow.StreamListOptions) ([]*flow.Stream, error) {
	return nil, nil
}

func (r *mockFlowReader) CountStreams(_ context.Context, _ flow.StreamListOptions) (int, error) {
	return 0, nil
}

func (r *mockFlowReader) GetFlow(_ context.Context, id string) (*flow.Flow, error) {
	if r.err != nil {
		return nil, r.err
	}
	f, ok := r.flowMap[id]
	if !ok {
		return nil, errors.New("flow not found")
	}
	return f, nil
}

func (r *mockFlowReader) GetFlows(_ context.Context, streamID string, opts flow.FlowListOptions) ([]*flow.Flow, error) {
	if r.err != nil {
		return nil, r.err
	}
	flows, ok := r.flows[streamID]
	if !ok {
		return nil, nil
	}
	if opts.Direction != "" {
		var filtered []*flow.Flow
		for _, f := range flows {
			if f.Direction == opts.Direction {
				filtered = append(filtered, f)
			}
		}
		return filtered, nil
	}
	return flows, nil
}

func (r *mockFlowReader) CountFlows(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// --- Test helpers ---

func testURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}

func makeSendFlow(method, rawURL string, headers map[string][]string, body []byte) *flow.Flow {
	return &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		Method:    method,
		URL:       testURL(rawURL),
		Headers:   headers,
		Body:      body,
	}
}

// --- HTTPResendSource tests ---

func TestHTTPResendSource_BasicResend(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/path?q=1",
		map[string][]string{"Host": {"example.com"}, "Accept": {"*/*"}},
		nil,
	)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.Direction != envelope.Send {
		t.Errorf("Direction: got %v, want Send", env.Direction)
	}
	if env.Protocol != envelope.ProtocolHTTP {
		t.Errorf("Protocol: got %v, want %v", env.Protocol, envelope.ProtocolHTTP)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type: got %T, want *HTTPMessage", env.Message)
	}
	if msg.Method != "GET" {
		t.Errorf("Method: got %q, want %q", msg.Method, "GET")
	}
	if msg.Scheme != "https" {
		t.Errorf("Scheme: got %q, want %q", msg.Scheme, "https")
	}
	if msg.Authority != "example.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "example.com")
	}
	if msg.Path != "/path" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/path")
	}
	if msg.RawQuery != "q=1" {
		t.Errorf("RawQuery: got %q, want %q", msg.RawQuery, "q=1")
	}
}

func TestHTTPResendSource_MethodOverride(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/", nil, nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		Method: "POST",
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Method != "POST" {
		t.Errorf("Method: got %q, want %q", msg.Method, "POST")
	}
}

func TestHTTPResendSource_URLOverride(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/old?a=1", nil, nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		URL: "https://other.com/new?b=2",
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Scheme != "https" {
		t.Errorf("Scheme: got %q, want %q", msg.Scheme, "https")
	}
	if msg.Authority != "other.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "other.com")
	}
	if msg.Path != "/new" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/new")
	}
	if msg.RawQuery != "b=2" {
		t.Errorf("RawQuery: got %q, want %q", msg.RawQuery, "b=2")
	}
}

func TestHTTPResendSource_URLOverride_NoScheme(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/old", nil, nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		URL: "other.com/new",
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	// Should preserve original scheme when override has no scheme.
	if msg.Scheme != "https" {
		t.Errorf("Scheme: got %q, want %q (preserved from original)", msg.Scheme, "https")
	}
	if msg.Authority != "other.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "other.com")
	}
	if msg.Path != "/new" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/new")
	}
}

func TestHTTPResendSource_HeaderOverride(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/",
		map[string][]string{
			"Host":         {"example.com"},
			"Content-Type": {"text/plain"},
			"Accept":       {"*/*"},
		},
		nil,
	)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer token123",
		},
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)

	// Content-Type should be replaced.
	foundCT := false
	foundAuth := false
	for _, kv := range msg.Headers {
		if kv.Name == "Content-Type" {
			if kv.Value != "application/json" {
				t.Errorf("Content-Type: got %q, want %q", kv.Value, "application/json")
			}
			foundCT = true
		}
		if kv.Name == "Authorization" {
			if kv.Value != "Bearer token123" {
				t.Errorf("Authorization: got %q, want %q", kv.Value, "Bearer token123")
			}
			foundAuth = true
		}
	}
	if !foundCT {
		t.Error("Content-Type header not found")
	}
	if !foundAuth {
		t.Error("Authorization header should be appended")
	}
}

func TestHTTPResendSource_BodyOverride(t *testing.T) {
	sendFlow := makeSendFlow("POST", "https://example.com/",
		nil, []byte("original body"),
	)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	newBody := []byte("new body content")
	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		Body:    newBody,
		BodySet: true,
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "new body content" {
		t.Errorf("Body: got %q, want %q", msg.Body, "new body content")
	}
}

func TestHTTPResendSource_BodyOverride_Empty(t *testing.T) {
	sendFlow := makeSendFlow("POST", "https://example.com/",
		nil, []byte("original body"),
	)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{
		Body:    []byte{},
		BodySet: true,
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if len(msg.Body) != 0 {
		t.Errorf("Body: got %q, want empty", msg.Body)
	}
}

func TestHTTPResendSource_SecondCallReturnsEOF(t *testing.T) {
	sendFlow := makeSendFlow("GET", "https://example.com/", nil, nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{})

	_, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	_, err = src.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("second call: got %v, want io.EOF", err)
	}
}

func TestHTTPResendSource_NoSendFlow(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {
				{ID: "f1", StreamID: "stream-1", Direction: "receive"},
			},
		},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{})
	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("expected error for missing send flow")
	}
}

func TestHTTPResendSource_ReaderError(t *testing.T) {
	reader := &mockFlowReader{
		err: errors.New("db error"),
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{})
	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("expected error from reader")
	}
}

func TestHTTPResendSource_NilURL(t *testing.T) {
	sendFlow := &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		Method:    "GET",
		URL:       nil,
	}
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{"stream-1": {sendFlow}},
	}

	src := NewHTTPResendSource(reader, "stream-1", HTTPResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Scheme != "http" {
		t.Errorf("Scheme: got %q, want %q (default)", msg.Scheme, "http")
	}
	if msg.Path != "/" {
		t.Errorf("Path: got %q, want %q (default)", msg.Path, "/")
	}
}

// --- parseOverrideURL tests ---

func TestParseOverrideURL(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		defScheme string
		wantSch   string
		wantAuth  string
		wantPath  string
		wantQuery string
	}{
		{
			name:      "full URL",
			rawURL:    "https://example.com/path?q=1",
			defScheme: "http",
			wantSch:   "https",
			wantAuth:  "example.com",
			wantPath:  "/path",
			wantQuery: "q=1",
		},
		{
			name:      "no scheme",
			rawURL:    "example.com/path",
			defScheme: "https",
			wantSch:   "https",
			wantAuth:  "example.com",
			wantPath:  "/path",
		},
		{
			name:      "host only",
			rawURL:    "example.com",
			defScheme: "http",
			wantSch:   "http",
			wantAuth:  "example.com",
			wantPath:  "/",
		},
		{
			name:      "with port",
			rawURL:    "http://localhost:8080/api",
			defScheme: "https",
			wantSch:   "http",
			wantAuth:  "localhost:8080",
			wantPath:  "/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sch, auth, path, query := parseOverrideURL(tt.rawURL, tt.defScheme)
			if sch != tt.wantSch {
				t.Errorf("scheme: got %q, want %q", sch, tt.wantSch)
			}
			if auth != tt.wantAuth {
				t.Errorf("authority: got %q, want %q", auth, tt.wantAuth)
			}
			if path != tt.wantPath {
				t.Errorf("path: got %q, want %q", path, tt.wantPath)
			}
			if query != tt.wantQuery {
				t.Errorf("query: got %q, want %q", query, tt.wantQuery)
			}
		})
	}
}

// --- applyHeaderOverrides tests ---

func TestApplyHeaderOverrides_ReplaceExisting(t *testing.T) {
	base := []envelope.KeyValue{
		{Name: "Host", Value: "old.com"},
		{Name: "Accept", Value: "*/*"},
	}
	overrides := map[string]string{
		"host": "new.com", // case-insensitive match
	}

	result := applyHeaderOverrides(base, overrides)
	if len(result) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result))
	}
	if result[0].Name != "Host" || result[0].Value != "new.com" {
		t.Errorf("first header: got %v, want Host:new.com", result[0])
	}
	if result[1].Name != "Accept" || result[1].Value != "*/*" {
		t.Errorf("second header preserved: got %v", result[1])
	}
}

func TestApplyHeaderOverrides_AppendNew(t *testing.T) {
	base := []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
	}
	overrides := map[string]string{
		"Authorization": "Bearer xyz",
	}

	result := applyHeaderOverrides(base, overrides)
	if len(result) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result))
	}
	if result[1].Name != "Authorization" || result[1].Value != "Bearer xyz" {
		t.Errorf("appended header: got %v", result[1])
	}
}

func TestApplyHeaderOverrides_RemoveDuplicates(t *testing.T) {
	base := []envelope.KeyValue{
		{Name: "Cookie", Value: "a=1"},
		{Name: "Cookie", Value: "b=2"},
	}
	overrides := map[string]string{
		"Cookie": "c=3",
	}

	result := applyHeaderOverrides(base, overrides)
	if len(result) != 1 {
		t.Fatalf("expected 1 header (duplicates collapsed), got %d", len(result))
	}
	if result[0].Value != "c=3" {
		t.Errorf("cookie value: got %q, want %q", result[0].Value, "c=3")
	}
}
