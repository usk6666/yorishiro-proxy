package job

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// --- sendRequestToEnvelope tests ---

func TestSendRequestToEnvelope(t *testing.T) {
	req := &macro.SendRequest{
		Method: "POST",
		URL:    "https://example.com/api?key=val",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Accept":       {"*/*"},
		},
		Body: []byte(`{"data":"test"}`),
	}

	env := sendRequestToEnvelope(req)

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
	if msg.Method != "POST" {
		t.Errorf("Method: got %q, want %q", msg.Method, "POST")
	}
	if msg.Scheme != "https" {
		t.Errorf("Scheme: got %q, want %q", msg.Scheme, "https")
	}
	if msg.Authority != "example.com" {
		t.Errorf("Authority: got %q, want %q", msg.Authority, "example.com")
	}
	if msg.Path != "/api" {
		t.Errorf("Path: got %q, want %q", msg.Path, "/api")
	}
	if msg.RawQuery != "key=val" {
		t.Errorf("RawQuery: got %q, want %q", msg.RawQuery, "key=val")
	}
	if string(msg.Body) != `{"data":"test"}` {
		t.Errorf("Body: got %q", msg.Body)
	}
}

// --- envelopeToSendResponse tests ---

func TestEnvelopeToSendResponse(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:    200,
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/api",
			RawQuery:  "key=val",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/json"},
				{Name: "Set-Cookie", Value: "a=1"},
				{Name: "Set-Cookie", Value: "b=2"},
			},
			Body: []byte(`{"result":"ok"}`),
		},
	}

	resp, err := envelopeToSendResponse(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode: got %d, want 200", resp.StatusCode)
	}
	if resp.URL != "https://example.com/api?key=val" {
		t.Errorf("URL: got %q", resp.URL)
	}
	if string(resp.Body) != `{"result":"ok"}` {
		t.Errorf("Body: got %q", resp.Body)
	}

	// Check headers converted to http.Header.
	if ct := resp.Headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q", ct)
	}
	cookies := resp.Headers.Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Errorf("Set-Cookie count: got %d, want 2", len(cookies))
	}
}

func TestEnvelopeToSendResponse_NonHTTP(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("raw")},
	}

	_, err := envelopeToSendResponse(env)
	if err == nil {
		t.Fatal("expected error for non-HTTP message")
	}
}

// --- MacroSendFuncAdapter tests ---

func TestMacroSendFuncAdapter_BasicRoundTrip(t *testing.T) {
	respEnv := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:    200,
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/",
			Headers:   []envelope.KeyValue{{Name: "X-Test", Value: "ok"}},
			Body:      []byte("response body"),
		},
	}

	ch := &mockChannel{
		streamID:  "upstream",
		responses: []*envelope.Envelope{respEnv},
	}

	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return ch, nil
	}

	sendFn := MacroSendFuncAdapter(dialFn, nil)

	req := &macro.SendRequest{
		Method:  "GET",
		URL:     "https://example.com/",
		Headers: map[string][]string{"Host": {"example.com"}},
	}

	resp, err := sendFn(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "response body" {
		t.Errorf("Body: got %q", resp.Body)
	}
	if len(ch.sent) != 1 {
		t.Errorf("sent count: got %d, want 1", len(ch.sent))
	}
	if !ch.closed {
		t.Error("channel should be closed after send")
	}
}

func TestMacroSendFuncAdapter_WithPipeline(t *testing.T) {
	respEnv := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:    200,
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/",
		},
	}

	pipelineRan := 0
	countStep := &countingStep{count: &pipelineRan}
	p := pipeline.New(countStep)

	ch := &mockChannel{
		streamID:  "upstream",
		responses: []*envelope.Envelope{respEnv},
	}
	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return ch, nil
	}

	sendFn := MacroSendFuncAdapter(dialFn, p)
	req := &macro.SendRequest{
		Method: "GET",
		URL:    "https://example.com/",
	}

	_, err := sendFn(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pipeline should run twice: once for request, once for response.
	if pipelineRan != 2 {
		t.Errorf("pipeline ran %d times, want 2", pipelineRan)
	}
}

func TestMacroSendFuncAdapter_DialError(t *testing.T) {
	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return nil, errors.New("connection refused")
	}

	sendFn := MacroSendFuncAdapter(dialFn, nil)
	req := &macro.SendRequest{Method: "GET", URL: "https://example.com/"}

	_, err := sendFn(context.Background(), req)
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestMacroSendFuncAdapter_SendError(t *testing.T) {
	ch := &mockChannel{
		streamID: "upstream",
		sendErr:  errors.New("write failed"),
	}
	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return ch, nil
	}

	sendFn := MacroSendFuncAdapter(dialFn, nil)
	req := &macro.SendRequest{Method: "GET", URL: "https://example.com/"}

	_, err := sendFn(context.Background(), req)
	if err == nil {
		t.Fatal("expected send error")
	}
}

func TestMacroSendFuncAdapter_NextError(t *testing.T) {
	ch := &mockChannel{
		streamID: "upstream",
		nextErr:  errors.New("read failed"),
	}
	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return ch, nil
	}

	sendFn := MacroSendFuncAdapter(dialFn, nil)
	req := &macro.SendRequest{Method: "GET", URL: "https://example.com/"}

	_, err := sendFn(context.Background(), req)
	if err == nil {
		t.Fatal("expected next error")
	}
}

// --- FlowFetcherAdapter tests ---

func TestFlowFetcherAdapter_ByStreamID(t *testing.T) {
	sendFlow := &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		Method:    "POST",
		URL: &url.URL{
			Scheme:   "https",
			Host:     "example.com",
			Path:     "/api",
			RawQuery: "q=1",
		},
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(`{"key":"val"}`),
	}

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	adapter := NewFlowFetcherAdapter(reader)
	req, err := adapter.GetFlowRequest(context.Background(), "stream-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method: got %q, want %q", req.Method, "POST")
	}
	if req.URL != "https://example.com/api?q=1" {
		t.Errorf("URL: got %q", req.URL)
	}
	if req.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("Content-Type: got %v", req.Headers["Content-Type"])
	}
	if string(req.Body) != `{"key":"val"}` {
		t.Errorf("Body: got %q", req.Body)
	}
}

func TestFlowFetcherAdapter_FallbackToFlowID(t *testing.T) {
	individualFlow := &flow.Flow{
		ID:        "flow-42",
		StreamID:  "stream-99",
		Direction: "send",
		Method:    "GET",
		URL:       &url.URL{Scheme: "https", Host: "test.com", Path: "/"},
	}

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			// No send flows for "flow-42" as a stream ID.
		},
		flowMap: map[string]*flow.Flow{
			"flow-42": individualFlow,
		},
	}

	adapter := NewFlowFetcherAdapter(reader)
	req, err := adapter.GetFlowRequest(context.Background(), "flow-42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method: got %q, want %q", req.Method, "GET")
	}
}

func TestFlowFetcherAdapter_NotFound(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{},
		err:   errors.New("not found"),
	}

	adapter := NewFlowFetcherAdapter(reader)
	_, err := adapter.GetFlowRequest(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent flow")
	}
}

// --- parseMacroURL tests ---

func TestParseMacroURL(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		wantSch   string
		wantAuth  string
		wantPath  string
		wantQuery string
	}{
		{
			name:      "full HTTPS",
			rawURL:    "https://example.com/path?q=1",
			wantSch:   "https",
			wantAuth:  "example.com",
			wantPath:  "/path",
			wantQuery: "q=1",
		},
		{
			name:      "HTTP",
			rawURL:    "http://localhost:8080/api",
			wantSch:   "http",
			wantAuth:  "localhost:8080",
			wantPath:  "/api",
			wantQuery: "",
		},
		{
			name:     "no scheme defaults to https",
			rawURL:   "example.com/path",
			wantSch:  "https",
			wantAuth: "example.com",
			wantPath: "/path",
		},
		{
			name:     "host only",
			rawURL:   "example.com",
			wantSch:  "https",
			wantAuth: "example.com",
			wantPath: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sch, auth, path, query := parseMacroURL(tt.rawURL)
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

// --- countingStep tracks how many times Pipeline.Run processes it ---

type countingStep struct {
	count *int
}

func (s *countingStep) Process(_ context.Context, _ *envelope.Envelope) pipeline.Result {
	*s.count++
	return pipeline.Result{}
}

// --- Verify mock implements interface ---

var _ macro.FlowFetcher = (*FlowFetcherAdapter)(nil)

// Verify that MacroSendFuncAdapter returns a macro.SendFunc.
var _ macro.SendFunc = MacroSendFuncAdapter(nil, nil)
