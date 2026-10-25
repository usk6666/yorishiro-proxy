package mcp

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// Tests for USK-1343: the top level of `query resource=flow` (and the
// method / url / status_code of `query resource=flows`) is the head
// message of each direction — the upgrade / start message for streaming
// flows — and original_request / original_response appear only when the
// head itself has a variant=original / variant=modified pair.
//
// The pipeline-driven tests below record envelopes through the real
// pipeline.RecordStep (the sole producer of variant rows) so the stored
// row layout is the one the live data path produces, then read it back
// through the MCP query tool over an in-memory JSON-RPC session.

// mutateStep is a test-local pipeline.Step that applies fn to every
// envelope matching match. It stands in for an Intercept / Transform
// modification: RecordStep diffs the envelope against the pipeline's
// pre-Step snapshot and records the original / modified variant pair.
type mutateStep struct {
	match func(env *envelope.Envelope) bool
	fn    func(env *envelope.Envelope)
}

func (s mutateStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if s.match(env) {
		s.fn(env)
	}
	return pipeline.Result{}
}

// recordThroughPipeline runs each envelope through
// mutateStep → RecordStep into store.
func recordThroughPipeline(t *testing.T, store flow.Store, step mutateStep, envs []*envelope.Envelope) {
	t.Helper()
	p := pipeline.New(step, pipeline.NewRecordStep(store, testutil.DiscardLogger()))
	for _, env := range envs {
		if _, action, _ := p.Run(context.Background(), env); action == pipeline.Drop {
			t.Fatalf("pipeline dropped envelope seq=%d dir=%v", env.Sequence, env.Direction)
		}
	}
}

func noMutation() mutateStep {
	return mutateStep{
		match: func(*envelope.Envelope) bool { return false },
		fn:    func(*envelope.Envelope) {},
	}
}

// wsH1Envelopes returns the envelope sequence an HTTP/1.1 WebSocket
// session produces (session.go: Send seq0 = Upgrade GET, Receive seq1 =
// 101, frames numbered from seq2 on the same StreamID).
func wsH1Envelopes(streamID string) []*envelope.Envelope {
	getRaw := []byte("GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	respRaw := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
	envs := []*envelope.Envelope{
		{
			StreamID: streamID, FlowID: streamID + "-0", Sequence: 0,
			Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Raw: getRaw,
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "example.com", Path: "/chat",
				HTTPVersion: "http/1.1",
				Headers: []envelope.KeyValue{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
					{Name: "Sec-WebSocket-Key", Value: "dGhlIHNhbXBsZSBub25jZQ=="},
					{Name: "Sec-WebSocket-Version", Value: "13"},
				},
			},
		},
		{
			StreamID: streamID, FlowID: streamID + "-1", Sequence: 1,
			Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP, Raw: respRaw,
			Message: &envelope.HTTPMessage{
				Status: 101, StatusReason: "Switching Protocols", HTTPVersion: "http/1.1",
				Headers: []envelope.KeyValue{
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
					{Name: "Sec-WebSocket-Accept", Value: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
				},
			},
		},
	}
	frames := []struct {
		dir     envelope.Direction
		opcode  envelope.WSOpcode
		payload string
	}{
		{envelope.Send, envelope.WSText, "hello"},
		{envelope.Receive, envelope.WSText, "hello"},
		{envelope.Send, envelope.WSText, "secret"},
		{envelope.Receive, envelope.WSText, "secret"},
		{envelope.Send, envelope.WSClose, ""},
		{envelope.Receive, envelope.WSClose, ""},
	}
	for i, f := range frames {
		seq := i + 2
		envs = append(envs, &envelope.Envelope{
			StreamID: streamID, FlowID: streamID + "-f" + string(rune('a'+i)), Sequence: seq,
			Direction: f.dir, Protocol: envelope.ProtocolWebSocket,
			Raw:     append([]byte{0x81, byte(len(f.payload))}, f.payload...),
			Message: &envelope.WSMessage{Opcode: f.opcode, Fin: true, Payload: []byte(f.payload)},
		})
	}
	return envs
}

// queryFlowDetail runs `query resource=flow` for id over cs.
func queryFlowDetail(t *testing.T, cs *gomcp.ClientSession, id string, filter *queryFilter) queryFlowResult {
	t.Helper()
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: id, Filter: filter})
	if result.IsError {
		t.Fatalf("query flow %s: error %v", id, result.Content)
	}
	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)
	return out
}

// TestQueryFlow_WSModifiedFrame_TopLevelIsUpgrade covers a WebSocket flow
// whose non-head frame (seq 4) was modified: RecordStep records a
// variant=original / variant=modified pair at seq 4. The top level must
// still be the Upgrade GET / 101 and there must be no original_* (the
// pair is not at the head); both variant rows stay visible via messages.
func TestQueryFlow_WSModifiedFrame_TopLevelIsUpgrade(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "ws-mod-frame"
	recordThroughPipeline(t, store, mutateStep{
		match: func(env *envelope.Envelope) bool { return env.Sequence == 4 && env.Direction == envelope.Send },
		fn: func(env *envelope.Envelope) {
			env.Message.(*envelope.WSMessage).Payload = []byte("patched")
		},
	}, wsH1Envelopes(id))

	cs := setupQueryTestSession(t, store)
	out := queryFlowDetail(t, cs, id, nil)

	if out.OriginalRequest != nil {
		t.Errorf("original_request = %+v, want nil (the variant pair is on a non-head frame)", out.OriginalRequest)
	}
	if out.OriginalResponse != nil {
		t.Errorf("original_response = %+v, want nil", out.OriginalResponse)
	}
	if out.Method != "GET" {
		t.Errorf("method = %q, want GET (Upgrade request)", out.Method)
	}
	if out.URL != "https://example.com/chat" {
		t.Errorf("url = %q, want https://example.com/chat", out.URL)
	}
	if got := out.RequestHeaders["Upgrade"]; len(got) != 1 || got[0] != "websocket" {
		t.Errorf("request_headers[Upgrade] = %v, want [websocket]", got)
	}
	if out.ResponseStatusCode != 101 {
		t.Errorf("response_status_code = %d, want 101", out.ResponseStatusCode)
	}
	if out.RequestBody != "" {
		t.Errorf("request_body = %q, want empty (Upgrade GET has no body)", out.RequestBody)
	}
	if len(out.MessagePreview) == 0 {
		t.Errorf("message_preview is empty, want the WS frames")
	}

	// Both variant rows of the modified frame are visible via messages.
	res := callQuery(t, cs, queryInput{Resource: "messages", ID: id})
	if res.IsError {
		t.Fatalf("query messages: %v", res.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, res, &msgs)
	variants := map[string]string{}
	for _, m := range msgs.Messages {
		if m.Sequence == 4 && m.Direction == "send" {
			variants[m.Metadata["variant"]] = m.Body
		}
	}
	if variants["original"] != "secret" || variants["modified"] != "patched" {
		t.Errorf("seq 4 send variants = %v, want original=secret modified=patched", variants)
	}
}

// TestQueryFlow_UnmodifiedWS_NoOriginal is the unit-seam twin of the e2e
// reproduction: an unmodified WS flow has no original_* and its top level
// is the Upgrade GET / 101, not the last Close frames.
func TestQueryFlow_UnmodifiedWS_NoOriginal(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "ws-unmodified"
	recordThroughPipeline(t, store, noMutation(), wsH1Envelopes(id))

	out := queryFlowDetail(t, setupQueryTestSession(t, store), id, nil)
	if out.OriginalRequest != nil || out.OriginalResponse != nil {
		t.Errorf("original_request=%+v original_response=%+v, want both nil", out.OriginalRequest, out.OriginalResponse)
	}
	if out.Method != "GET" || out.ResponseStatusCode != 101 {
		t.Errorf("method=%q status=%d, want GET / 101", out.Method, out.ResponseStatusCode)
	}
	if out.RawRequest == "" || out.RawResponse == "" {
		t.Fatalf("raw_request / raw_response empty")
	}
}

// TestQueryFlows_WSModifiedFrame_ListShowsUpgrade: the flows list and the
// flow detail must agree — a WS stream with a modified frame lists as
// GET / 101.
func TestQueryFlows_WSModifiedFrame_ListShowsUpgrade(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "ws-list-mod"
	recordThroughPipeline(t, store, mutateStep{
		match: func(env *envelope.Envelope) bool { return env.Sequence >= 4 },
		fn: func(env *envelope.Envelope) {
			if m, ok := env.Message.(*envelope.WSMessage); ok && m.Opcode == envelope.WSText {
				m.Payload = []byte("patched")
			}
		},
	}, wsH1Envelopes(id))

	cs := setupQueryTestSession(t, store)
	res := callQuery(t, cs, queryInput{Resource: "flows"})
	if res.IsError {
		t.Fatalf("query flows: %v", res.Content)
	}
	var list queryFlowsResult
	unmarshalQueryResult(t, res, &list)
	if len(list.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(list.Flows))
	}
	e := list.Flows[0]
	if e.Method != "GET" || e.StatusCode != 101 || e.URL != "https://example.com/chat" {
		t.Errorf("flows entry method=%q url=%q status=%d, want GET https://example.com/chat 101", e.Method, e.URL, e.StatusCode)
	}
}

// TestQueryFlow_HTTPHeadVariant_StillEmitsOriginal is the regression
// guard for intercept-modified HTTP request / response: the head has a
// variant pair, so the top level is the modified variant and original_*
// is the original.
func TestQueryFlow_HTTPHeadVariant_StillEmitsOriginal(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "http-head-variant"
	envs := []*envelope.Envelope{
		{
			StreamID: id, FlowID: id + "-req", Sequence: 0, Direction: envelope.Send,
			Protocol: envelope.ProtocolHTTP,
			Raw:      []byte("POST /orig HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\norig"),
			Message: &envelope.HTTPMessage{
				Method: "POST", Scheme: "http", Authority: "example.com", Path: "/orig",
				HTTPVersion: "http/1.1",
				Headers:     []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
				Body:        []byte("orig"),
			},
		},
		{
			StreamID: id, FlowID: id + "-resp", Sequence: 1, Direction: envelope.Receive,
			Protocol: envelope.ProtocolHTTP,
			Raw:      []byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nupresp"),
			Message: &envelope.HTTPMessage{
				Status: 200, HTTPVersion: "http/1.1",
				Headers: []envelope.KeyValue{{Name: "Content-Length", Value: "6"}},
				Body:    []byte("upresp"),
			},
		},
	}
	recordThroughPipeline(t, store, mutateStep{
		match: func(*envelope.Envelope) bool { return true },
		fn: func(env *envelope.Envelope) {
			m := env.Message.(*envelope.HTTPMessage)
			if env.Direction == envelope.Send {
				m.Path = "/mod"
				m.Body = []byte("modified")
			} else {
				m.Status = 403
				m.Body = []byte("blocked")
			}
		},
	}, envs)

	out := queryFlowDetail(t, setupQueryTestSession(t, store), id, nil)
	if out.URL != "http://example.com/mod" || out.RequestBody != "modified" {
		t.Errorf("top-level url=%q body=%q, want the modified request", out.URL, out.RequestBody)
	}
	if out.OriginalRequest == nil {
		t.Fatal("original_request is nil, want the original request")
	}
	if out.OriginalRequest.URL != "http://example.com/orig" || out.OriginalRequest.Body != "orig" {
		t.Errorf("original_request url=%q body=%q, want http://example.com/orig / orig", out.OriginalRequest.URL, out.OriginalRequest.Body)
	}
	if out.ResponseStatusCode != 403 || out.ResponseBody != "blocked" {
		t.Errorf("top-level status=%d body=%q, want the modified 403 / blocked", out.ResponseStatusCode, out.ResponseBody)
	}
	if out.OriginalResponse == nil {
		t.Fatal("original_response is nil, want the original response")
	}
	if out.OriginalResponse.StatusCode != 200 || out.OriginalResponse.Body != "upresp" {
		t.Errorf("original_response status=%d body=%q, want 200 / upresp", out.OriginalResponse.StatusCode, out.OriginalResponse.Body)
	}
}

// TestQueryFlow_HTTPInformational_NoFakeOriginal: an HTTP exchange whose
// upstream sent 100 Continue before the final 200 (the HTTP/1.x Layer
// records the 1xx at Receive seq1 and the final response at seq2). The
// 1xx is not an "original" response and the top level is the final 200.
func TestQueryFlow_HTTPInformational_NoFakeOriginal(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "http-100-continue"
	envs := []*envelope.Envelope{
		{
			StreamID: id, FlowID: id + "-req", Sequence: 0, Direction: envelope.Send,
			Protocol: envelope.ProtocolHTTP,
			Raw:      []byte("POST /up HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi"),
			Message: &envelope.HTTPMessage{
				Method: "POST", Scheme: "http", Authority: "example.com", Path: "/up",
				HTTPVersion: "http/1.1",
				Headers:     []envelope.KeyValue{{Name: "Host", Value: "example.com"}, {Name: "Expect", Value: "100-continue"}},
				Body:        []byte("hi"),
			},
		},
		{
			StreamID: id, FlowID: id + "-100", Sequence: 1, Direction: envelope.Receive,
			Protocol: envelope.ProtocolHTTP,
			Raw:      []byte("HTTP/1.1 100 Continue\r\n\r\n"),
			Message:  &envelope.HTTPMessage{Status: 100, StatusReason: "Continue", HTTPVersion: "http/1.1"},
		},
		{
			StreamID: id, FlowID: id + "-200", Sequence: 2, Direction: envelope.Receive,
			Protocol: envelope.ProtocolHTTP,
			Raw:      []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
			Message: &envelope.HTTPMessage{
				Status: 200, StatusReason: "OK", HTTPVersion: "http/1.1",
				Headers: []envelope.KeyValue{{Name: "Content-Length", Value: "2"}},
				Body:    []byte("ok"),
			},
		},
	}
	recordThroughPipeline(t, store, noMutation(), envs)

	out := queryFlowDetail(t, setupQueryTestSession(t, store), id, nil)
	if out.OriginalResponse != nil {
		t.Errorf("original_response = %+v, want nil (a 1xx is not an original variant)", out.OriginalResponse)
	}
	if out.ResponseStatusCode != 200 || out.ResponseBody != "ok" {
		t.Errorf("response status=%d body=%q, want the final 200 / ok", out.ResponseStatusCode, out.ResponseBody)
	}
}

// TestQueryFlow_RawChunks_HeadIsFirstChunk: a Raw TCP stream with several
// chunks each way has no original_* and its top level raw bytes are the
// first chunk of each direction.
func TestQueryFlow_RawChunks_HeadIsFirstChunk(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	const id = "raw-chunks"
	chunks := []struct {
		dir  envelope.Direction
		data string
	}{
		{envelope.Send, "HELO a\r\n"},
		{envelope.Receive, "250 hi\r\n"},
		{envelope.Send, "MAIL FROM:<x>\r\n"},
		{envelope.Receive, "250 ok\r\n"},
		{envelope.Send, "QUIT\r\n"},
		{envelope.Receive, "221 bye\r\n"},
	}
	var envs []*envelope.Envelope
	for i, c := range chunks {
		envs = append(envs, &envelope.Envelope{
			StreamID: id, FlowID: id + "-" + string(rune('a'+i)), Sequence: i,
			Direction: c.dir, Protocol: envelope.ProtocolRaw, Raw: []byte(c.data),
			Message: &envelope.RawMessage{Bytes: []byte(c.data)},
		})
	}
	recordThroughPipeline(t, store, noMutation(), envs)

	out := queryFlowDetail(t, setupQueryTestSession(t, store), id, nil)
	if out.OriginalRequest != nil || out.OriginalResponse != nil {
		t.Errorf("original_request=%+v original_response=%+v, want both nil", out.OriginalRequest, out.OriginalResponse)
	}
	if out.RawRequest != b64(chunks[0].data) {
		t.Errorf("raw_request = %q, want first send chunk %q", out.RawRequest, b64(chunks[0].data))
	}
	if out.RawResponse != b64(chunks[1].data) {
		t.Errorf("raw_response = %q, want first receive chunk %q", out.RawResponse, b64(chunks[1].data))
	}
}

// TestQueryFlow_WireLevelAll_TopLevelFromSemantic: with
// filter.wire_level="all", overlay rows join message_preview but the top
// level is still computed from the semantic head rows, and no original_*
// is fabricated.
func TestQueryFlow_WireLevelAll_TopLevelFromSemantic(t *testing.T) {
	t.Parallel()
	for _, wl := range []string{"all", "h2-frame"} {
		wl := wl
		t.Run(wl, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			id, _, _, _ := seedFlowWithMixedWireLevels(t, store, "mixed-wl-head-"+wl)
			out := queryFlowDetail(t, setupQueryTestSession(t, store), id, &queryFilter{WireLevel: wl})
			if out.OriginalRequest != nil || out.OriginalResponse != nil {
				t.Errorf("original_request=%+v original_response=%+v, want both nil", out.OriginalRequest, out.OriginalResponse)
			}
			if out.Method != "POST" || out.URL != "http://example.com/svc.Echo/Unary" {
				t.Errorf("method=%q url=%q, want the semantic Send Start (POST http://example.com/svc.Echo/Unary)", out.Method, out.URL)
			}
			if out.ResponseStatusCode != 200 {
				t.Errorf("response_status_code = %d, want 200 (semantic Receive Start)", out.ResponseStatusCode)
			}
			if out.RawRequest != "" || out.RawResponse != "" {
				t.Errorf("raw_request=%q raw_response=%q, want empty (semantic Start rows carry no raw; overlay rows must not leak in)", out.RawRequest, out.RawResponse)
			}
		})
	}
}

// TestResolveHeadPair is the table test for the pure head-selection
// helper.
func TestResolveHeadPair(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("http://example.com/")
	now := time.Now()
	mk := func(id string, seq int, dir string, status int, md map[string]string, wl string) *flow.Flow {
		if md == nil {
			md = map[string]string{}
		}
		return &flow.Flow{ID: id, Sequence: seq, Direction: dir, StatusCode: status, Metadata: md, WireLevel: wl, Timestamp: now, URL: u}
	}
	httpMD := func(kv ...string) map[string]string {
		m := map[string]string{"protocol": "http"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	tests := []struct {
		name         string
		msgs         []*flow.Flow
		dir          string
		wantEff      string
		wantOriginal string
	}{
		{name: "empty", msgs: nil, dir: "send"},
		{
			name:    "single row",
			msgs:    []*flow.Flow{mk("s0", 0, "send", 0, nil, "")},
			dir:     "send",
			wantEff: "s0",
		},
		{
			name: "streaming rows without variants pick the lowest sequence",
			msgs: []*flow.Flow{
				mk("s0", 0, "send", 0, httpMD(), "semantic"),
				mk("s2", 2, "send", 0, map[string]string{"protocol": "ws"}, "semantic"),
				mk("s4", 4, "send", 0, map[string]string{"protocol": "ws"}, "semantic"),
			},
			dir:     "send",
			wantEff: "s0",
		},
		{
			name: "head variant pair",
			msgs: []*flow.Flow{
				mk("s0o", 0, "send", 0, httpMD("variant", "original"), "semantic"),
				mk("s0m", 0, "send", 0, httpMD("variant", "modified"), "semantic"),
				mk("s2", 2, "send", 0, nil, "semantic"),
			},
			dir:          "send",
			wantEff:      "s0m",
			wantOriginal: "s0o",
		},
		{
			name: "non-head variant pair is not the head",
			msgs: []*flow.Flow{
				mk("s0", 0, "send", 0, httpMD(), "semantic"),
				mk("s4o", 4, "send", 0, map[string]string{"variant": "original"}, "semantic"),
				mk("s4m", 4, "send", 0, map[string]string{"variant": "modified"}, "semantic"),
			},
			dir:     "send",
			wantEff: "s0",
		},
		{
			name: "1xx then final response",
			msgs: []*flow.Flow{
				mk("r1", 1, "receive", 100, httpMD(), "semantic"),
				mk("r2", 2, "receive", 200, httpMD(), "semantic"),
			},
			dir:     "receive",
			wantEff: "r2",
		},
		{
			name: "103 and 100 then final",
			msgs: []*flow.Flow{
				mk("r1", 1, "receive", 103, httpMD(), "semantic"),
				mk("r2", 2, "receive", 100, httpMD(), "semantic"),
				mk("r3", 3, "receive", 204, httpMD(), "semantic"),
			},
			dir:     "receive",
			wantEff: "r3",
		},
		{
			name: "101 is the head, not skipped",
			msgs: []*flow.Flow{
				mk("r1", 1, "receive", 101, httpMD(), "semantic"),
				mk("r3", 3, "receive", 0, map[string]string{"protocol": "ws"}, "semantic"),
			},
			dir:     "receive",
			wantEff: "r1",
		},
		{
			name: "all 1xx uses the last",
			msgs: []*flow.Flow{
				mk("r1", 1, "receive", 100, httpMD(), "semantic"),
				mk("r2", 2, "receive", 103, httpMD(), "semantic"),
			},
			dir:     "receive",
			wantEff: "r2",
		},
		{
			name: "1xx skip is HTTP-only",
			msgs: []*flow.Flow{
				mk("r0", 0, "receive", 150, map[string]string{"protocol": "raw"}, "semantic"),
				mk("r1", 1, "receive", 0, map[string]string{"protocol": "raw"}, "semantic"),
			},
			dir:     "receive",
			wantEff: "r0",
		},
		{
			name: "overlay rows ignored",
			msgs: []*flow.Flow{
				mk("o0", 0, "send", 0, nil, "h2-frame"),
				mk("s1", 1, "send", 0, nil, "semantic"),
				mk("o2", 2, "send", 0, nil, "grpc-lpm-frame"),
			},
			dir:     "send",
			wantEff: "s1",
		},
		{
			name: "only overlay rows",
			msgs: []*flow.Flow{
				mk("o0", 0, "send", 0, nil, "h2-frame"),
			},
			dir: "send",
		},
		{
			name: "other direction ignored",
			msgs: []*flow.Flow{
				mk("r0", 0, "receive", 200, httpMD(), ""),
				mk("s0", 0, "send", 0, httpMD(), ""),
				mk("s1", 1, "send", 0, httpMD(), ""),
			},
			dir:     "send",
			wantEff: "s0",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			eff, orig := resolveHeadPair(tt.msgs, tt.dir)
			if id := flowIDOrEmpty(eff); id != tt.wantEff {
				t.Errorf("effective = %q, want %q", id, tt.wantEff)
			}
			if id := flowIDOrEmpty(orig); id != tt.wantOriginal {
				t.Errorf("original = %q, want %q", id, tt.wantOriginal)
			}
		})
	}
}

func flowIDOrEmpty(f *flow.Flow) string {
	if f == nil {
		return ""
	}
	return f.ID
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
