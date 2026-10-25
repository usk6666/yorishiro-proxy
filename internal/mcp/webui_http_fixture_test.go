package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// The tests in this file record streams through the real pipeline
// RecordStep, read them back through the real MCP query handler, and pin
// the JSON the WebUI's vitest suites consume as fixtures. The WebUI
// branches on `protocol` / `http_version` / the filter enums, so its
// fixtures must be what the server actually emits — not hand-written
// spellings. Regenerate with UPDATE_WEBUI_HTTP_FIXTURE=1; otherwise any
// drift between the server response and a fixture fails the test.

const updateWebUIHTTPFixtureEnv = "UPDATE_WEBUI_HTTP_FIXTURE"

var (
	webUIFlowDetailFixtureDir = filepath.Join("..", "..", "web", "src", "pages", "FlowDetail", "__fixtures__")
	webUIFlowsFixture         = filepath.Join("..", "..", "web", "src", "pages", "Flows", "__fixtures__", "flows-all-protocols.response.json")
	webUIFilterEnumsFixture   = filepath.Join("..", "..", "web", "src", "lib", "mcp", "__fixtures__", "query-filter-enums.json")
)

// webUIFixtureRecorder runs envelopes through a RecordStep-only pipeline.
type webUIFixtureRecorder struct {
	t     *testing.T
	store flow.Store
	p     *pipeline.Pipeline
}

func newWebUIFixtureRecorder(t *testing.T, store flow.Store) *webUIFixtureRecorder {
	t.Helper()
	return &webUIFixtureRecorder{
		t:     t,
		store: store,
		p:     pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger())),
	}
}

// run records envs on streamID (FlowID / Sequence assigned in order) and
// then marks the stream complete, as the session OnComplete hook does.
func (r *webUIFixtureRecorder) run(streamID string, envs ...*envelope.Envelope) {
	r.t.Helper()
	ctx := context.Background()
	for i, env := range envs {
		env.StreamID = streamID
		env.FlowID = fmt.Sprintf("%s-%d", streamID, i)
		env.Sequence = i
		if env.Context.ConnID == "" {
			env.Context.ConnID = "conn-" + streamID
		}
		r.p.Run(ctx, env)
	}
	if err := r.store.UpdateStream(ctx, streamID, flow.StreamUpdate{State: "complete"}); err != nil {
		r.t.Fatalf("complete stream %s: %v", streamID, err)
	}
}

// h2HeadersFrame builds a single HEADERS frame (END_HEADERS|END_STREAM on
// stream 1) whose block HPACK-encodes fields in order — the bytes the h2
// Layer records as Envelope.Raw for a semantic HTTPMessage.
func h2HeadersFrame(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	frame := make([]byte, 9, 9+block.Len())
	n := block.Len()
	frame[0], frame[1], frame[2] = byte(n>>16), byte(n>>8), byte(n)
	frame[3] = 0x1     // HEADERS
	frame[4] = 0x4 | 1 // END_HEADERS | END_STREAM
	binary.BigEndian.PutUint32(frame[5:], 1)
	return append(frame, block.Bytes()...)
}

// recordH2Pair records an HTTP/2 GET + 200 response the way the
// httpaggregator emits them: pseudo-headers live in the HTTPMessage
// fields (never in Headers) and HTTPVersion is derived from the scheme.
func recordH2Pair(t *testing.T, r *webUIFixtureRecorder, streamID, scheme string) {
	t.Helper()
	version := envelope.HTTPVersionFromH2Scheme(scheme)
	reqCtx := envelope.EnvelopeContext{}
	if scheme == "https" {
		reqCtx.TLS = &envelope.TLSSnapshot{SNI: "h2.example.com", ALPN: "h2", Version: tls.VersionTLS13}
	}
	r.run(streamID,
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Context:   reqCtx,
			Raw: h2HeadersFrame(t,
				hpack.HeaderField{Name: ":method", Value: "GET"},
				hpack.HeaderField{Name: ":scheme", Value: scheme},
				hpack.HeaderField{Name: ":authority", Value: "h2.example.com"},
				hpack.HeaderField{Name: ":path", Value: "/api/items"},
				hpack.HeaderField{Name: "accept", Value: "application/json"},
				hpack.HeaderField{Name: "user-agent", Value: "fixture/1.0"},
			),
			Message: &envelope.HTTPMessage{
				Method:      "GET",
				Scheme:      scheme,
				Authority:   "h2.example.com",
				Path:        "/api/items",
				HTTPVersion: version,
				Headers: []envelope.KeyValue{
					{Name: "accept", Value: "application/json"},
					{Name: "user-agent", Value: "fixture/1.0"},
				},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw: h2HeadersFrame(t,
				hpack.HeaderField{Name: ":status", Value: "200"},
				hpack.HeaderField{Name: "content-type", Value: "application/json"},
			),
			Message: &envelope.HTTPMessage{
				Status:      200,
				HTTPVersion: version,
				Headers: []envelope.KeyValue{
					{Name: "content-type", Value: "application/json"},
				},
			},
		},
	)
}

// recordH1Pair records an HTTP/1.1 GET + 200 response with wire-cased
// headers and the verbatim request/response bytes as Raw.
func recordH1Pair(r *webUIFixtureRecorder, streamID string) {
	r.t.Helper()
	r.run(streamID,
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("GET /api/items HTTP/1.1\r\nHost: h1.example.com\r\nAccept: application/json\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Method:      "GET",
				Scheme:      "http",
				Authority:   "h1.example.com",
				Path:        "/api/items",
				HTTPVersion: envelope.HTTPVersion11,
				Headers: []envelope.KeyValue{
					{Name: "Host", Value: "h1.example.com"},
					{Name: "Accept", Value: "application/json"},
				},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
			Message: &envelope.HTTPMessage{
				Status:       200,
				StatusReason: "OK",
				HTTPVersion:  envelope.HTTPVersion11,
				Headers: []envelope.KeyValue{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "Content-Length", Value: "2"},
				},
				Body: []byte("{}"),
			},
		},
	)
}

// recordAllProtocolStreams records one stream per canonical
// Stream.Protocol value. Envelope shapes follow the producing Layers:
// WS and SSE streams open as an HTTP request and are retagged by the
// first post-upgrade envelope, exactly as RecordStep does live.
func recordAllProtocolStreams(t *testing.T, r *webUIFixtureRecorder) {
	t.Helper()
	recordH1Pair(r, "stream-http-h1")
	recordH2Pair(t, r, "stream-http-h2", "https")
	recordH2Pair(t, r, "stream-http-h2c", "http")

	r.run("stream-ws",
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("GET /echo HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "ws.example.com", Path: "/echo",
				HTTPVersion: envelope.HTTPVersion11,
				Headers: []envelope.KeyValue{
					{Name: "Host", Value: "ws.example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Status: 101, StatusReason: "Switching Protocols",
				HTTPVersion: envelope.HTTPVersion11,
				Headers: []envelope.KeyValue{
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolWebSocket,
			Raw:       []byte{0x81, 0x82, 0, 0, 0, 0, 'h', 'i'},
			Message:   &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hi")},
		},
	)

	for _, g := range []struct {
		id    string
		proto envelope.Protocol
		ct    string
	}{
		{"stream-grpc", envelope.ProtocolGRPC, "application/grpc"},
		{"stream-grpc-web", envelope.ProtocolGRPCWeb, "application/grpc-web"},
	} {
		r.run(g.id,
			&envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  g.proto,
				Raw:       []byte("hpack-encoded-start"),
				Message: &envelope.GRPCStartMessage{
					Service: "pkg.Svc", Method: "Do", ContentType: g.ct,
					Scheme: "https", Authority: "grpc.example.com", Path: "/pkg.Svc/Do",
				},
			},
			&envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  g.proto,
				Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x01},
				Message: &envelope.GRPCDataMessage{
					Service: "pkg.Svc", Method: "Do", WireLength: 2,
					Payload: []byte{0x08, 0x01}, EndStream: true,
				},
			},
			&envelope.Envelope{
				Direction: envelope.Receive,
				Protocol:  g.proto,
				Raw:       []byte("hpack-encoded-trailers"),
				Message:   &envelope.GRPCEndMessage{Status: 0},
			},
		)
	}

	r.run("stream-sse",
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("GET /events HTTP/1.1\r\nHost: sse.example.com\r\nAccept: text/event-stream\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "sse.example.com", Path: "/events",
				HTTPVersion: envelope.HTTPVersion11,
				Headers: []envelope.KeyValue{
					{Name: "Host", Value: "sse.example.com"},
					{Name: "Accept", Value: "text/event-stream"},
				},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Status: 200, StatusReason: "OK",
				HTTPVersion: envelope.HTTPVersion11,
				Headers:     []envelope.KeyValue{{Name: "Content-Type", Value: "text/event-stream"}},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolSSE,
			Raw:       []byte("event: tick\ndata: 1\n\n"),
			Message:   &envelope.SSEMessage{Event: "tick", Data: "1"},
		},
	)

	r.run("stream-raw",
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolRaw,
			Raw:       []byte("PING\r\n"),
			Message:   &envelope.RawMessage{Bytes: []byte("PING\r\n")},
		},
	)

	r.run("stream-tls-handshake",
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolTLSHandshake,
			Message: &envelope.TLSHandshakeMessage{
				SNI:     "passthrough.example.com",
				Outcome: envelope.TLSHandshakeOutcomeTunneled,
			},
		},
	)
}

// queryJSON calls the query tool with raw args and returns the decoded
// JSON object, failing on a tool error.
func queryJSON(t *testing.T, cs *gomcp.ClientSession, args map[string]any) map[string]any {
	t.Helper()
	result := callQueryRaw(t, cs, args)
	if result.IsError {
		t.Fatalf("query %v: %v", args, result.Content)
	}
	var out map[string]any
	unmarshalQueryResultRaw(t, result, &out)
	return out
}

// normalizeWebUIFixture replaces per-run values (wall-clock timestamps
// and durations) anywhere in the decoded response.
func normalizeWebUIFixture(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			switch k {
			case "timestamp":
				x[k] = "2026-01-01T00:00:00Z"
			case "duration_ms", "send_ms", "wait_ms", "receive_ms":
				x[k] = 0
			default:
				normalizeWebUIFixture(child)
			}
		}
	case []any:
		for _, child := range x {
			normalizeWebUIFixture(child)
		}
	}
}

// checkWebUIFixture writes v to path when the update env var is set, and
// otherwise fails when the checked-in fixture drifted from v.
func checkWebUIFixture(t *testing.T, path string, v any) {
	t.Helper()
	want, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')

	if os.Getenv(updateWebUIHTTPFixtureEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir fixture dir: %v", err)
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v (regenerate with %s=1)", path, err, updateWebUIHTTPFixtureEnv)
	}
	var gotV, wantV any
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Fatalf("fixture %s is not valid JSON: %v", path, err)
	}
	if err := json.Unmarshal(want, &wantV); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if !reflect.DeepEqual(gotV, wantV) {
		t.Fatalf("fixture %s drifted from the query response; regenerate with %s=1\n--- want ---\n%s",
			path, updateWebUIHTTPFixtureEnv, want)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fixture %s is semantically equal but not canonically formatted; regenerate with %s=1",
			path, updateWebUIHTTPFixtureEnv)
	}
}

// TestQueryFlow_HTTPVersionMatchesWebUIFixtures pins the query
// resource=flow response for h2, h2c and HTTP/1.1 streams. All three
// report protocol "http"; only http_version tells them apart, which is
// what the WebUI's HTTP/2 detection must key on.
func TestQueryFlow_HTTPVersionMatchesWebUIFixtures(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordH2Pair(t, r, "stream-http-h2", "https")
	recordH2Pair(t, r, "stream-http-h2c", "http")
	recordH1Pair(r, "stream-http-h1")
	cs := setupQueryTestSession(t, store)

	for _, tc := range []struct {
		id, file, wantVersion string
	}{
		{"stream-http-h2", "h2-flow.response.json", "h2"},
		{"stream-http-h2c", "h2c-flow.response.json", "h2c"},
		{"stream-http-h1", "h1-flow.response.json", "http/1.1"},
	} {
		t.Run(tc.wantVersion, func(t *testing.T) {
			got := queryJSON(t, cs, map[string]any{"resource": "flow", "id": tc.id})
			if got["protocol"] != "http" {
				t.Fatalf("protocol = %v, want http", got["protocol"])
			}
			if got["http_version"] != tc.wantVersion {
				t.Fatalf("http_version = %v, want %s", got["http_version"], tc.wantVersion)
			}
			normalizeWebUIFixture(got)
			checkWebUIFixture(t, filepath.Join(webUIFlowDetailFixtureDir, tc.file), got)
		})
	}
}

// TestQueryFlows_AllProtocolsMatchesWebUIFixture pins the query
// resource=flows response holding one stream per canonical protocol, and
// proves every filter value the WebUI offers is accepted by the server
// and selects the matching streams.
func TestQueryFlows_AllProtocolsMatchesWebUIFixture(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	cs := setupQueryTestSession(t, store)

	all := queryJSON(t, cs, map[string]any{"resource": "flows", "limit": 100})
	flows, ok := all["flows"].([]any)
	if !ok {
		t.Fatalf("flows = %T, want array", all["flows"])
	}
	// Order by id so the fixture does not depend on same-instant
	// timestamp tie-breaking.
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].(map[string]any)["id"].(string) < flows[j].(map[string]any)["id"].(string)
	})
	gotProtocols := map[string]int{}
	for _, f := range flows {
		gotProtocols[f.(map[string]any)["protocol"].(string)]++
	}
	for _, p := range validFilterProtocols {
		if gotProtocols[p] == 0 {
			t.Errorf("no recorded stream has protocol %q (recorded: %v)", p, gotProtocols)
		}
	}
	if len(gotProtocols) != len(validFilterProtocols) {
		t.Errorf("recorded protocols %v, want exactly %v", gotProtocols, validFilterProtocols)
	}

	// Every protocol filter value is accepted and matches its streams.
	for _, p := range validFilterProtocols {
		res := queryJSON(t, cs, map[string]any{"resource": "flows", "filter": map[string]any{"protocol": p}})
		if total := int(res["total"].(float64)); total != gotProtocols[p] {
			t.Errorf("filter.protocol=%q total = %d, want %d", p, total, gotProtocols[p])
		}
	}
	// h2 / h2c breakdown (protocol=http + http_version) selects one stream each.
	for _, v := range []string{"h2", "h2c", "http/1.1"} {
		res := queryJSON(t, cs, map[string]any{"resource": "flows", "filter": map[string]any{"protocol": "http", "http_version": v}})
		if total := int(res["total"].(float64)); total != 1 {
			t.Errorf("filter {protocol:http, http_version:%q} total = %d, want 1", v, total)
		}
	}
	for _, v := range validFilterHTTPVersions {
		queryJSON(t, cs, map[string]any{"resource": "flows", "filter": map[string]any{"http_version": v}})
	}
	for _, s := range validFilterSchemes {
		queryJSON(t, cs, map[string]any{"resource": "flows", "filter": map[string]any{"scheme": s}})
	}

	all["flows"] = flows
	normalizeWebUIFixture(all)
	checkWebUIFixture(t, webUIFlowsFixture, all)

	// The enum lists the query handler validates against, so the WebUI
	// can assert its filter controls only offer accepted values.
	checkWebUIFixture(t, webUIFilterEnumsFixture, map[string]any{
		"protocol":     validFilterProtocols,
		"http_version": validFilterHTTPVersions,
		"scheme":       validFilterSchemes,
	})
}

// TestQueryFlow_StreamingProtocolsMatchWebUIFixtures pins the query
// resource=flow response for one stream of every non-HTTP canonical
// protocol. The WebUI decides whether FlowDetail needs the messages
// query from `protocol` alone: the server has no unary/streaming
// classification (a MITM proxy cannot know RPC cardinality), so the
// response must not carry the dropped flow_type key either.
func TestQueryFlow_StreamingProtocolsMatchWebUIFixtures(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	cs := setupQueryTestSession(t, store)

	for _, proto := range []string{"ws", "grpc", "grpc-web", "sse", "raw", "tls-handshake"} {
		t.Run(proto, func(t *testing.T) {
			got := queryJSON(t, cs, map[string]any{"resource": "flow", "id": "stream-" + proto})
			if got["protocol"] != proto {
				t.Fatalf("protocol = %v, want %s", got["protocol"], proto)
			}
			if v, ok := got["flow_type"]; ok {
				t.Fatalf("response carries flow_type = %v; the server has no unary/streaming field", v)
			}
			normalizeWebUIFixture(got)
			checkWebUIFixture(t, filepath.Join(webUIFlowDetailFixtureDir, proto+"-flow.response.json"), got)
		})
	}
}
