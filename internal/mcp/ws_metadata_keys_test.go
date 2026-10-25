package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// The tests in this file record WebSocket and gRPC streams through the real
// pipeline RecordStep and read them back through the MCP tools, so the
// readers (HAR export, protocol_summary, the WebUI fixture) are checked
// against the Metadata keys the producer actually writes (ws_opcode,
// ws_close_code, grpc_service, ...) rather than hand-written key names.

// recordWSStream records an upgrade GET, its 101 response, and then the
// given WS frames on streamID. Envelope shapes follow
// internal/pipeline/record_step_test.go TestRecordStep_FlowFieldsWSText /
// TestRecordStep_FlowFieldsWSCloseFrame.
func recordWSStream(t *testing.T, store flow.Store, streamID string, frames []wsTestFrame) {
	t.Helper()
	ctx := context.Background()
	p := pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger()))

	p.Run(ctx, &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-upgrade-req",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET /echo HTTP/1.1\r\nHost: echo.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "echo.example.com",
			Path:      "/echo",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "echo.example.com"},
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
			},
		},
	})
	p.Run(ctx, &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-upgrade-resp",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Status:       101,
			StatusReason: "Switching Protocols",
			Headers: []envelope.KeyValue{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
			},
		},
	})
	for i, f := range frames {
		p.Run(ctx, &envelope.Envelope{
			StreamID:  streamID,
			FlowID:    fmt.Sprintf("%s-frame-%d", streamID, i),
			Sequence:  2 + i,
			Direction: f.dir,
			Protocol:  envelope.ProtocolWebSocket,
			Raw:       f.raw,
			Message:   f.msg,
		})
	}
}

type wsTestFrame struct {
	dir envelope.Direction
	raw []byte
	msg *envelope.WSMessage
}

// issueReproFrames mirrors the Issue's manual repro: Send Text "hello",
// Receive Binary 00 01 02 ff, Receive Close(1000, "bye").
func issueReproFrames() []wsTestFrame {
	return []wsTestFrame{
		{
			dir: envelope.Send,
			raw: []byte{0x81, 0x85, 0, 0, 0, 0, 'h', 'e', 'l', 'l', 'o'},
			msg: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hello")},
		},
		{
			dir: envelope.Receive,
			raw: []byte{0x82, 0x04, 0x00, 0x01, 0x02, 0xff},
			msg: &envelope.WSMessage{Opcode: envelope.WSBinary, Fin: true, Payload: []byte{0x00, 0x01, 0x02, 0xff}},
		},
		{
			dir: envelope.Receive,
			raw: []byte{0x88, 0x05, 0x03, 0xe8, 'b', 'y', 'e'},
			msg: &envelope.WSMessage{
				Opcode:      envelope.WSClose,
				Fin:         true,
				CloseCode:   1000,
				CloseReason: "bye",
				Payload:     []byte{0x03, 0xe8, 'b', 'y', 'e'},
			},
		},
	}
}

// exportHAR runs MCP manage export_flows format=har and returns the parsed HAR.
func exportHAR(t *testing.T, cs *gomcp.ClientSession, dir string) flow.HAR {
	t.Helper()
	out := filepath.Join(dir, "out.har")
	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"format":      "har",
			"output_path": out,
		},
	})
	if result.IsError {
		t.Fatalf("export_flows har: %v", result.Content)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read HAR: %v", err)
	}
	var har flow.HAR
	if err := json.Unmarshal(data, &har); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}
	return har
}

func TestExportHAR_WSOpcodeFromRecordStep(t *testing.T) {
	store := newTestStore(t)
	recordWSStream(t, store, "ws-usk1342-repro", issueReproFrames())
	cs, dir := setupExportSession(t, newTestCA(t), store)

	har := exportHAR(t, cs, dir)
	if len(har.Log.Entries) != 1 {
		t.Fatalf("HAR entries = %d, want 1", len(har.Log.Entries))
	}
	msgs := har.Log.Entries[0].WebSocketMessages
	want := []struct {
		typ    string
		opcode int
		data   string
	}{
		{"send", 1, "hello"},
		{"receive", 2, "AAEC/w=="},
		{"receive", 8, "A+hieWU="},
	}
	if len(msgs) != len(want) {
		t.Fatalf("_webSocketMessages = %d entries, want %d (upgrade flows must not be listed): %+v", len(msgs), len(want), msgs)
	}
	for i, w := range want {
		if msgs[i].Type != w.typ {
			t.Errorf("_webSocketMessages[%d].type = %q, want %q", i, msgs[i].Type, w.typ)
		}
		if msgs[i].Opcode != w.opcode {
			t.Errorf("_webSocketMessages[%d].opcode = %d, want %d", i, msgs[i].Opcode, w.opcode)
		}
		if msgs[i].Data != w.data {
			t.Errorf("_webSocketMessages[%d].data = %q, want %q", i, msgs[i].Data, w.data)
		}
	}
}

// TestExportHAR_WSBinaryASCIIPayloadIsBase64 pins that a Binary frame's
// HAR data is base64 even when its bytes happen to be valid UTF-8, so the
// opcode and the data encoding agree.
func TestExportHAR_WSBinaryASCIIPayloadIsBase64(t *testing.T) {
	store := newTestStore(t)
	recordWSStream(t, store, "ws-usk1342-binary-ascii", []wsTestFrame{
		{
			dir: envelope.Receive,
			raw: []byte{0x82, 0x03, 'a', 'b', 'c'},
			msg: &envelope.WSMessage{Opcode: envelope.WSBinary, Fin: true, Payload: []byte("abc")},
		},
		{
			dir: envelope.Receive,
			raw: []byte{0x81, 0x03, 'a', 'b', 'c'},
			msg: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("abc")},
		},
	})
	cs, dir := setupExportSession(t, newTestCA(t), store)

	har := exportHAR(t, cs, dir)
	if len(har.Log.Entries) != 1 {
		t.Fatalf("HAR entries = %d, want 1", len(har.Log.Entries))
	}
	msgs := har.Log.Entries[0].WebSocketMessages
	if len(msgs) != 2 {
		t.Fatalf("_webSocketMessages = %d entries, want 2: %+v", len(msgs), msgs)
	}
	if msgs[0].Opcode != 2 || msgs[0].Data != "YWJj" {
		t.Errorf("binary frame = {opcode %d, data %q}, want {opcode 2, data \"YWJj\"}", msgs[0].Opcode, msgs[0].Data)
	}
	if msgs[1].Opcode != 1 || msgs[1].Data != "abc" {
		t.Errorf("text frame = {opcode %d, data %q}, want {opcode 1, data \"abc\"}", msgs[1].Opcode, msgs[1].Data)
	}
}

func TestQueryFlow_ProtocolSummaryFromRecordStep(t *testing.T) {
	t.Run("ws_last_frame_type", func(t *testing.T) {
		store := newTestStore(t)
		const streamID = "ws-usk1342-summary"
		recordWSStream(t, store, streamID, issueReproFrames())
		cs := setupQueryTestSession(t, store)

		result := callQuery(t, cs, queryInput{Resource: "flow", ID: streamID})
		if result.IsError {
			t.Fatalf("query flow: %v", result.Content)
		}
		var got queryFlowResult
		unmarshalQueryResult(t, result, &got)
		if got.Protocol != "ws" {
			t.Fatalf("protocol = %q, want ws", got.Protocol)
		}
		if lt := got.ProtocolSummary["last_frame_type"]; lt != "Close" {
			t.Errorf("protocol_summary.last_frame_type = %q, want Close (summary %+v)", lt, got.ProtocolSummary)
		}
	})

	t.Run("grpc_service_method_status", func(t *testing.T) {
		store := newTestStore(t)
		const streamID = "grpc-usk1342-summary"
		recordGRPCStream(t, store, streamID)
		cs := setupQueryTestSession(t, store)

		result := callQuery(t, cs, queryInput{Resource: "flow", ID: streamID})
		if result.IsError {
			t.Fatalf("query flow: %v", result.Content)
		}
		var got queryFlowResult
		unmarshalQueryResult(t, result, &got)
		if got.Protocol != "grpc" {
			t.Fatalf("protocol = %q, want grpc", got.Protocol)
		}
		want := map[string]string{
			"service":          "pkg.Svc",
			"method":           "Do",
			"grpc_status":      "0",
			"grpc_status_name": "OK",
		}
		for k, v := range want {
			if got.ProtocolSummary[k] != v {
				t.Errorf("protocol_summary.%s = %q, want %q (summary %+v)", k, got.ProtocolSummary[k], v, got.ProtocolSummary)
			}
		}
	})
}

// recordGRPCStream records a unary RPC (Start, Data, End) through the real
// RecordStep. Shapes follow internal/pipeline/record_step_test.go
// TestRecordStep_FlowFieldsGRPCStart and its Data / End siblings.
func recordGRPCStream(t *testing.T, store flow.Store, streamID string) {
	t.Helper()
	ctx := context.Background()
	p := pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger()))
	envs := []*envelope.Envelope{
		{
			Direction: envelope.Send,
			Raw:       []byte("hpack-encoded-start"),
			Message: &envelope.GRPCStartMessage{
				Service:     "pkg.Svc",
				Method:      "Do",
				ContentType: "application/grpc",
				Scheme:      "https",
				Authority:   "grpc.example.com",
				Path:        "/pkg.Svc/Do",
			},
		},
		{
			Direction: envelope.Send,
			Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x01},
			Message: &envelope.GRPCDataMessage{
				Service:    "pkg.Svc",
				Method:     "Do",
				WireLength: 2,
				Payload:    []byte{0x08, 0x01},
				EndStream:  true,
			},
		},
		{
			Direction: envelope.Receive,
			Raw:       []byte("hpack-encoded-trailers"),
			Message:   &envelope.GRPCEndMessage{Status: 0},
		},
	}
	for i, env := range envs {
		env.StreamID = streamID
		env.FlowID = fmt.Sprintf("%s-%d", streamID, i)
		env.Sequence = i
		env.Protocol = envelope.ProtocolGRPC
		p.Run(ctx, env)
	}
}

// webUIWSMessagesFixture is the checked-in query resource=messages response
// for the issueReproFrames WS stream, consumed by the WebUI's
// WebSocketMessageList vitest suite. Regenerate with
// UPDATE_WEBUI_WS_FIXTURE=1.
var webUIWSMessagesFixture = filepath.Join("..", "..", "web", "src", "pages", "FlowDetail", "__fixtures__", "ws-messages.response.json")

const updateWebUIWSFixtureEnv = "UPDATE_WEBUI_WS_FIXTURE"

// TestQueryMessages_WSMatchesWebUIFixture fails when the messages response
// for a RecordStep-recorded WS stream differs from the fixture the WebUI
// tests render. Per-run fields (id, timestamp) are normalised.
func TestQueryMessages_WSMatchesWebUIFixture(t *testing.T) {
	store := newTestStore(t)
	const streamID = "ws-usk1342-webui"
	recordWSStream(t, store, streamID, issueReproFrames())
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: streamID})
	if result.IsError {
		t.Fatalf("query messages: %v", result.Content)
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(text.Text), &resp); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	msgs, ok := resp["messages"].([]any)
	if !ok || len(msgs) != 5 {
		t.Fatalf("messages = %v, want 5 entries", resp["messages"])
	}
	for _, m := range msgs {
		entry := m.(map[string]any)
		entry["id"] = fmt.Sprintf("msg-%v", entry["sequence"])
		entry["timestamp"] = "2026-01-01T00:00:00Z"
	}

	want, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')

	if os.Getenv(updateWebUIWSFixtureEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(webUIWSMessagesFixture), 0o755); err != nil {
			t.Fatalf("mkdir fixture dir: %v", err)
		}
		if err := os.WriteFile(webUIWSMessagesFixture, want, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	got, err := os.ReadFile(webUIWSMessagesFixture)
	if err != nil {
		t.Fatalf("read fixture %s: %v (regenerate with %s=1)", webUIWSMessagesFixture, err, updateWebUIWSFixtureEnv)
	}
	var gotResp any
	if err := json.Unmarshal(got, &gotResp); err != nil {
		t.Fatalf("fixture %s is not valid JSON: %v", webUIWSMessagesFixture, err)
	}
	var wantResp any
	if err := json.Unmarshal(want, &wantResp); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if !reflect.DeepEqual(gotResp, wantResp) {
		t.Fatalf("fixture %s drifted from the query messages response; regenerate with %s=1\n--- want ---\n%s",
			webUIWSMessagesFixture, updateWebUIWSFixtureEnv, want)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fixture %s is semantically equal but not canonically formatted; regenerate with %s=1",
			webUIWSMessagesFixture, updateWebUIWSFixtureEnv)
	}
}
