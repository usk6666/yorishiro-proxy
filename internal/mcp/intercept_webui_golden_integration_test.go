//go:build e2e && !e2e_smoke

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// The WebUI Intercept page builds its `intercept` arguments with the pure
// builder in web/src/pages/Intercept/interceptPayload.ts. Its vitest suite
// pins, per hold kind, the queue entry it reads (queue-entry.<kind>.json,
// hand-written to mirror the server projection) and the arguments it
// sends after a fixed set of edits (modify-args.<kind>.json, written by
// toMatchFileSnapshot from the real builder). This test closes the loop
// against the real server: the held envelope must project to exactly that
// queue entry, and the builder-produced arguments must be accepted by the
// intercept tool and reach the forwarded envelope.
var webUIInterceptFixtureDir = filepath.Join("..", "..", "web", "src", "pages", "Intercept", "__fixtures__")

// webUIFixtureInterceptID is the placeholder id used in the WebUI fixtures.
const webUIFixtureInterceptID = "INTERCEPT_ID"

func readWebUIFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(webUIInterceptFixtureDir, name))
	if err != nil {
		t.Fatalf("read WebUI fixture %s: %v", name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode WebUI fixture %s: %v", name, err)
	}
	return out
}

// queryHeldQueueEntry returns the first intercept_queue item as decoded JSON.
func queryHeldQueueEntry(t *testing.T, cs *gomcp.ClientSession) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "intercept_queue"},
	})
	if err != nil {
		t.Fatalf("CallTool query: %v", err)
	}
	if res.IsError {
		t.Fatalf("query intercept_queue returned error: %v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal query result: %v", err)
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode query result: %v", err)
	}
	if len(out.Items) != 1 {
		t.Fatalf("intercept_queue items = %d, want 1", len(out.Items))
	}
	return out.Items[0]
}

// runWebUIGolden holds env, checks the server's queue projection equals the
// WebUI's queue-entry fixture, replays the WebUI modify-args golden and
// returns the forwarded envelope.
func runWebUIGolden(t *testing.T, kind string, env *envelope.Envelope) *envelope.Envelope {
	t.Helper()
	queue, cs := setupHoldQueueSession(t)
	actionCh := holdInBackground(t, queue, env)
	held := waitForHeldEntry(t, queue, 2*time.Second)

	got := queryHeldQueueEntry(t, cs)
	want := readWebUIFixture(t, "queue-entry."+kind+".json")
	if got["id"] != held.ID {
		t.Fatalf("queue entry id = %v, want %s", got["id"], held.ID)
	}
	// id and held_at are per-run values; everything else must match the
	// shape the WebUI was written against.
	for _, k := range []string{"id", "held_at"} {
		delete(got, k)
		delete(want, k)
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("server queue projection differs from WebUI fixture queue-entry.%s.json\n--- server ---\n%s\n--- fixture ---\n%s", kind, gotJSON, wantJSON)
	}

	args := readWebUIFixture(t, "modify-args."+kind+".json")
	params, ok := args["params"].(map[string]any)
	if !ok {
		t.Fatalf("modify-args.%s.json: params is not an object", kind)
	}
	if params["intercept_id"] != webUIFixtureInterceptID {
		t.Fatalf("modify-args.%s.json: intercept_id = %v, want placeholder %s", kind, params["intercept_id"], webUIFixtureInterceptID)
	}
	params["intercept_id"] = held.ID

	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("intercept rejected WebUI modify-args.%s.json: %v", kind, res.Content)
	}

	select {
	case action := <-actionCh:
		if action == nil {
			t.Fatal("Hold returned nil action")
		}
		if action.Type != common.ActionModifyAndForward {
			t.Fatalf("action type = %v, want ModifyAndForward", action.Type)
		}
		return action.Modified
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Hold to return")
	}
	return nil
}

func wantHeaders(t *testing.T, got []envelope.KeyValue, want []envelope.KeyValue) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("headers = %+v, want %+v", got, want)
	}
}

// TestInterceptWebUIGolden_HTTPRequest_ModifyAndForward: edited path, query,
// headers (a duplicate pair with differing casing, one removed, one added)
// and body arrive; method, scheme and authority keep the held values.
func TestInterceptWebUIGolden_HTTPRequest_ModifyAndForward(t *testing.T) {
	env := &envelope.Envelope{
		StreamID:  "s-req",
		FlowID:    "f-req",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/orig",
			RawQuery:  "a=1",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Dup", Value: "1"},
				{Name: "x-dup", Value: "2"},
				{Name: "X-Remove", Value: "gone"},
			},
			Body: []byte("hello"),
		},
	}
	mod := runWebUIGolden(t, "request", env)
	hm, ok := mod.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("modified message = %T, want *HTTPMessage", mod.Message)
	}
	if hm.Method != "POST" || hm.Scheme != "https" || hm.Authority != "example.com" {
		t.Errorf("untouched fields changed: method=%q scheme=%q authority=%q", hm.Method, hm.Scheme, hm.Authority)
	}
	if hm.Path != "/admin" {
		t.Errorf("Path = %q, want /admin", hm.Path)
	}
	if hm.RawQuery != "a=2" {
		t.Errorf("RawQuery = %q, want a=2", hm.RawQuery)
	}
	wantHeaders(t, hm.Headers, []envelope.KeyValue{
		{Name: "Host", Value: "example.com"},
		{Name: "X-Dup", Value: "1"},
		{Name: "x-dup", Value: "3"},
		{Name: "X-Added", Value: "yes"},
	})
	if string(hm.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", hm.Body, "hello world")
	}
}

// TestInterceptWebUIGolden_HTTPResponse_ModifyAndForward: status, a
// Set-Cookie appended after a Set-Cookie / set-cookie pair, and a base64
// (non-UTF-8) body arrive; the reason phrase keeps its held value.
func TestInterceptWebUIGolden_HTTPResponse_ModifyAndForward(t *testing.T) {
	env := &envelope.Envelope{
		StreamID:  "s-resp",
		FlowID:    "f-resp",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/octet-stream"},
				{Name: "Set-Cookie", Value: "a=1"},
				{Name: "set-cookie", Value: "b=2"},
			},
			Body: []byte{0xff, 0x00, 0x01},
		},
	}
	mod := runWebUIGolden(t, "response", env)
	hm, ok := mod.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("modified message = %T, want *HTTPMessage", mod.Message)
	}
	if hm.Status != 403 {
		t.Errorf("Status = %d, want 403", hm.Status)
	}
	if hm.StatusReason != "OK" {
		t.Errorf("StatusReason = %q, want held OK", hm.StatusReason)
	}
	wantHeaders(t, hm.Headers, []envelope.KeyValue{
		{Name: "Content-Type", Value: "application/octet-stream"},
		{Name: "Set-Cookie", Value: "a=1"},
		{Name: "set-cookie", Value: "b=2"},
		{Name: "Set-Cookie", Value: "c=3"},
	})
	if want := []byte{0xff, 0x00, 0x02, 0x03}; !bytes.Equal(hm.Body, want) {
		t.Errorf("Body = %x, want %x", hm.Body, want)
	}
}

// TestInterceptWebUIGolden_WS_ModifyAndForward: the edited payload arrives;
// opcode and FIN keep the held values.
func TestInterceptWebUIGolden_WS_ModifyAndForward(t *testing.T) {
	env := &envelope.Envelope{
		StreamID:  "s-ws",
		FlowID:    "f-ws",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Masked:  true,
			Payload: []byte("ping"),
		},
	}
	mod := runWebUIGolden(t, "ws", env)
	wm, ok := mod.Message.(*envelope.WSMessage)
	if !ok {
		t.Fatalf("modified message = %T, want *WSMessage", mod.Message)
	}
	if wm.Opcode != envelope.WSText || !wm.Fin {
		t.Errorf("opcode/fin changed: opcode=%v fin=%v", wm.Opcode, wm.Fin)
	}
	if string(wm.Payload) != "pong" {
		t.Errorf("Payload = %q, want pong", wm.Payload)
	}
}

// TestInterceptWebUIGolden_Raw_ModifyAndForward: the edited bytes arrive
// through raw.bytes_override (not the params.raw_override_base64 path).
func TestInterceptWebUIGolden_Raw_ModifyAndForward(t *testing.T) {
	env := &envelope.Envelope{
		StreamID:  "s-raw",
		FlowID:    "f-raw",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("HELLO\r\n")},
		Raw:       []byte("HELLO\r\n"),
	}
	mod := runWebUIGolden(t, "raw", env)
	rm, ok := mod.Message.(*envelope.RawMessage)
	if !ok {
		t.Fatalf("modified message = %T, want *RawMessage", mod.Message)
	}
	if string(rm.Bytes) != "BYE\r\n" {
		t.Errorf("Bytes = %q, want %q", rm.Bytes, "BYE\r\n")
	}
}
