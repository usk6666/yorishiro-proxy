//go:build e2e

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// setupHoldQueueSession spins up an MCP server backed by a fresh
// common.HoldQueue and returns the queue + a connected client session.
// The test goroutine that invokes the intercept tool runs against the
// same queue; tests that hold an envelope must do so in a goroutine so
// the tool call can release it.
func setupHoldQueueSession(t *testing.T) (*common.HoldQueue, *gomcp.ClientSession) {
	t.Helper()
	queue := common.NewHoldQueue()
	ca := newTestCA(t)
	cs := setupTestSessionWithStore(t, ca, nil)
	// The default newServer wires nil holdQueue; mutate it here.
	// We rely on the WithHoldQueue option indirectly: the session
	// helpers don't expose options, so use a parallel server creation
	// path that does.
	_ = cs
	// Fall through to a custom server with WithHoldQueue.
	ctx := context.Background()
	srv := newServer(ctx, ca, nil, nil, WithHoldQueue(queue))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "intercept-typed-test", Version: "v0.0.1"}, nil)
	cs2, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs2.Close() })
	return queue, cs2
}

// holdInBackground enqueues env on the HoldQueue and returns a channel
// that receives the resulting HoldAction (Modified envelope or
// Drop/Release marker). The test issues an MCP intercept call against the
// queue's first entry; the tool dispatch unblocks Hold.
func holdInBackground(t *testing.T, queue *common.HoldQueue, env *envelope.Envelope) chan *common.HoldAction {
	t.Helper()
	out := make(chan *common.HoldAction, 1)
	go func() {
		action, err := queue.Hold(context.Background(), env, []string{"test-rule"})
		if err != nil {
			t.Errorf("queue.Hold returned error: %v", err)
			out <- nil
			return
		}
		out <- action
	}()
	return out
}

// waitForHeldEntry polls the queue for the first held entry. Failing the
// poll within timeout fails the test.
func waitForHeldEntry(t *testing.T, queue *common.HoldQueue, timeout time.Duration) *common.HeldEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries := queue.List()
		if len(entries) > 0 {
			return entries[0]
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for held entry within %v", timeout)
	return nil
}

// callInterceptRaw issues the intercept tool with arbitrary args (any
// shape; serialised as JSON). Returns the *gomcp.CallToolResult so the
// caller can inspect IsError and content.
func callInterceptRaw(t *testing.T, cs *gomcp.ClientSession, args any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "intercept",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool intercept: %v", err)
	}
	return res
}

// TestInterceptHoldQueue_HTTP_ModifyAndForward holds an HTTP envelope,
// invokes intercept with a typed httpMessageModify payload, and asserts
// that the modified envelope returned through the queue carries the
// changed Path + new header.
func TestInterceptHoldQueue_HTTP_ModifyAndForward(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/orig",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Original", Value: "yes"},
			},
		},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	newPath := "/modified"
	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"http": map[string]any{
			"path": newPath,
			"headers": []map[string]string{
				{"name": "Host", "value": "example.com"},
				{"name": "X-Original", "value": "yes"},
				{"name": "X-Injected", "value": "1"},
			},
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	select {
	case action := <-actionCh:
		if action == nil {
			t.Fatal("Hold returned nil action")
		}
		if action.Type != common.ActionModifyAndForward {
			t.Fatalf("Action type = %v, want ModifyAndForward", action.Type)
		}
		hm, ok := action.Modified.Message.(*envelope.HTTPMessage)
		if !ok {
			t.Fatalf("Modified.Message type = %T, want *HTTPMessage", action.Modified.Message)
		}
		if hm.Path != newPath {
			t.Errorf("Modified Path = %q, want %q", hm.Path, newPath)
		}
		if len(hm.Headers) != 3 {
			t.Fatalf("Modified Headers len = %d, want 3", len(hm.Headers))
		}
		if hm.Headers[2].Name != "X-Injected" || hm.Headers[2].Value != "1" {
			t.Errorf("Modified Headers[2] = %+v, want {X-Injected, 1}", hm.Headers[2])
		}
		if action.Modified.Raw != nil {
			t.Errorf("Modified.Raw should be nil so Layer regenerates wire bytes; got %d bytes", len(action.Modified.Raw))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Hold to return")
	}
}

// TestInterceptHoldQueue_HTTP_HeaderOrderPreserved verifies that the
// supplied headers slice is stored verbatim — order, casing, and
// duplicates intact (RFC-001 wire-fidelity invariant).
func TestInterceptHoldQueue_HTTP_HeaderOrderPreserved(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
			Headers: []envelope.KeyValue{
				{Name: "Set-Cookie", Value: "a=1"},
				{Name: "set-cookie", Value: "b=2"},
				{Name: "X-Custom", Value: "first"},
			},
		},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"http": map[string]any{
			"headers": []map[string]string{
				{"name": "Set-Cookie", "value": "a=1"},
				{"name": "set-cookie", "value": "b=2"},
				{"name": "X-Custom", "value": "first"},
				{"name": "X-Appended", "value": "yes"},
			},
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	action := <-actionCh
	hm := action.Modified.Message.(*envelope.HTTPMessage)
	expected := []envelope.KeyValue{
		{Name: "Set-Cookie", Value: "a=1"},
		{Name: "set-cookie", Value: "b=2"},
		{Name: "X-Custom", Value: "first"},
		{Name: "X-Appended", Value: "yes"},
	}
	if len(hm.Headers) != len(expected) {
		t.Fatalf("Headers len = %d, want %d", len(hm.Headers), len(expected))
	}
	for i, h := range expected {
		if hm.Headers[i] != h {
			t.Errorf("Headers[%d] = %+v, want %+v", i, hm.Headers[i], h)
		}
	}
}

// TestInterceptHoldQueue_WS_ModifyAndForward holds a WS Text frame, then
// substitutes the payload via MCP. Asserts payload and opcode round-trip.
func TestInterceptHoldQueue_WS_ModifyAndForward(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Payload: []byte("orig"),
		},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	newPayload := "rewritten"
	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"ws": map[string]any{
			"opcode":  "text",
			"payload": newPayload,
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	action := <-actionCh
	wm := action.Modified.Message.(*envelope.WSMessage)
	if wm.Opcode != envelope.WSText {
		t.Errorf("Opcode = %d, want WSText", wm.Opcode)
	}
	if string(wm.Payload) != newPayload {
		t.Errorf("Payload = %q, want %q", wm.Payload, newPayload)
	}
}

// TestInterceptHoldQueue_GRPCData_ModifyAndForward holds a GRPCData
// envelope, swaps its payload, and confirms Compressed flag round-trips.
func TestInterceptHoldQueue_GRPCData_ModifyAndForward(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Service: "Greeter",
			Method:  "SayHello",
			Payload: []byte("\x0a\x05world"),
		},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	newPayload := base64.StdEncoding.EncodeToString([]byte("\x0a\x07modified"))
	compressed := false
	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"grpc_data": map[string]any{
			"payload":          newPayload,
			"payload_encoding": "base64",
			"compressed":       compressed,
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	action := <-actionCh
	gm := action.Modified.Message.(*envelope.GRPCDataMessage)
	if gm.Compressed {
		t.Errorf("Compressed = true, want false")
	}
	if string(gm.Payload) != "\x0a\x07modified" {
		t.Errorf("Payload = %q, want %q", gm.Payload, "\x0a\x07modified")
	}
}

// TestInterceptHoldQueue_Raw_BytesOverride verifies the bytes_override
// path on a held RawMessage.
func TestInterceptHoldQueue_Raw_BytesOverride(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("hello")},
		Raw:       []byte("hello"),
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"raw": map[string]any{
			"bytes_override": "world",
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	action := <-actionCh
	rm := action.Modified.Message.(*envelope.RawMessage)
	if string(rm.Bytes) != "world" {
		t.Errorf("Bytes = %q, want %q", rm.Bytes, "world")
	}
}

// TestInterceptHoldQueue_Raw_Patches exercises the patches path on a
// RawMessage envelope.
func TestInterceptHoldQueue_Raw_Patches(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("hello world")},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"raw": map[string]any{
			"patches": []map[string]any{
				{"find_text": "hello", "replace_text": "HELLO"},
			},
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}

	action := <-actionCh
	rm := action.Modified.Message.(*envelope.RawMessage)
	if string(rm.Bytes) != "HELLO world" {
		t.Errorf("Bytes = %q, want %q", rm.Bytes, "HELLO world")
	}
}

// TestInterceptHoldQueue_Raw_BytesOverrideAndPatches_Rejected verifies
// the mutual-exclusion validation. The held entry must not be consumed
// when the request is rejected.
func TestInterceptHoldQueue_Raw_BytesOverrideAndPatches_Rejected(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("data")},
	}
	_ = holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry.ID,
		},
		"raw": map[string]any{
			"bytes_override": "X",
			"patches":        []map[string]any{{"find_text": "d", "replace_text": "D"}},
		},
	}
	res := callInterceptRaw(t, cs, args)
	if !res.IsError {
		t.Fatal("expected error result for mutual-exclusion violation, got success")
	}
	if queue.Len() != 1 {
		t.Errorf("queue.Len() after rejected validation = %d, want 1 (entry must NOT be consumed)", queue.Len())
	}
	// Cleanup: release the entry so the background goroutine terminates.
	if err := queue.Release(entry.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Errorf("cleanup Release: %v", err)
	}
}

// TestInterceptHoldQueue_Drop verifies the drop action.
func TestInterceptHoldQueue_Drop(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/"},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "drop",
		"params": map[string]any{"intercept_id": entry.ID},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}
	action := <-actionCh
	if action.Type != common.ActionDrop {
		t.Errorf("Action type = %v, want Drop", action.Type)
	}
}

// TestInterceptHoldQueue_Release verifies the release action passes the
// envelope through unchanged.
func TestInterceptHoldQueue_Release(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/"},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "release",
		"params": map[string]any{"intercept_id": entry.ID},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}
	action := <-actionCh
	if action.Type != common.ActionRelease {
		t.Errorf("Action type = %v, want Release", action.Type)
	}
}

// TestInterceptHoldQueue_LegacyFallback confirms that an unknown ID (not
// in the new HoldQueue) falls through to the legacy queue handler. Since
// no legacy queue is wired, the call returns an error from the legacy
// path — which is the contract: HoldQueue is tried first, never tried
// twice, never silently swallowed.
func TestInterceptHoldQueue_LegacyFallback(t *testing.T) {
	_, cs := setupHoldQueueSession(t)

	args := map[string]any{
		"action": "drop",
		"params": map[string]any{"intercept_id": "does-not-exist-anywhere"},
	}
	res := callInterceptRaw(t, cs, args)
	if !res.IsError {
		t.Fatal("expected error for unknown intercept_id falling through to legacy queue, got success")
	}
}

// TestInterceptHoldQueue_Mode_Raw_OverrideOnHTTP verifies the Mode=raw
// path: a held HTTP envelope can be replaced with arbitrary wire bytes
// via raw_override_base64. The Modified envelope's Raw must equal the
// override exactly so the Layer skips re-encoding (smuggling injection
// surface).
func TestInterceptHoldQueue_Mode_Raw_OverrideOnHTTP(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/"},
		Raw:       []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	smuggle := []byte("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 8\r\n\r\nXXXX")
	args := map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":        entry.ID,
			"mode":                "raw",
			"raw_override_base64": base64.StdEncoding.EncodeToString(smuggle),
		},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		// Print content for debugging.
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		t.Fatalf("CallTool intercept: %s", sb.String())
	}
	action := <-actionCh
	if action.Type != common.ActionModifyAndForward {
		t.Fatalf("Action.Type = %v, want ModifyAndForward", action.Type)
	}
	if string(action.Modified.Raw) != string(smuggle) {
		t.Errorf("Modified.Raw = %q, want %q", action.Modified.Raw, smuggle)
	}
	if _, ok := action.Modified.Message.(*envelope.RawMessage); !ok {
		t.Errorf("Modified.Message type = %T, want *RawMessage (raw mode synthesises a RawMessage)", action.Modified.Message)
	}
}

// TestInterceptHoldQueue_Result_Shape verifies the structured response
// from the holdQueue path includes the expected fields.
func TestInterceptHoldQueue_Result_Shape(t *testing.T) {
	queue, cs := setupHoldQueueSession(t)

	env := &envelope.Envelope{
		StreamID:  "stream-x",
		FlowID:    "flow-y",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/"},
	}
	actionCh := holdInBackground(t, queue, env)
	entry := waitForHeldEntry(t, queue, 2*time.Second)

	args := map[string]any{
		"action": "release",
		"params": map[string]any{"intercept_id": entry.ID},
	}
	res := callInterceptRaw(t, cs, args)
	if res.IsError {
		t.Fatalf("CallTool intercept: %v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty Content")
	}
	tc, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] type = %T, want *TextContent", res.Content[0])
	}
	var out struct {
		InterceptID string `json:"intercept_id"`
		Action      string `json:"action"`
		Status      string `json:"status"`
		Protocol    string `json:"protocol"`
		FlowID      string `json:"flow_id"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Action != "release" || out.Status != "released" {
		t.Errorf("Action/Status = %q/%q, want release/released", out.Action, out.Status)
	}
	if out.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", out.Protocol)
	}
	if out.FlowID != "flow-y" {
		t.Errorf("FlowID = %q, want flow-y", out.FlowID)
	}
	<-actionCh // drain
}
