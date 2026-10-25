package mcp

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// Unit coverage for intercept modify_and_forward on a held HTTP message
// whose body was spilled to disk (HTTPMessage.Body nil, content in a
// file-backed BodyBuffer). The integration counterpart, which drives a real
// listener, lives in intercept_spilled_body_patch_integration_test.go.

const unitSpillPrefix = "mcp-unit-spill"

// spilledJSONBody is the held body. "target" is the only key the json_path
// tests rewrite.
const spilledJSONBody = `{"keep":"same","target":"old","tail":[1,2,3]}`

// newSpilledHTTPEnv returns a Send-direction HTTP envelope whose body and
// wire body live in file-backed buffers in dir, each at refCount=1 (the
// reference the session owns). Callers release it with ReleaseBuffers.
func newSpilledHTTPEnv(t *testing.T, dir, body string) *envelope.Envelope {
	t.Helper()
	newBuf := func(payload string) *bodybuf.BodyBuffer {
		buf, err := bodybuf.NewFile(dir, unitSpillPrefix, 0)
		if err != nil {
			t.Fatalf("bodybuf.NewFile: %v", err)
		}
		if _, err := buf.Write([]byte(payload)); err != nil {
			t.Fatalf("bodybuf.Write: %v", err)
		}
		return buf
	}
	return &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"),
		RawBuffer: newBuf(body),
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/api",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
			},
			BodyBuffer: newBuf(body),
		},
	}
}

func countUnitSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), unitSpillPrefix) {
			n++
		}
	}
	return n
}

func httpMsg(t *testing.T, env *envelope.Envelope) *envelope.HTTPMessage {
	t.Helper()
	hm, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("message is %T, want *HTTPMessage", env.Message)
	}
	return hm
}

func strPtr(s string) *string { return &s }

// TestApplyHTTPModify_SpilledBody_PatchesMaterializedBody: body_patches on
// a spilled body apply to the full materialized body and the result becomes
// the authoritative HTTPMessage.Body.
func TestApplyHTTPModify_SpilledBody_PatchesMaterializedBody(t *testing.T) {
	tests := []struct {
		name  string
		patch BodyPatch
		want  string
	}{
		{
			name:  "json_path",
			patch: BodyPatch{JSONPath: "$.target", Value: "new"},
			want:  `{"keep":"same","target":"new","tail":[1,2,3]}`,
		},
		{
			name:  "regex",
			patch: BodyPatch{Regex: `"old"`, Replace: `"new"`},
			want:  `{"keep":"same","target":"new","tail":[1,2,3]}`,
		},
		{
			name:  "empty_match_start",
			patch: BodyPatch{Regex: `^`, Replace: "PRE"},
			want:  "PRE" + spilledJSONBody,
		},
		{
			name:  "empty_match_end",
			patch: BodyPatch{Regex: `$`, Replace: "POST"},
			want:  spilledJSONBody + "POST",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := newSpilledHTTPEnv(t, dir, spilledJSONBody)
			defer env.ReleaseBuffers()

			mod, err := applyHTTPModify(context.Background(), env, httpMsg(t, env), &httpMessageModify{
				BodyPatches: []BodyPatch{tc.patch},
			})
			if err != nil {
				t.Fatalf("applyHTTPModify: %v", err)
			}
			defer mod.ReleaseBuffers()
			hm := httpMsg(t, mod)
			if string(hm.Body) != tc.want {
				t.Errorf("Body = %q, want %q", hm.Body, tc.want)
			}
			if hm.BodyBuffer != nil {
				t.Errorf("BodyBuffer still set after a committed patch; senders would prefer the stale buffer")
			}
		})
	}
}

// TestApplyHTTPModify_SpilledBody_NoopPatchKeepsBodyBuffer is a guard: a
// patch that changes nothing must not commit the materialized bytes to
// Body, because on HTTP/1.x a Body change re-frames the request (drops
// Transfer-Encoding, re-stamps Content-Length) — a wire change nobody asked
// for.
func TestApplyHTTPModify_SpilledBody_NoopPatchKeepsBodyBuffer(t *testing.T) {
	dir := t.TempDir()
	env := newSpilledHTTPEnv(t, dir, spilledJSONBody)
	defer env.ReleaseBuffers()
	orig := httpMsg(t, env).BodyBuffer

	mod, err := applyHTTPModify(context.Background(), env, httpMsg(t, env), &httpMessageModify{
		BodyPatches: []BodyPatch{{Regex: `no-such-text`, Replace: "x"}},
	})
	if err != nil {
		t.Fatalf("applyHTTPModify: %v", err)
	}
	defer mod.ReleaseBuffers()
	hm := httpMsg(t, mod)
	if hm.Body != nil {
		t.Errorf("Body = %q, want nil (no-op patch must not commit)", hm.Body)
	}
	if hm.BodyBuffer != orig {
		t.Errorf("BodyBuffer = %p, want the held buffer %p", hm.BodyBuffer, orig)
	}
}

// TestApplyHTTPModify_SpilledBody_ReleasesCloneRefs: whatever arm runs, the
// modify clone's buffer references are either released by applyHTTPModify
// (when it drops them) or by the clone's owner via ReleaseBuffers. After
// the source envelope releases its single reference, no file remains.
func TestApplyHTTPModify_SpilledBody_ReleasesCloneRefs(t *testing.T) {
	tests := []struct {
		name   string
		params *httpMessageModify
	}{
		{name: "body_patches", params: &httpMessageModify{BodyPatches: []BodyPatch{{JSONPath: "$.target", Value: "new"}}}},
		{name: "body_replacement", params: &httpMessageModify{Body: strPtr(`{"replaced":true}`)}},
		{name: "noop_patch", params: &httpMessageModify{BodyPatches: []BodyPatch{{Regex: `no-such-text`, Replace: "x"}}}},
		{name: "header_only", params: &httpMessageModify{Headers: []headerKV{{Name: "Host", Value: "example.com"}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := newSpilledHTTPEnv(t, dir, spilledJSONBody)

			mod, err := applyHTTPModify(context.Background(), env, httpMsg(t, env), tc.params)
			if err != nil {
				t.Fatalf("applyHTTPModify: %v", err)
			}
			mod.ReleaseBuffers()
			env.ReleaseBuffers()
			if n := countUnitSpillFiles(t, dir); n != 0 {
				t.Errorf("%d spill files remain, want 0 (modify clone reference leaked)", n)
			}
		})
	}
}

// TestApplyHTTPModify_SpilledBody_ErrorReleasesCloneRefs: a failed modify
// returns no envelope, so it must release the references its clone took.
func TestApplyHTTPModify_SpilledBody_ErrorReleasesCloneRefs(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		body    string
		params  *httpMessageModify
		wantErr string
	}{
		{
			name:    "json_path_on_non_json",
			ctx:     context.Background(),
			body:    "not json at all",
			params:  &httpMessageModify{BodyPatches: []BodyPatch{{JSONPath: "$.target", Value: "new"}}},
			wantErr: "not valid JSON",
		},
		{
			name:    "cancelled_ctx",
			ctx:     cancelled,
			body:    spilledJSONBody,
			params:  &httpMessageModify{BodyPatches: []BodyPatch{{JSONPath: "$.target", Value: "new"}}},
			wantErr: "materialize spilled body",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := newSpilledHTTPEnv(t, dir, tc.body)

			mod, err := applyHTTPModify(tc.ctx, env, httpMsg(t, env), tc.params)
			if err == nil {
				mod.ReleaseBuffers()
				t.Fatalf("applyHTTPModify succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			env.ReleaseBuffers()
			if n := countUnitSpillFiles(t, dir); n != 0 {
				t.Errorf("%d spill files remain after a failed modify, want 0", n)
			}
		})
	}
}

// TestApplyHTTPModify_SpilledBody_VanishedFileErrorOmitsPath: when the spill
// file disappears under a live reference (e.g. an external tmp cleaner),
// the MCP-facing error keeps the materialize prefix but must not carry the
// spill directory or file name (CWE-209).
func TestApplyHTTPModify_SpilledBody_VanishedFileErrorOmitsPath(t *testing.T) {
	dir := t.TempDir()
	env := newSpilledHTTPEnv(t, dir, spilledJSONBody)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if err := os.Remove(dir + string(os.PathSeparator) + e.Name()); err != nil {
			t.Fatalf("remove spill file: %v", err)
		}
	}

	mod, err := applyHTTPModify(context.Background(), env, httpMsg(t, env),
		&httpMessageModify{BodyPatches: []BodyPatch{{JSONPath: "$.target", Value: "new"}}})
	if err == nil {
		mod.ReleaseBuffers()
		t.Fatal("applyHTTPModify succeeded on a vanished spill file, want error")
	}
	env.ReleaseBuffers()
	msg := err.Error()
	if !strings.Contains(msg, "body_patches: materialize spilled body") {
		t.Errorf("error = %q, want the materialize prefix", msg)
	}
	if strings.Contains(msg, dir) || strings.Contains(msg, unitSpillPrefix) {
		t.Errorf("error = %q leaks the spill path to the MCP client", msg)
	}
}

// TestApplyHoldQueueRawOverride_SpilledBody_ReleasesCloneRefs: a raw
// override replaces the HTTP message with raw bytes, so neither the cloned
// BodyBuffer nor the stale RawBuffer may stay referenced.
func TestApplyHoldQueueRawOverride_SpilledBody_ReleasesCloneRefs(t *testing.T) {
	dir := t.TempDir()
	env := newSpilledHTTPEnv(t, dir, spilledJSONBody)

	mod, err := applyHoldQueueRawOverride(env, "R0VUIC8gSFRUUC8xLjENCg0K") // "GET / HTTP/1.1\r\n\r\n"
	if err != nil {
		t.Fatalf("applyHoldQueueRawOverride: %v", err)
	}
	if mod.RawBuffer != nil {
		t.Errorf("raw override kept the held RawBuffer; WireBytes would append the stale spilled body to the override")
	}
	mod.ReleaseBuffers()
	env.ReleaseBuffers()
	if n := countUnitSpillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files remain after a raw override, want 0", n)
	}
}

// newSpillHoldQueueSession connects an in-memory MCP client to a server
// whose intercept tool resolves against queue.
func newSpillHoldQueueSession(t *testing.T, queue *common.HoldQueue) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := newServer(ctx, newTestCA(t), nil, nil, WithHoldQueue(queue))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "spill-unit", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// TestInterceptTool_SpilledBody_FailedPatchKeepsHoldAndLeaksNothing: a
// body_patches error surfaces as a tool error, the entry stays held (the
// original is never forwarded behind the agent's back), and the clones the
// tool took are released — once the hold is resolved and the session
// releases its reference, nothing is left on disk.
func TestInterceptTool_SpilledBody_FailedPatchKeepsHoldAndLeaksNothing(t *testing.T) {
	dir := t.TempDir()
	queue := common.NewHoldQueue()
	cs := newSpillHoldQueueSession(t, queue)
	env := newSpilledHTTPEnv(t, dir, spilledJSONBody)

	actionCh := make(chan *common.HoldAction, 1)
	go func() {
		a, _ := queue.Hold(context.Background(), env, []string{"r"})
		actionCh <- a
	}()
	deadline := time.Now().Add(2 * time.Second)
	for queue.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	entries := queue.List()
	if len(entries) != 1 {
		t.Fatalf("held entries = %d, want 1", len(entries))
	}
	id := entries[0].ID
	entries[0].Envelope.ReleaseBuffers()

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "intercept",
		Arguments: map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{"intercept_id": id},
			"http": map[string]any{
				"body_patches": []map[string]any{{"json_path": "$.missing.deep", "value": "x"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("intercept with a failing json_path succeeded; want a tool error")
	}
	if queue.Len() != 1 {
		t.Fatalf("queue length after failed modify = %d, want 1 (hold must stay pending)", queue.Len())
	}

	if err := queue.Release(id, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if a := <-actionCh; a == nil || a.Type != common.ActionRelease {
		t.Fatalf("Hold returned %v, want release", a)
	}
	env.ReleaseBuffers()
	if n := countUnitSpillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files remain, want 0", n)
	}
}

// TestInterceptTool_SpilledBody_ModifyAndForwardPatches drives the tool
// end to end against a held spilled envelope: the forwarded envelope
// carries the patched body, and once its owner and the session release
// their references no file remains.
func TestInterceptTool_SpilledBody_ModifyAndForwardPatches(t *testing.T) {
	dir := t.TempDir()
	queue := common.NewHoldQueue()
	cs := newSpillHoldQueueSession(t, queue)
	env := newSpilledHTTPEnv(t, dir, spilledJSONBody)

	actionCh := make(chan *common.HoldAction, 1)
	go func() {
		a, _ := queue.Hold(context.Background(), env, []string{"r"})
		actionCh <- a
	}()
	deadline := time.Now().Add(2 * time.Second)
	for queue.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	entries := queue.List()
	if len(entries) != 1 {
		t.Fatalf("held entries = %d, want 1", len(entries))
	}
	id := entries[0].ID
	entries[0].Envelope.ReleaseBuffers()

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "intercept",
		Arguments: map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{"intercept_id": id},
			"http": map[string]any{
				"body_patches": []map[string]any{{"json_path": "$.target", "value": "new"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("intercept returned a tool error: %v", res.Content)
	}
	a := <-actionCh
	if a == nil || a.Type != common.ActionModifyAndForward || a.Modified == nil {
		t.Fatalf("Hold returned %+v, want modify_and_forward with an envelope", a)
	}
	want := []byte(`{"keep":"same","target":"new","tail":[1,2,3]}`)
	if got := httpMsg(t, a.Modified).Body; !bytes.Equal(got, want) {
		t.Errorf("forwarded body = %q, want %q", got, want)
	}
	a.Modified.ReleaseBuffers()
	env.ReleaseBuffers()
	if n := countUnitSpillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files remain, want 0", n)
	}
}
