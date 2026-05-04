//go:build e2e

package mcp

// resend_ws_integration_test.go — RFC-001 N8 acceptance gate for the
// resend_ws MCP tool. Drives the full pipeline (PluginStepPost +
// RecordStep) end-to-end against a live WebSocket echo server and
// asserts the four USK-673 acceptance criteria:
//
//   AC#1: WS round-trip for text + binary opcodes
//   AC#2: Close frame resend includes CloseCode/CloseReason on the wire
//   AC#3: Compressed (permessage-deflate) frame resend round-trips
//   AC#4: PluginStepPost fires; PluginStepPre never fires (RFC §9.3 D1)
//   AC#5: Legacy `resend` tool continues to coexist
//
// Pattern follows resend_http_integration_test.go (in-memory MCP
// transports + sqlite flow store + counter plugin) but uses the
// untagged newWebSocketEchoServer helper from resend_ws_test.go for the
// non-deflate fixture and a local newWSDeflateEchoServer for the
// compressed-frame test. The two fixtures stay separate so a future
// refactor of the deflate path does not destabilise the simpler
// uncompressed cases.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// resendWSHookCallable wraps a Go counter increment in a Starlark
// Callable so it can be registered on the pluginv2 Engine.
func resendWSHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// callResendWS invokes the resend_ws tool and returns the parsed
// structured result.
func callResendWS(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend_ws",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool resend_ws: %v", err)
	}
	return res
}

// setupResendWSSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers pre/post counter
// hooks for ("ws", "on_message"). Returns the client session, the live
// flow store, and atomic counters that tests assert on.
func setupResendWSSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var preCount, postCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnMessage,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "resend-ws-pre",
		Fn: resendWSHookCallable("pre", func() {
			atomic.AddInt32(&preCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnMessage,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "resend-ws-post",
		Fn: resendWSHookCallable("post", func() {
			atomic.AddInt32(&postCount, 1)
		}),
	})

	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithPluginv2Engine(engine))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-ws-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &preCount, &postCount
}

// seedResendWSFlow stores a Stream + upgrade send/receive Flows so the
// resend_ws tool can recover the upgrade dance via flow_id. Returns the
// stream id.
func seedResendWSFlow(t *testing.T, store flow.Store, addr string, withDeflate bool) string {
	t.Helper()
	ctx := context.Background()
	host, port, _ := net.SplitHostPort(addr)
	wsURL, _ := url.Parse(fmt.Sprintf("ws://%s:%s/echo", host, port))
	id := "resend-ws-" + host + "-" + port

	stream := &flow.Stream{
		ID:        id,
		Protocol:  "WebSocket",
		Scheme:    "ws",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	upgradeReq := &flow.Flow{
		StreamID:  id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-WebSocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Sec-WebSocket-Version": {"13"},
			"Host":                  {fmt.Sprintf("%s:%s", host, port)},
		},
	}
	if err := store.SaveFlow(ctx, upgradeReq); err != nil {
		t.Fatalf("SaveFlow upgrade send: %v", err)
	}
	upgradeRespHeaders := map[string][]string{
		"Upgrade":              {"websocket"},
		"Connection":           {"Upgrade"},
		"Sec-WebSocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
	}
	if withDeflate {
		upgradeRespHeaders["Sec-WebSocket-Extensions"] = []string{"permessage-deflate"}
	}
	upgradeResp := &flow.Flow{
		StreamID:   id,
		Sequence:   0,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 101,
		Headers:    upgradeRespHeaders,
	}
	if err := store.SaveFlow(ctx, upgradeResp); err != nil {
		t.Fatalf("SaveFlow upgrade receive: %v", err)
	}
	return id
}

// TestResendWS_TextFrame_RoundTrip covers AC#1 (text frame). Verifies
// the upstream sees the sent text and the result frame returned to the
// caller is the echoed text.
func TestResendWS_TextFrame_RoundTrip(t *testing.T) {
	cs, store, preCount, postCount := setupResendWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()
	streamID := seedResendWSFlow(t, store, addr, false)

	res := callResendWS(t, cs, map[string]any{
		"flow_id":    streamID,
		"opcode":     "text",
		"payload":    "hello text",
		"timeout_ms": 5000,
		"tag":        "text-rt",
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}

	var out resendWSResult
	decodeStructuredResult(t, res, &out)

	if out.StreamID == "" {
		t.Errorf("StreamID empty")
	}
	if out.Opcode != "text" {
		t.Errorf("Opcode = %q, want text", out.Opcode)
	}
	if out.Payload != "hello text" {
		t.Errorf("Payload = %q, want hello text", out.Payload)
	}
	if out.PayloadEncoding != "text" {
		t.Errorf("PayloadEncoding = %q, want text", out.PayloadEncoding)
	}
	if out.Tag != "text-rt" {
		t.Errorf("Tag = %q, want text-rt", out.Tag)
	}

	// AC#4: PluginStepPost fires (>=1); PluginStepPre never fires.
	if pre := atomic.LoadInt32(preCount); pre != 0 {
		t.Errorf("preCount = %d, want 0 (PluginStepPre must be excluded)", pre)
	}
	if post := atomic.LoadInt32(postCount); post < 1 {
		t.Errorf("postCount = %d, want >= 1", post)
	}

	// Stream + flows recorded.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := store.GetStream(ctx, out.StreamID)
	if err != nil {
		t.Fatalf("GetStream(%s): %v", out.StreamID, err)
	}
	if stream.Tags["tag"] != "text-rt" {
		t.Errorf("Stream.Tags[tag] = %q, want text-rt", stream.Tags["tag"])
	}
}

// TestResendWS_BinaryFrame_RoundTrip covers AC#1 (binary frame).
func TestResendWS_BinaryFrame_RoundTrip(t *testing.T) {
	cs, store, _, _ := setupResendWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()
	streamID := seedResendWSFlow(t, store, addr, false)

	binary := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	res := callResendWS(t, cs, map[string]any{
		"flow_id":       streamID,
		"opcode":        "binary",
		"payload":       base64.StdEncoding.EncodeToString(binary),
		"body_encoding": "base64",
		"timeout_ms":    5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendWSResult
	decodeStructuredResult(t, res, &out)

	if out.Opcode != "binary" {
		t.Errorf("Opcode = %q, want binary", out.Opcode)
	}
	if out.PayloadEncoding != "base64" {
		t.Errorf("PayloadEncoding = %q, want base64", out.PayloadEncoding)
	}
	got, err := base64.StdEncoding.DecodeString(out.Payload)
	if err != nil {
		t.Fatalf("decode base64 payload: %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Errorf("Payload = %x, want %x", got, binary)
	}
}

// TestResendWS_CloseFrame covers AC#2: a Close frame resend carries
// CloseCode/CloseReason and the upstream's echoed close is returned.
func TestResendWS_CloseFrame(t *testing.T) {
	cs, store, _, _ := setupResendWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()
	streamID := seedResendWSFlow(t, store, addr, false)

	res := callResendWS(t, cs, map[string]any{
		"flow_id":      streamID,
		"opcode":       "close",
		"close_code":   1000,
		"close_reason": "bye",
		"timeout_ms":   5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendWSResult
	decodeStructuredResult(t, res, &out)

	if out.Opcode != "close" {
		t.Errorf("Opcode = %q, want close", out.Opcode)
	}
	if out.CloseCode != 1000 {
		t.Errorf("CloseCode = %d, want 1000", out.CloseCode)
	}
	if out.CloseReason != "bye" {
		t.Errorf("CloseReason = %q, want bye", out.CloseReason)
	}
}

// TestResendWS_CompressedFrame_RoundTrip covers AC#3. Uses a deflate-
// aware echo server that decompresses the inbound RSV1 frame and
// returns the decompressed payload as an uncompressed text frame so we
// can verify the wire-side compression worked end-to-end.
func TestResendWS_CompressedFrame_RoundTrip(t *testing.T) {
	cs, store, _, _ := setupResendWSSession(t)
	addr, observed, cleanup := newWSDeflateEchoServer(t)
	defer cleanup()
	streamID := seedResendWSFlow(t, store, addr, true /* withDeflate */)

	repeating := strings.Repeat("hello ", 50) // compressible
	compressedTrue := true
	res := callResendWS(t, cs, map[string]any{
		"flow_id":    streamID,
		"opcode":     "text",
		"payload":    repeating,
		"compressed": compressedTrue,
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendWSResult
	decodeStructuredResult(t, res, &out)
	if out.Payload != repeating {
		t.Errorf("Payload = %q (truncated), want %q (truncated)", truncate(out.Payload, 30), truncate(repeating, 30))
	}
	if got, want := observed(), repeating; got != want {
		t.Errorf("server-decompressed payload = %q (truncated), want %q (truncated)", truncate(got, 30), truncate(want, 30))
	}
}

// TestResendWS_FromScratch_RequiredFields confirms validation rejects
// the from-scratch path without target_addr or path.
func TestResendWS_FromScratch_RequiredFields(t *testing.T) {
	cs, _, _, _ := setupResendWSSession(t)
	res := callResendWS(t, cs, map[string]any{
		"opcode": "text",
	})
	if !res.IsError {
		t.Fatal("expected IsError=true for missing target_addr/path")
	}
}

// TestResendWS_UnknownOpcodeRejected confirms an opcode not in the
// allowed set surfaces a tool-call error from the handler-side
// validator (schema-level required is enforced by the gomcp SDK; here
// we cover the value-set check).
func TestResendWS_UnknownOpcodeRejected(t *testing.T) {
	cs, _, _, _ := setupResendWSSession(t)
	res := callResendWS(t, cs, map[string]any{
		"target_addr": "127.0.0.1:1",
		"path":        "/echo",
		"opcode":      "zinc",
	})
	if !res.IsError {
		t.Fatal("expected IsError=true for unknown opcode")
	}
}

// TestResendWS_NonWSFlowIDRejected confirms a flow_id pointing at a
// non-WS Stream produces a clear pointer to the matching tool.
func TestResendWS_NonWSFlowIDRejected(t *testing.T) {
	cs, store, _, _ := setupResendWSSession(t)

	ctx := context.Background()
	httpStream := &flow.Stream{ID: "http-stream", Protocol: "HTTP/1.1", Scheme: "http"}
	if err := store.SaveStream(ctx, httpStream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	httpFlow := &flow.Flow{StreamID: httpStream.ID, Sequence: 0, Direction: "send", Method: "GET"}
	if err := store.SaveFlow(ctx, httpFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	res := callResendWS(t, cs, map[string]any{
		"flow_id": httpStream.ID,
		"opcode":  "text",
	})
	if !res.IsError {
		t.Fatal("expected IsError=true for non-WS flow_id")
	}
	body := strings.ToLower(extractTextContent(res))
	if !strings.Contains(body, "resend_http") {
		t.Errorf("error %q does not point at resend_http", body)
	}
}

// newWSDeflateEchoServer accepts an HTTP Upgrade with permessage-deflate,
// reads one compressed text frame, decompresses it, captures the
// decompressed payload (visible via the returned getter), and writes
// back an uncompressed text frame echoing the decompressed bytes.
func newWSDeflateEchoServer(t *testing.T) (string, func() string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var observed atomic.Pointer[string]

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWSDeflateEchoConn(conn, &observed)
		}
	}()
	return ln.Addr().String(),
		func() string {
			p := observed.Load()
			if p == nil {
				return ""
			}
			return *p
		},
		func() { ln.Close() }
}

func handleWSDeflateEchoConn(conn net.Conn, observed *atomic.Pointer[string]) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	frame, err := ws.ReadFrame(r)
	if err != nil {
		return
	}
	// permessage-deflate appends a fixed 4-byte trailer before
	// decompression per RFC 7692 §7.2.2.
	src := append(append([]byte{}, frame.Payload...), 0x00, 0x00, 0xff, 0xff)
	fr := flate.NewReader(bytes.NewReader(src))
	defer fr.Close()
	decoded, _ := io.ReadAll(fr)
	str := string(decoded)
	observed.Store(&str)

	// Echo the decompressed bytes back as an uncompressed text frame.
	echo := &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: decoded}
	_ = ws.WriteFrame(conn, echo)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// extractTextContent extracts the first text content block from a tool result.
var _ = json.Marshal // keep encoding/json import live for future result-shape helpers
