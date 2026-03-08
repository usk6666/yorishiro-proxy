package ws

import (
	"context"
	"encoding/binary"
	"net"
	gohttp "net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// writeStarlarkScript creates a Starlark script file in dir and returns its path.
func writeStarlarkScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

// setupPluginEngine creates a plugin.Engine with the given script and hooks.
func setupPluginEngine(t *testing.T, scriptPath, protocol string, hooks []string) *plugin.Engine {
	t.Helper()
	engine := plugin.NewEngine(nil)
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: protocol,
			Hooks:    hooks,
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	if engine.PluginCount() != 1 {
		t.Fatalf("expected 1 plugin loaded, got %d", engine.PluginCount())
	}
	return engine
}

func TestHandleUpgrade_PluginContinue(t *testing.T) {
	// Plugin that passes through frames unmodified.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "continue.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE, "data": data}

def on_before_send_to_server(data):
    return {"action": action.CONTINUE, "data": data}

def on_receive_from_server(data):
    return {"action": action.CONTINUE, "data": data}

def on_before_send_to_client(data):
    return {"action": action.CONTINUE, "data": data}
`)
	engine := setupPluginEngine(t, scriptPath, "websocket", []string{
		"on_receive_from_client",
		"on_before_send_to_server",
		"on_receive_from_server",
		"on_before_send_to_client",
	})
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-plugin-1", "127.0.0.1:1234", nil)
	}()

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("hello plugin"),
		})
	}()

	// Upstream receives the frame unchanged.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "hello plugin" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "hello plugin")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			Payload: closePayload,
		})
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_PluginDropFrame(t *testing.T) {
	// Plugin that drops frames containing "drop-me".
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "drop.star", `
def on_receive_from_client(data):
    payload = data.get("payload", "")
    # Convert payload to string for matching.
    payload_str = str(payload)
    if "drop-me" in payload_str:
        return {"action": action.DROP}
    return {"action": action.CONTINUE, "data": data}
`)
	engine := setupPluginEngine(t, scriptPath, "websocket", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-plugin-2", "127.0.0.1:2345", nil)
	}()

	// Client sends a frame that should be dropped, then one that passes.
	go func() {
		// This frame should be dropped.
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04},
			Payload: []byte("drop-me please"),
		})
		// This frame should pass through.
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x05, 0x06, 0x07, 0x08},
			Payload: []byte("keep me"),
		})
	}()

	// Upstream should only receive the second frame.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "keep me" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "keep me")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			Payload: closePayload,
		})
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_PluginModifyPayload(t *testing.T) {
	// Plugin that replaces the payload with a fixed string.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "modify.star", `
def on_before_send_to_server(data):
    return {"action": action.CONTINUE, "data": {"payload": "modified-payload"}}
`)
	engine := setupPluginEngine(t, scriptPath, "websocket", []string{
		"on_before_send_to_server",
	})
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-plugin-3", "127.0.0.1:3456", nil)
	}()

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("original"),
		})
	}()

	// Upstream should receive the modified payload.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "modified-payload" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "modified-payload")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			Payload: closePayload,
		})
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_PluginReceivesFrameData(t *testing.T) {
	// Plugin that verifies it receives all expected fields.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "verify.star", `
def on_receive_from_client(data):
    # Verify expected fields exist.
    assert_keys = ["opcode", "opcode_name", "payload", "fin", "direction", "upgrade_url", "conn_info"]
    for key in assert_keys:
        if key not in data:
            fail("missing key: " + key)

    # Verify direction.
    if data["direction"] != "client_to_server":
        fail("expected direction client_to_server, got " + data["direction"])

    # Verify opcode_name.
    if data["opcode_name"] != "text":
        fail("expected opcode_name text, got " + data["opcode_name"])

    # Verify upgrade_url.
    if "example.com" not in data["upgrade_url"]:
        fail("expected upgrade_url to contain example.com, got " + data["upgrade_url"])

    # Verify conn_info is a dict.
    ci = data["conn_info"]
    if type(ci) != "dict":
        fail("expected conn_info to be dict, got " + type(ci))

    return {"action": action.CONTINUE, "data": data}
`)
	engine := setupPluginEngine(t, scriptPath, "websocket", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	connInfo := &flow.ConnectionInfo{
		ClientAddr: "10.0.0.1:12345",
		ServerAddr: "93.184.216.34:443",
		TLSVersion: "TLS 1.3",
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-plugin-4", "10.0.0.1:12345", connInfo)
	}()

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("test data"),
		})
	}()

	// If plugin fails (via fail()), the frame would still pass through
	// because on_error is "skip". We verify it passes through.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "test data" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "test data")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			Payload: closePayload,
		})
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_PluginServerToClientDirection(t *testing.T) {
	// Plugin that replaces the payload of server-to-client frames.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "server_modify.star", `
def on_before_send_to_client(data):
    return {"action": action.CONTINUE, "data": {"payload": "server-modified"}}
`)
	engine := setupPluginEngine(t, scriptPath, "websocket", []string{
		"on_before_send_to_client",
	})
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-plugin-5", "127.0.0.1:5678", nil)
	}()

	// Server sends a text frame.
	go func() {
		WriteFrame(upstreamEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Payload: []byte("server says"),
		})
	}()

	// Client should receive the modified payload.
	received, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(received.Payload) != "server-modified" {
		t.Errorf("client received = %q, want %q", received.Payload, "server-modified")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(upstreamEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Payload: closePayload,
		})
	}()
	ReadFrame(clientEnd)
	clientEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_NilPluginEngine(t *testing.T) {
	// Verify handler works correctly with nil plugin engine (no-op).
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// Do NOT call SetPluginEngine — pluginEngine is nil.

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-nil-engine", "127.0.0.1:9999", nil)
	}()

	// Send and receive a frame normally.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x11, 0x22, 0x33, 0x44},
			Payload: []byte("no plugin"),
		})
	}()

	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "no plugin" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "no plugin")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			Payload: closePayload,
		})
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestBuildFrameData(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("test"),
	}

	req, _ := gohttp.NewRequest("GET", "ws://example.com/chat", nil)
	connInfo := &flow.ConnectionInfo{
		ClientAddr: "10.0.0.1:1234",
		ServerAddr: "10.0.0.2:443",
		TLSVersion: "TLS 1.3",
		TLSCipher:  "AES_256_GCM",
	}

	data := handler.buildFrameData(frame, "client_to_server", req, connInfo)

	// Verify all expected keys.
	if data["opcode"] != int(OpcodeText) {
		t.Errorf("opcode = %v, want %d", data["opcode"], OpcodeText)
	}
	if data["opcode_name"] != "text" {
		t.Errorf("opcode_name = %v, want %q", data["opcode_name"], "text")
	}
	if string(data["payload"].([]byte)) != "test" {
		t.Errorf("payload = %v, want %q", data["payload"], "test")
	}
	if data["fin"] != true {
		t.Errorf("fin = %v, want true", data["fin"])
	}
	if data["direction"] != "client_to_server" {
		t.Errorf("direction = %v, want %q", data["direction"], "client_to_server")
	}
	if data["upgrade_url"] != "ws://example.com/chat" {
		t.Errorf("upgrade_url = %v, want %q", data["upgrade_url"], "ws://example.com/chat")
	}

	ci, ok := data["conn_info"].(map[string]any)
	if !ok {
		t.Fatalf("conn_info is not map[string]any: %T", data["conn_info"])
	}
	if ci["client_addr"] != "10.0.0.1:1234" {
		t.Errorf("conn_info.client_addr = %v, want %q", ci["client_addr"], "10.0.0.1:1234")
	}
	if ci["tls_version"] != "TLS 1.3" {
		t.Errorf("conn_info.tls_version = %v, want %q", ci["tls_version"], "TLS 1.3")
	}
}

func TestDispatchFrameHook_PayloadSizeLimit(t *testing.T) {
	// Register a plugin handler that returns an oversized payload via the registry.
	engine := plugin.NewEngine(nil)
	registry := engine.Registry()

	// Create a payload that exceeds config.MaxWebSocketMessageSize.
	oversized := make([]byte, int(config.MaxWebSocketMessageSize)+1)
	for i := range oversized {
		oversized[i] = 'X'
	}

	registry.Register("oversized-plugin", plugin.HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*plugin.HookResult, error) {
		return &plugin.HookResult{
			Action: plugin.ActionContinue,
			Data:   map[string]any{"payload": oversized},
		}, nil
	}, plugin.OnErrorSkip)

	handler := NewHandler(nil, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	originalPayload := []byte("original")
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: originalPayload,
	}

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)

	txCtx := plugin.NewTxCtx()
	dropped := handler.dispatchFrameHook(
		context.Background(),
		plugin.HookOnReceiveFromClient,
		frame,
		"client_to_server",
		req,
		nil,
		"test-flow",
		txCtx,
	)

	if dropped {
		t.Fatal("frame should not be dropped")
	}

	// The payload should remain the original because the oversized modification
	// must be rejected.
	if string(frame.Payload) != "original" {
		t.Errorf("payload = %q (len=%d), want %q; oversized plugin payload should be rejected",
			frame.Payload, len(frame.Payload), "original")
	}
}

func TestDispatchFrameHook_PayloadWithinLimit(t *testing.T) {
	// Register a plugin handler that returns a payload within the limit.
	engine := plugin.NewEngine(nil)
	registry := engine.Registry()

	registry.Register("ok-plugin", plugin.HookOnReceiveFromClient, func(ctx context.Context, data map[string]any) (*plugin.HookResult, error) {
		return &plugin.HookResult{
			Action: plugin.ActionContinue,
			Data:   map[string]any{"payload": "modified-ok"},
		}, nil
	}, plugin.OnErrorSkip)

	handler := NewHandler(nil, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("original"),
	}

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)

	txCtx := plugin.NewTxCtx()
	dropped := handler.dispatchFrameHook(
		context.Background(),
		plugin.HookOnReceiveFromClient,
		frame,
		"client_to_server",
		req,
		nil,
		"test-flow",
		txCtx,
	)

	if dropped {
		t.Fatal("frame should not be dropped")
	}

	if string(frame.Payload) != "modified-ok" {
		t.Errorf("payload = %q, want %q", frame.Payload, "modified-ok")
	}
}

func TestBuildFrameData_NilConnInfo(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeBinary,
		Payload: []byte{0x01, 0x02},
	}

	data := handler.buildFrameData(frame, "server_to_client", nil, nil)

	if data["upgrade_url"] != "" {
		t.Errorf("upgrade_url = %v, want empty string", data["upgrade_url"])
	}
	ci, ok := data["conn_info"].(map[string]any)
	if !ok {
		t.Fatalf("conn_info is not map[string]any: %T", data["conn_info"])
	}
	// With nil connInfo, the map should be empty.
	if len(ci) != 0 {
		t.Errorf("conn_info should be empty, got %v", ci)
	}
}
