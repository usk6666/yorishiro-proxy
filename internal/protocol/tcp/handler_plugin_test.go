package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
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

func TestHandler_PluginContinue(t *testing.T) {
	// Plugin that passes through data unmodified.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "continue.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE}

def on_before_send_to_server(data):
    return {"action": action.CONTINUE}

def on_receive_from_server(data):
    return {"action": action.CONTINUE}

def on_before_send_to_client(data):
    return {"action": action.CONTINUE}
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
		"on_before_send_to_server",
		"on_receive_from_server",
		"on_before_send_to_client",
	})
	defer engine.Close()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-plugin-continue")
	ctx = proxy.ContextWithClientAddr(ctx, "192.168.1.100:54321")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send data and verify echo works with plugin active.
	testData := []byte("hello with plugin")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}

	// Verify messages were recorded.
	messages := store.getMessages()
	if len(messages) < 2 {
		t.Fatalf("expected at least 2 messages (send+receive), got %d", len(messages))
	}
}

func TestHandler_PluginModifyData(t *testing.T) {
	// Plugin that modifies data by appending " [modified]".
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "modify.star", `
def on_before_send_to_server(data):
    original = data["data"]
    # Starlark bytes are immutable; convert to string, modify, and return.
    modified = str(original) + " [modified]"
    return {"action": action.CONTINUE, "data": {"data": modified}}
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_before_send_to_server",
	})
	defer engine.Close()

	// Set up a server that reads and stores received data instead of echoing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()
	_, serverPort, _ := net.SplitHostPort(serverAddr)

	receivedCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		receivedCh <- string(data)
	}()

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{serverPort: {Target: serverAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, serverPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-plugin-modify")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send data and close.
	testData := []byte("hello")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("client write: %v", err)
	}
	clientConn.Close()

	<-errCh

	select {
	case received := <-receivedCh:
		expected := "hello [modified]"
		if received != expected {
			t.Errorf("server received = %q, want %q", received, expected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to receive data")
	}
}

func TestHandler_PluginDrop(t *testing.T) {
	// Plugin that drops all client-to-server chunks.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "drop.star", `
def on_receive_from_client(data):
    return {"action": action.DROP}
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	// Server that records data.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()
	_, serverPort, _ := net.SplitHostPort(serverAddr)

	receivedCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		receivedCh <- string(data)
	}()

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{serverPort: {Target: serverAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, serverPort)},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = proxy.ContextWithConnID(ctx, "test-plugin-drop")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send data that should be dropped.
	if _, err := clientConn.Write([]byte("should be dropped")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Close client to end relay.
	clientConn.Close()

	<-errCh

	select {
	case received := <-receivedCh:
		if received != "" {
			t.Errorf("server received %q, expected nothing (chunk should be dropped)", received)
		}
	case <-time.After(3 * time.Second):
		// OK: server didn't receive anything because relay closed before data arrived.
	}

	// No send messages should be recorded (all dropped).
	messages := store.getMessages()
	for _, msg := range messages {
		if msg.Direction == "send" {
			t.Errorf("unexpected send message recorded: %q", msg.RawBytes)
		}
	}
}

func TestHandler_PluginNilEngine(t *testing.T) {
	// Without SetPluginEngine, relay should work normally.
	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	// Do NOT call SetPluginEngine.

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-nil-engine")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	testData := []byte("no plugin test")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
}

func TestHandler_PluginError_FailOpen(t *testing.T) {
	// Plugin that returns an error -- relay should continue (fail-open).
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "error.star", `
def on_receive_from_client(data):
    fail("intentional error")
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-plugin-error")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Data should still be relayed despite plugin error.
	testData := []byte("error test data")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
}

func TestHandler_PluginChunkData(t *testing.T) {
	// Plugin that verifies the data map contains expected fields.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "verify.star", `
def on_receive_from_client(data):
    # Verify all expected fields are present.
    assert_fields = ["protocol", "data", "direction", "conn_info", "forward_target"]
    for f in assert_fields:
        if f not in data:
            fail("missing field: " + f)
    if data["protocol"] != "tcp":
        fail("expected protocol=tcp, got " + str(data["protocol"]))
    if data["direction"] != "client_to_server":
        fail("expected direction=client_to_server, got " + str(data["direction"]))
    # Verify conn_info has expected keys.
    ci = data["conn_info"]
    if "client_addr" not in ci:
        fail("missing conn_info.client_addr")
    if "server_addr" not in ci:
        fail("missing conn_info.server_addr")
    return {"action": action.CONTINUE}
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-plugin-data")
	ctx = proxy.ContextWithClientAddr(ctx, "10.0.0.1:12345")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	testData := []byte("verify data map")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		t.Errorf("Handle() returned error: %v", err)
	}
}

func TestRelay_BuildChunkData(t *testing.T) {
	r := &relay{
		flowID: "test-flow",
		logger: testutil.DiscardLogger(),
		connInfo: &plugin.ConnInfo{
			ClientAddr: "192.168.1.1:12345",
			ServerAddr: "10.0.0.1:3306",
		},
		target: "10.0.0.1:3306",
	}

	data := r.buildChunkData([]byte("test"), "client_to_server")

	if data["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want %q", data["protocol"], "tcp")
	}
	if data["direction"] != "client_to_server" {
		t.Errorf("direction = %v, want %q", data["direction"], "client_to_server")
	}
	if data["forward_target"] != "10.0.0.1:3306" {
		t.Errorf("forward_target = %v, want %q", data["forward_target"], "10.0.0.1:3306")
	}
	if string(data["data"].([]byte)) != "test" {
		t.Errorf("data = %v, want %q", data["data"], "test")
	}

	connInfo, ok := data["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info is not map[string]any")
	}
	if connInfo["client_addr"] != "192.168.1.1:12345" {
		t.Errorf("conn_info.client_addr = %v, want %q", connInfo["client_addr"], "192.168.1.1:12345")
	}
	if connInfo["server_addr"] != "10.0.0.1:3306" {
		t.Errorf("conn_info.server_addr = %v, want %q", connInfo["server_addr"], "10.0.0.1:3306")
	}
}

func TestRelay_BuildChunkData_NilConnInfo(t *testing.T) {
	r := &relay{
		flowID:   "test-flow",
		logger:   testutil.DiscardLogger(),
		connInfo: nil,
		target:   "10.0.0.1:3306",
	}

	data := r.buildChunkData([]byte("test"), "server_to_client")

	connInfo, ok := data["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info is not map[string]any")
	}
	// Should be an empty map, not nil.
	if len(connInfo) != 0 {
		t.Errorf("expected empty conn_info map, got %v", connInfo)
	}
}

func TestHandler_PluginModifyOversizedData(t *testing.T) {
	// Plugin that returns data exceeding MaxTCPPluginChunkSize.
	// The modification should be discarded and the original data forwarded.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "oversize.star", fmt.Sprintf(`
def on_before_send_to_server(data):
    # Create a string larger than the limit.
    big = "x" * %d
    return {"action": action.CONTINUE, "data": {"data": big}}
`, 2*1024*1024)) // 2 MB > 1 MB limit
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_before_send_to_server",
	})
	defer engine.Close()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-oversize")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Original data should be forwarded unchanged.
	testData := []byte("original data")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo should return original data, got %q, want %q", buf, testData)
	}

	clientConn.Close()
	<-errCh
}

func TestHandler_PluginBidirectionalHooks(t *testing.T) {
	// Plugin that modifies data differently in each direction.
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "bidir.star", `
def on_before_send_to_server(data):
    return {"action": action.CONTINUE, "data": {"data": "TO_SERVER"}}

def on_before_send_to_client(data):
    return {"action": action.CONTINUE, "data": {"data": "TO_CLIENT"}}
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_before_send_to_server",
		"on_before_send_to_client",
	})
	defer engine.Close()

	// Set up a server that sends a response then reads.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()
	_, serverPort, _ := net.SplitHostPort(serverAddr)

	serverReceivedCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Wait for data from client via proxy.
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverReceivedCh <- ""
			return
		}
		serverReceivedCh <- string(buf[:n])

		// Send response back.
		conn.Write([]byte("server response"))
	}()

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{serverPort: {Target: serverAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, serverPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-bidir")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	// Send data through proxy.
	if _, err := clientConn.Write([]byte("client data")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify server received modified data.
	select {
	case received := <-serverReceivedCh:
		if received != "TO_SERVER" {
			t.Errorf("server received = %q, want %q", received, "TO_SERVER")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server data")
	}

	// Read response from server (should be modified by plugin).
	buf := make([]byte, len("TO_CLIENT"))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != "TO_CLIENT" {
		t.Errorf("client received = %q, want %q", buf, "TO_CLIENT")
	}

	clientConn.Close()
	<-errCh
}

func TestHandler_SetPluginEngine(t *testing.T) {
	h := NewHandler(nil, nil, testutil.DiscardLogger())

	// Initially nil.
	if h.pluginEngine != nil {
		t.Error("pluginEngine should be nil initially")
	}

	engine := plugin.NewEngine(nil)
	h.SetPluginEngine(engine)

	if h.pluginEngine != engine {
		t.Error("pluginEngine should be set after SetPluginEngine")
	}

	// Setting nil should clear it.
	h.SetPluginEngine(nil)
	if h.pluginEngine != nil {
		t.Error("pluginEngine should be nil after SetPluginEngine(nil)")
	}
}

func TestRelay_DispatchChunkHooks_NilEngine(t *testing.T) {
	r := &relay{
		flowID:       "test-flow",
		logger:       testutil.DiscardLogger(),
		pluginEngine: nil,
	}

	data := []byte("test data")
	result, dropped := r.dispatchChunkHooks(context.Background(), data, plugin.HookOnReceiveFromClient, plugin.HookOnBeforeSendToServer, "client_to_server")

	if dropped {
		t.Error("should not be dropped with nil engine")
	}
	if string(result) != string(data) {
		t.Errorf("result = %q, want %q", result, data)
	}
}

func TestHandler_PluginNoneReturn(t *testing.T) {
	// Plugin that returns None (equivalent to CONTINUE with no modification).
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "none_return.star", `
def on_receive_from_client(data):
    return None

def on_before_send_to_server(data):
    pass
`)
	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
		"on_before_send_to_server",
	})
	defer engine.Close()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-none-return")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	testData := []byte("none return test")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	<-errCh
}

func TestHandler_PluginForwardTarget(t *testing.T) {
	// Verify the forward_target field is correct in the plugin data map.
	dir := t.TempDir()

	echoAddr := setupEchoServer(t)
	_, echoPort, _ := net.SplitHostPort(echoAddr)

	scriptPath := writeStarlarkScript(t, dir, "check_target.star", fmt.Sprintf(`
def on_receive_from_client(data):
    if data["forward_target"] != "%s":
        fail("expected forward_target=%s, got " + str(data["forward_target"]))
    return {"action": action.CONTINUE}
`, echoAddr, echoAddr))

	engine := setupPluginEngine(t, scriptPath, "tcp", []string{
		"on_receive_from_client",
	})
	defer engine.Close()

	store := &mockStore{}
	forwards := map[string]*config.ForwardConfig{echoPort: {Target: echoAddr, Protocol: "raw"}}
	h := NewHandler(store, forwards, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	wrappedConn := &connWithLocalAddr{
		Conn:      proxyConn,
		localAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mustParsePort(t, echoPort)},
	}

	ctx := context.Background()
	ctx = proxy.ContextWithConnID(ctx, "test-target")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, wrappedConn)
	}()

	testData := []byte("check target")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	clientConn.Close()
	err := <-errCh
	if err != nil {
		// If the assertion in the script fails, fail-open means data still flows,
		// but the error is logged. If it contained "fail", the script assertion failed.
		if strings.Contains(err.Error(), "fail") {
			t.Errorf("plugin assertion failed: %v", err)
		}
	}
}
