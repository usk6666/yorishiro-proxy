package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// writeStarlarkScript writes a Starlark script to a temp file and returns the path.
func writeStarlarkScript(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestPluginHook_OnReceiveFromClient_Continue(t *testing.T) {
	// Plugin adds X-Plugin-Added header and continues.
	script := writeStarlarkScript(t, "add_header.star", `
def on_receive_from_client(data):
    headers = data["headers"]
    headers["X-Plugin-Added"] = ["plugin-value"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Check if the plugin-added header is present.
		val := r.Header.Get("X-Plugin-Added")
		w.Header().Set("X-Received-Plugin-Header", val)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Received-Plugin-Header"); got != "plugin-value" {
		t.Errorf("X-Received-Plugin-Header = %q, want %q", got, "plugin-value")
	}
}

func TestPluginHook_OnReceiveFromClient_Drop(t *testing.T) {
	// Plugin drops the request.
	script := writeStarlarkScript(t, "drop.star", `
def on_receive_from_client(data):
    return {"action": "DROP"}
`)

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	// DROP action should return 502 Bad Gateway.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestPluginHook_OnReceiveFromClient_Respond(t *testing.T) {
	// Plugin sends a custom response instead of forwarding.
	script := writeStarlarkScript(t, "respond.star", `
def on_receive_from_client(data):
    return {
        "action": "RESPOND",
        "response": {
            "status_code": 403,
            "headers": {"X-Plugin": ["blocked"]},
            "body": "Access denied by plugin",
        },
    }
`)

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := "GET http://example.com/secret HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Plugin"); got != "blocked" {
		t.Errorf("X-Plugin = %q, want %q", got, "blocked")
	}
	if !strings.Contains(string(body), "Access denied by plugin") {
		t.Errorf("body = %q, want to contain %q", string(body), "Access denied by plugin")
	}
}

func TestPluginHook_OnBeforeSendToServer_ModifyRequest(t *testing.T) {
	// Plugin modifies request headers before sending to server.
	script := writeStarlarkScript(t, "modify_before_send.star", `
def on_before_send_to_server(data):
    headers = data["headers"]
    headers["X-Before-Send"] = ["added-by-plugin"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Before-Send")
		w.Header().Set("X-Received-Before-Send", val)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_before_send_to_server"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Received-Before-Send"); got != "added-by-plugin" {
		t.Errorf("X-Received-Before-Send = %q, want %q", got, "added-by-plugin")
	}
}

func TestPluginHook_OnReceiveFromServer_ModifyResponse(t *testing.T) {
	// Plugin modifies response headers after receiving from server.
	script := writeStarlarkScript(t, "modify_response.star", `
def on_receive_from_server(data):
    headers = data["headers"]
    headers["X-Plugin-Response"] = ["modified"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Original", "yes")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_server"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Plugin-Response"); got != "modified" {
		t.Errorf("X-Plugin-Response = %q, want %q", got, "modified")
	}
}

func TestPluginHook_OnBeforeSendToClient_ModifyResponse(t *testing.T) {
	// Plugin modifies response before sending to client.
	script := writeStarlarkScript(t, "modify_before_client.star", `
def on_before_send_to_client(data):
    headers = data["headers"]
    headers["X-Before-Client"] = ["final-touch"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_before_send_to_client"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Before-Client"); got != "final-touch" {
		t.Errorf("X-Before-Client = %q, want %q", got, "final-touch")
	}
}

func TestPluginHook_FlowRecording_WithPlugin(t *testing.T) {
	// Integration test: plugin adds a header, request flows through, and flow is recorded.
	script := writeStarlarkScript(t, "record_test.star", `
def on_receive_from_client(data):
    headers = data["headers"]
    headers["X-Plugin-Trace"] = ["traced"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "recorded")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     script,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()
	handler.SetPluginEngine(engine)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Wait briefly for recording to complete.
	time.Sleep(100 * time.Millisecond)

	entries := store.Entries()
	if len(entries) == 0 {
		t.Fatal("expected at least 1 flow entry, got 0")
	}

	// Verify the flow was recorded with a send and receive message.
	e := entries[0]
	if e.Send == nil {
		t.Error("expected send message in flow")
	}
	if e.Receive == nil {
		t.Error("expected receive message in flow")
	}
	if e.Session.State != "complete" {
		t.Errorf("flow state = %q, want %q", e.Session.State, "complete")
	}
}

func TestPluginHook_NoEngine_Passthrough(t *testing.T) {
	// Without a plugin engine, requests pass through normally.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "passthrough")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// No SetPluginEngine call.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "passthrough" {
		t.Errorf("body = %q, want %q", string(body), "passthrough")
	}
}

func TestPluginHook_SetPluginEngine_Getter(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	if handler.PluginEngine() != nil {
		t.Error("PluginEngine() should be nil initially")
	}

	engine := plugin.NewEngine(testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	if handler.PluginEngine() != engine {
		t.Error("PluginEngine() should return the set engine")
	}
}
