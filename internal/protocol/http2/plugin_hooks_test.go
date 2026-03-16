package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

// setupPluginEngine creates a plugin.Engine with the given script and hooks.
func setupPluginEngine(t *testing.T, scriptPath, protocol string, hooks []string) *plugin.Engine {
	t.Helper()
	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: protocol,
			Hooks:    hooks,
		},
	})
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	return engine
}

func TestPluginHook_H2_OnReceiveFromClient_Continue(t *testing.T) {
	// Plugin adds X-Plugin-H2 header and continues.
	script := writeStarlarkScript(t, "add_header.star", `
def on_receive_from_client(data):
    if data["protocol"] != "h2":
        return {"action": "CONTINUE", "data": data}
    headers = data["headers"]
    headers["X-Plugin-H2"] = ["h2-value"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Plugin-H2")
		w.Header().Set("X-Received-Plugin-Header", val)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-continue", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Received-Plugin-Header"); got != "h2-value" {
		t.Errorf("X-Received-Plugin-Header = %q, want %q", got, "h2-value")
	}
}

func TestPluginHook_H2_OnReceiveFromClient_Drop(t *testing.T) {
	script := writeStarlarkScript(t, "drop.star", `
def on_receive_from_client(data):
    return {"action": "DROP"}
`)

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-drop", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://example.com/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// DROP action should return 502 Bad Gateway.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestPluginHook_H2_OnReceiveFromClient_Respond(t *testing.T) {
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
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-respond", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://example.com/secret", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
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

func TestPluginHook_H2_OnBeforeSendToServer_ModifyRequest(t *testing.T) {
	script := writeStarlarkScript(t, "modify_before_send.star", `
def on_before_send_to_server(data):
    headers = data["headers"]
    headers["X-Before-Send-H2"] = ["added-by-plugin"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Before-Send-H2")
		w.Header().Set("X-Received-Before-Send", val)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_before_send_to_server"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-before-send", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Received-Before-Send"); got != "added-by-plugin" {
		t.Errorf("X-Received-Before-Send = %q, want %q", got, "added-by-plugin")
	}
}

func TestPluginHook_H2_OnReceiveFromServer_ModifyResponse(t *testing.T) {
	script := writeStarlarkScript(t, "modify_response.star", `
def on_receive_from_server(data):
    headers = data["headers"]
    headers["X-Plugin-Response-H2"] = ["modified"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Original", "yes")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_server"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-recv-server", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Plugin-Response-H2"); got != "modified" {
		t.Errorf("X-Plugin-Response-H2 = %q, want %q", got, "modified")
	}
}

func TestPluginHook_H2_OnBeforeSendToClient_ModifyResponse(t *testing.T) {
	script := writeStarlarkScript(t, "modify_before_client.star", `
def on_before_send_to_client(data):
    headers = data["headers"]
    headers["X-Before-Client-H2"] = ["final-touch"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_before_send_to_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-plugin-before-client", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Before-Client-H2"); got != "final-touch" {
		t.Errorf("X-Before-Client-H2 = %q, want %q", got, "final-touch")
	}
}

func TestPluginHook_H2_NilEngine_Passthrough(t *testing.T) {
	// Without a plugin engine, requests pass through normally.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "passthrough")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No SetPluginEngine call.

	addr, cancel := startH2CProxyListener(t, handler, "test-no-plugin", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
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

func TestPluginHook_H2_SetPluginEngine_Getter(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	if handler.PluginEngine() != nil {
		t.Error("PluginEngine() should be nil initially")
	}

	engine := plugin.NewEngine(testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	if handler.PluginEngine() != engine {
		t.Error("PluginEngine() should return the set engine")
	}
}

func TestPluginHook_H2_ProtocolField(t *testing.T) {
	// Verify the protocol field is set to "h2" in the hook data.
	script := writeStarlarkScript(t, "check_protocol.star", `
def on_receive_from_client(data):
    proto = data["protocol"]
    headers = data["headers"]
    headers["X-Protocol"] = [proto]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Protocol")
		w.Header().Set("X-Received-Protocol", val)
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-protocol-field", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if got := resp.Header.Get("X-Received-Protocol"); got != "h2" {
		t.Errorf("protocol = %q, want %q", got, "h2")
	}
}

func TestPluginHook_H2_BodyModification(t *testing.T) {
	// Plugin modifies the request body.
	script := writeStarlarkScript(t, "modify_body.star", `
def on_receive_from_client(data):
    data["body"] = "modified-body"
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-body-mod", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte("original-body")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "modified-body" {
		t.Errorf("body = %q, want %q", string(body), "modified-body")
	}
}

func TestPluginHook_H2_RawFramesAbsentViaH2CHelper(t *testing.T) {
	// This test uses Go's h2c handler via startH2CProxyListener, which does
	// not inject raw frames into the context (only clientConn does).
	// Verify the plugin handles absent raw_frames gracefully.
	script := writeStarlarkScript(t, "check_raw_frames.star", `
def on_receive_from_client(data):
    raw = data.get("raw_frames", None)
    if raw != None:
        headers = data["headers"]
        headers["X-Frame-Count"] = [str(len(raw))]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Frame-Count")
		w.Header().Set("X-Received-Frame-Count", val)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-raw-frames", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// h2c helper does not inject raw frames, so X-Received-Frame-Count
	// should be empty (plugin's raw_frames branch was not taken).
	if got := resp.Header.Get("X-Received-Frame-Count"); got != "" {
		t.Errorf("X-Received-Frame-Count = %q, want empty (h2c helper does not provide raw frames)", got)
	}
}

func TestPluginHook_H2_NoRawFramesBackwardCompat(t *testing.T) {
	// Plugins that don't use raw_frames should work fine.
	script := writeStarlarkScript(t, "no_raw_frames.star", `
def on_receive_from_client(data):
    # Plugin ignores raw_frames entirely — backward compatible.
    headers = data["headers"]
    headers["X-Compat"] = ["ok"]
    return {"action": "CONTINUE", "data": data}
`)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		val := r.Header.Get("X-Compat")
		w.Header().Set("X-Received-Compat", val)
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-compat", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("X-Received-Compat"); got != "ok" {
		t.Errorf("X-Received-Compat = %q, want %q", got, "ok")
	}
}

func TestPluginHook_H2_FlowRecording_WithPlugin(t *testing.T) {
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
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := setupPluginEngine(t, script, "h2", []string{"on_receive_from_client"})
	defer engine.Close()
	handler.SetPluginEngine(engine)

	addr, cancel := startH2CProxyListener(t, handler, "test-flow-record", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) == 0 {
		t.Fatal("expected at least 1 flow entry, got 0")
	}

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
