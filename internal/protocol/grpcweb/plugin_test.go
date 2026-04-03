package grpcweb

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// writeScript writes a Starlark script to a temporary file and returns its path.
func writeScript(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testStreamInfo(t *testing.T, reqBody, respBody []byte) *StreamInfo {
	t.Helper()
	u, err := url.Parse("https://example.com/test.Service/GetItem")
	if err != nil {
		t.Fatalf("invalid test URL: %v", err)
	}
	return &StreamInfo{
		ConnID:     "conn-plugin-test",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:8080",
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web+proto"},
			{Name: "grpc-encoding", Value: "identity"},
		},
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web+proto"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Method:       "POST",
		URL:          u,
		Scheme:       "https",
		Start:        time.Now(),
		Duration:     50 * time.Millisecond,
	}
}

func TestPluginRequestHook_ProtocolIsGRPCWeb(t *testing.T) {
	// Starlark script that asserts protocol == "grpc-web".
	script := `
def on_receive_from_client(data):
    assert data["protocol"] == "grpc-web", "expected grpc-web, got " + data["protocol"]
    assert data["service"] == "test.Service", "bad service: " + data["service"]
    assert data["method"] == "GetItem", "bad method: " + data["method"]
    assert "url" in data
    assert "headers" in data
    assert "conn_info" in data
    return {"action": "CONTINUE"}
`
	scriptPath := writeScript(t, "grpcweb_req.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, false, []byte("request-data"))
	trailerData := []byte("grpc-status: 0\r\n")
	respBody := append(EncodeFrame(false, false, []byte("response-data")), EncodeFrame(true, false, trailerData)...)

	info := testStreamInfo(t, reqBody, respBody)

	err = h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Verify flow was still recorded correctly.
	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
	if len(store.messages) != 2 {
		t.Fatalf("messages count = %d, want 2", len(store.messages))
	}
}

func TestPluginResponseHook_ProtocolIsGRPCWeb(t *testing.T) {
	script := `
def on_receive_from_server(data):
    assert data["protocol"] == "grpc-web", "expected grpc-web, got " + data["protocol"]
    assert data["status_code"] == 200
    assert "grpc_status" in data
    return {"action": "CONTINUE"}
`
	scriptPath := writeScript(t, "grpcweb_resp.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_server"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, false, []byte("req"))
	trailerData := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")
	respBody := append(EncodeFrame(false, false, []byte("resp")), EncodeFrame(true, false, trailerData)...)

	info := testStreamInfo(t, reqBody, respBody)

	err = h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestPluginStreamingHooks_MultipleFrames(t *testing.T) {
	// Script that counts hook invocations via global state.
	script := `
req_count = 0
resp_count = 0

def on_receive_from_client(data):
    global req_count
    req_count += 1
    assert data["protocol"] == "grpc-web"
    return None

def on_receive_from_server(data):
    global resp_count
    resp_count += 1
    assert data["protocol"] == "grpc-web"
    return None
`
	scriptPath := writeScript(t, "grpcweb_stream.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_client", "on_receive_from_server"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	// 2 request frames, 3 response frames.
	var reqBody []byte
	reqBody = append(reqBody, EncodeFrame(false, false, []byte("r1"))...)
	reqBody = append(reqBody, EncodeFrame(false, false, []byte("r2"))...)

	var respBody []byte
	respBody = append(respBody, EncodeFrame(false, false, []byte("s1"))...)
	respBody = append(respBody, EncodeFrame(false, false, []byte("s2"))...)
	respBody = append(respBody, EncodeFrame(false, false, []byte("s3"))...)
	respBody = append(respBody, EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))...)

	info := testStreamInfo(t, reqBody, respBody)

	err = h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
	fl := store.flows[0]
	if fl.FlowType != "bidirectional" {
		t.Errorf("FlowType = %q, want %q", fl.FlowType, "bidirectional")
	}

	// 2 send + 3 receive = 5 messages.
	if len(store.messages) != 5 {
		t.Fatalf("messages count = %d, want 5", len(store.messages))
	}
}

func TestPluginNilEngine_NoError(t *testing.T) {
	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	// No SetPluginEngine call.

	reqBody := EncodeFrame(false, false, []byte("data"))
	trailerData := []byte("grpc-status: 0\r\n")
	respBody := append(EncodeFrame(false, false, []byte("resp")), EncodeFrame(true, false, trailerData)...)

	info := testStreamInfo(t, reqBody, respBody)

	err := h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestPluginHookError_FlowStillRecorded(t *testing.T) {
	// Plugin that always errors — should be skipped.
	script := `
def on_receive_from_client(data):
    fail("intentional error")
`
	scriptPath := writeScript(t, "grpcweb_err.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, false, []byte("data"))
	trailerData := []byte("grpc-status: 0\r\n")
	respBody := append(EncodeFrame(false, false, []byte("resp")), EncodeFrame(true, false, trailerData)...)

	info := testStreamInfo(t, reqBody, respBody)

	// Should not fail — error is logged and skipped.
	err = h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestPluginConnInfo(t *testing.T) {
	// Plugin that verifies conn_info fields.
	script := `
def on_receive_from_client(data):
    ci = data["conn_info"]
    assert ci["client_addr"] == "127.0.0.1:12345", "bad client_addr: " + ci["client_addr"]
    assert ci["server_addr"] == "10.0.0.1:8080", "bad server_addr: " + ci["server_addr"]
    return None
`
	scriptPath := writeScript(t, "grpcweb_conninfo.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockFlowWriter{}
	h := NewHandler(store, testutil.DiscardLogger())
	h.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, false, []byte("data"))
	trailerData := []byte("grpc-status: 0\r\n")
	respBody := append(EncodeFrame(false, false, []byte("resp")), EncodeFrame(true, false, trailerData)...)

	info := testStreamInfo(t, reqBody, respBody)

	err = h.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestBuildPluginRequestData_Fields(t *testing.T) {
	u, _ := url.Parse("https://example.com/pkg.Svc/Do")
	info := &StreamInfo{
		URL: u,
		RequestHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:5678",
	}

	body := []byte{0x01, 0x02}
	connInfo := buildConnInfo(info)
	data := buildPluginRequestData(info, "pkg.Svc", "Do", "gzip", body, true, connInfo)

	if data["protocol"] != "grpc-web" {
		t.Errorf("protocol = %v, want grpc-web", data["protocol"])
	}
	if data["service"] != "pkg.Svc" {
		t.Errorf("service = %v", data["service"])
	}
	if data["method"] != "Do" {
		t.Errorf("method = %v", data["method"])
	}
	if data["url"] != "https://example.com/pkg.Svc/Do" {
		t.Errorf("url = %v", data["url"])
	}
	if data["compressed"] != true {
		t.Errorf("compressed = %v", data["compressed"])
	}
	if data["encoding"] != "gzip" {
		t.Errorf("encoding = %v", data["encoding"])
	}
	if data["body"] == nil {
		t.Error("body should not be nil")
	}
}

func TestBuildPluginResponseData_Fields(t *testing.T) {
	u, _ := url.Parse("https://example.com/pkg.Svc/Do")
	info := &StreamInfo{
		URL: u,
		ResponseHeaders: parser.RawHeaders{
			{Name: "content-type", Value: "application/grpc-web"},
		},
		StatusCode: 200,
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:5678",
	}

	body := []byte{0x01}
	connInfo := buildConnInfo(info)
	data := buildPluginResponseData(info, "pkg.Svc", "Do", "0", "", "gzip", body, false, connInfo)

	if data["protocol"] != "grpc-web" {
		t.Errorf("protocol = %v, want grpc-web", data["protocol"])
	}
	if data["status_code"] != 200 {
		t.Errorf("status_code = %v", data["status_code"])
	}
	if data["grpc_status"] != "0" {
		t.Errorf("grpc_status = %v", data["grpc_status"])
	}
	if data["compressed"] != false {
		t.Errorf("compressed = %v", data["compressed"])
	}
	if _, ok := data["grpc_message"]; ok {
		t.Error("grpc_message should not be present when empty")
	}
}

func TestBuildPluginRequestData_NoEncoding(t *testing.T) {
	u, _ := url.Parse("https://example.com/pkg.Svc/Do")
	info := &StreamInfo{
		URL:            u,
		RequestHeaders: parser.RawHeaders{},
		ClientAddr:     "1.2.3.4:1234",
		ServerAddr:     "5.6.7.8:5678",
	}

	connInfo := buildConnInfo(info)
	data := buildPluginRequestData(info, "pkg.Svc", "Do", "", nil, false, connInfo)

	if _, ok := data["encoding"]; ok {
		t.Error("encoding should not be present when empty")
	}
	if _, ok := data["body"]; ok {
		t.Error("body should not be present when nil")
	}
}
