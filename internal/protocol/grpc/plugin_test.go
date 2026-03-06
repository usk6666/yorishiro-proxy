package grpc

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
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

func TestRecordSession_PluginRequestHook(t *testing.T) {
	// Starlark script that records all hook calls.
	script := `
calls = []

def on_receive_from_client(data):
    calls.append({
        "service": data["service"],
        "method": data["method"],
        "protocol": data["protocol"],
        "url": data["url"],
        "compressed": data["compressed"],
    })
    return {"action": "CONTINUE"}
`
	scriptPath := writeScript(t, "grpc_req.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, []byte{0x0A, 0x05})
	respBody := EncodeFrame(false, []byte{0x0A, 0x07})

	info := &StreamInfo{
		ConnID:     "test-plugin-req",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/com.example.UserService/GetUser",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     50 * time.Millisecond,
		TLSVersion:   "TLS 1.3",
	}

	err = handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Verify flow was still recorded correctly.
	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
	msgs := store.messagesForSession(store.flows[0].ID)
	if len(msgs) != 2 {
		t.Fatalf("messages count = %d, want 2", len(msgs))
	}
}

func TestRecordSession_PluginResponseHook(t *testing.T) {
	script := `
def on_receive_from_server(data):
    # Verify response-specific fields are present.
    assert data["protocol"] == "grpc"
    assert data["status_code"] == 200
    assert "grpc_status" in data
    return {"action": "CONTINUE"}
`
	scriptPath := writeScript(t, "grpc_resp.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc",
			Hooks:    []string{"on_receive_from_server"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	reqBody := EncodeFrame(false, []byte{0x01})
	respBody := EncodeFrame(false, []byte{0x02})

	info := &StreamInfo{
		ConnID:     "test-plugin-resp",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     30 * time.Millisecond,
	}

	err = handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestRecordSession_PluginStreamingHooks(t *testing.T) {
	// Count how many times each hook fires for streaming.
	script := `
req_count = 0
resp_count = 0

def on_receive_from_client(data):
    global req_count
    req_count += 1
    return None

def on_receive_from_server(data):
    global resp_count
    resp_count += 1
    return None
`
	scriptPath := writeScript(t, "grpc_stream.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc",
			Hooks:    []string{"on_receive_from_client", "on_receive_from_server"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	// 2 request frames, 3 response frames => server streaming.
	var reqBody []byte
	reqBody = append(reqBody, EncodeFrame(false, []byte{0x01})...)
	reqBody = append(reqBody, EncodeFrame(false, []byte{0x02})...)

	var respBody []byte
	respBody = append(respBody, EncodeFrame(false, []byte{0x11})...)
	respBody = append(respBody, EncodeFrame(false, []byte{0x12})...)
	respBody = append(respBody, EncodeFrame(false, []byte{0x13})...)

	info := &StreamInfo{
		ConnID:     "test-plugin-stream",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Stream",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  reqBody,
		ResponseBody: respBody,
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     100 * time.Millisecond,
	}

	err = handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Verify flow was recorded.
	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
	fl := store.flows[0]
	if fl.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "bidirectional")
	}

	// 2 send + 3 receive = 5 messages.
	msgs := store.messagesForSession(fl.ID)
	if len(msgs) != 5 {
		t.Fatalf("messages count = %d, want 5", len(msgs))
	}
}

func TestRecordSession_PluginNilEngine(t *testing.T) {
	// Verify that a handler without plugin engine works fine.
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No SetPluginEngine call.

	info := &StreamInfo{
		ConnID:     "test-no-plugin",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  EncodeFrame(false, []byte{0x01}),
		ResponseBody: EncodeFrame(false, []byte{0x02}),
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     5 * time.Millisecond,
	}

	err := handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestRecordSession_PluginHookError(t *testing.T) {
	// Plugin that always errors — should be skipped (default on_error=skip).
	script := `
def on_receive_from_client(data):
    fail("intentional error")
`
	scriptPath := writeScript(t, "grpc_err.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	info := &StreamInfo{
		ConnID:     "test-plugin-err",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  EncodeFrame(false, []byte{0x01}),
		ResponseBody: EncodeFrame(false, []byte{0x02}),
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     5 * time.Millisecond,
	}

	// Should not fail — error is logged and skipped.
	err = handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	// Flow should still be recorded.
	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestRecordSession_PluginConnInfo(t *testing.T) {
	// Plugin that verifies conn_info fields.
	script := `
def on_receive_from_client(data):
    ci = data["conn_info"]
    assert ci["client_addr"] == "127.0.0.1:12345", "bad client_addr: " + ci["client_addr"]
    assert ci["server_addr"] == "10.0.0.1:50051", "bad server_addr: " + ci["server_addr"]
    assert ci["tls_version"] == "TLS 1.3", "bad tls_version: " + ci["tls_version"]
    assert ci["tls_alpn"] == "h2", "bad tls_alpn: " + ci["tls_alpn"]
    return None
`
	scriptPath := writeScript(t, "grpc_conninfo.star", script)

	engine := plugin.NewEngine(testutil.DiscardLogger())
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}
	defer engine.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetPluginEngine(engine)

	info := &StreamInfo{
		ConnID:     "test-plugin-conninfo",
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "10.0.0.1:50051",
		Method:     "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ResponseHeaders: map[string][]string{},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		RequestBody:  EncodeFrame(false, []byte{0x01}),
		ResponseBody: EncodeFrame(false, []byte{0x02}),
		StatusCode:   200,
		Start:        time.Now(),
		Duration:     5 * time.Millisecond,
		TLSVersion:   "TLS 1.3",
		TLSCipher:    "TLS_AES_128_GCM_SHA256",
		TLSALPN:      "h2",
	}

	err = handler.RecordSession(context.Background(), info)
	if err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	if len(store.flows) != 1 {
		t.Fatalf("flows count = %d, want 1", len(store.flows))
	}
}

func TestBuildConnInfo(t *testing.T) {
	info := &StreamInfo{
		ClientAddr:           "1.2.3.4:1234",
		ServerAddr:           "5.6.7.8:5678",
		TLSVersion:           "TLS 1.3",
		TLSCipher:            "AES256",
		TLSALPN:              "h2",
		TLSServerCertSubject: "CN=example.com",
	}

	ci := buildConnInfo(info)

	if ci["client_addr"] != "1.2.3.4:1234" {
		t.Errorf("client_addr = %v", ci["client_addr"])
	}
	if ci["server_addr"] != "5.6.7.8:5678" {
		t.Errorf("server_addr = %v", ci["server_addr"])
	}
	if ci["tls_version"] != "TLS 1.3" {
		t.Errorf("tls_version = %v", ci["tls_version"])
	}
	if ci["tls_cipher"] != "AES256" {
		t.Errorf("tls_cipher = %v", ci["tls_cipher"])
	}
	if ci["tls_alpn"] != "h2" {
		t.Errorf("tls_alpn = %v", ci["tls_alpn"])
	}
	if ci["tls_server_cert_subject"] != "CN=example.com" {
		t.Errorf("tls_server_cert_subject = %v", ci["tls_server_cert_subject"])
	}
}

func TestBuildConnInfo_NoTLS(t *testing.T) {
	info := &StreamInfo{
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:5678",
	}

	ci := buildConnInfo(info)

	if ci["client_addr"] != "1.2.3.4:1234" {
		t.Errorf("client_addr = %v", ci["client_addr"])
	}
	if _, ok := ci["tls_version"]; ok {
		t.Error("tls_version should not be present")
	}
}

func TestFlattenHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    map[string]any
	}{
		{
			name:    "nil headers",
			headers: nil,
			want:    map[string]any{},
		},
		{
			name:    "single values",
			headers: map[string][]string{"Content-Type": {"application/grpc"}},
			want:    map[string]any{"Content-Type": "application/grpc"},
		},
		{
			name:    "multiple values joined",
			headers: map[string][]string{"Accept": {"a", "b"}},
			want:    map[string]any{"Accept": "a, b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flattenHeaders(tt.headers)
			for k, wantV := range tt.want {
				if got[k] != wantV {
					t.Errorf("key %q = %v, want %v", k, got[k], wantV)
				}
			}
			if len(got) != len(tt.want) {
				t.Errorf("len = %d, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestBuildGRPCRequestData(t *testing.T) {
	info := &StreamInfo{
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:5678",
	}

	body := []byte{0x01, 0x02}
	connInfo := buildConnInfo(info)
	data := buildGRPCRequestData(info, "pkg.Svc", "Do", "gzip", body, true, connInfo)

	if data["protocol"] != "grpc" {
		t.Errorf("protocol = %v", data["protocol"])
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

func TestBuildGRPCResponseData(t *testing.T) {
	info := &StreamInfo{
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/pkg.Svc/Do",
		},
		ResponseHeaders: map[string][]string{
			"Content-Type": {"application/grpc"},
		},
		Trailers: map[string][]string{
			"grpc-status": {"0"},
		},
		StatusCode: 200,
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:5678",
	}

	body := []byte{0x01}
	connInfo := buildConnInfo(info)
	data := buildGRPCResponseData(info, "pkg.Svc", "Do", "0", "", "gzip", body, false, connInfo)

	if data["protocol"] != "grpc" {
		t.Errorf("protocol = %v", data["protocol"])
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
