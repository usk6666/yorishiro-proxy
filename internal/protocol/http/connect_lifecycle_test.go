package http

import (
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestDispatchOnTLSHandshake_NilEngine(t *testing.T) {
	// Verify no panic when pluginEngine is nil.
	handler := &Handler{HandlerBase: proxy.HandlerBase{Logger: testutil.DiscardLogger()}}
	handler.dispatchOnTLSHandshake(context.Background(), "example.com", tlsMetadata{
		Version:     "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ALPN:        "h2",
	})
}

func TestDispatchOnTLSHandshake_Dispatched(t *testing.T) {
	var mu sync.Mutex
	var capturedData map[string]any

	engine := plugin.NewEngine(nil)
	engine.Registry().Register("test-plugin", plugin.HookOnTLSHandshake,
		func(_ context.Context, data map[string]any) (*plugin.HookResult, error) {
			mu.Lock()
			defer mu.Unlock()
			capturedData = make(map[string]any, len(data))
			for k, v := range data {
				capturedData[k] = v
			}
			return &plugin.HookResult{Action: plugin.ActionContinue}, nil
		}, plugin.OnErrorSkip)

	handler := &Handler{
		HandlerBase:  proxy.HandlerBase{Logger: testutil.DiscardLogger()},
		pluginEngine: engine,
	}

	handler.dispatchOnTLSHandshake(context.Background(), "example.com", tlsMetadata{
		Version:     "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ALPN:        "h2",
	})

	mu.Lock()
	defer mu.Unlock()

	if capturedData == nil {
		t.Fatal("on_tls_handshake hook was not dispatched")
	}

	if capturedData["event"] != "tls_handshake" {
		t.Errorf("event = %v, want tls_handshake", capturedData["event"])
	}

	if capturedData["server_name"] != "example.com" {
		t.Errorf("server_name = %v, want example.com", capturedData["server_name"])
	}

	connInfo, ok := capturedData["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info is not a map")
	}

	if connInfo["tls_version"] != "TLS 1.3" {
		t.Errorf("tls_version = %v, want TLS 1.3", connInfo["tls_version"])
	}
	if connInfo["tls_cipher"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("tls_cipher = %v, want TLS_AES_128_GCM_SHA256", connInfo["tls_cipher"])
	}
	if connInfo["tls_alpn"] != "h2" {
		t.Errorf("tls_alpn = %v, want h2", connInfo["tls_alpn"])
	}
}

func TestDispatchOnTLSHandshake_ErrorFailOpen(t *testing.T) {
	// Register a hook that returns an error via OnErrorAbort.
	// The method should log the error but not panic.
	engine := plugin.NewEngine(nil)
	engine.Registry().Register("error-plugin", plugin.HookOnTLSHandshake,
		func(_ context.Context, _ map[string]any) (*plugin.HookResult, error) {
			return nil, &plugin.DispatchError{
				PluginName: "error-plugin",
				Hook:       plugin.HookOnTLSHandshake,
				Err:        context.DeadlineExceeded,
			}
		}, plugin.OnErrorAbort)

	handler := &Handler{
		HandlerBase:  proxy.HandlerBase{Logger: testutil.DiscardLogger()},
		pluginEngine: engine,
	}

	// Should not panic.
	handler.dispatchOnTLSHandshake(context.Background(), "example.com", tlsMetadata{
		Version:     "TLS 1.2",
		CipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA",
	})
}
