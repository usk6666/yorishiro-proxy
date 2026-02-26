package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	interceptPkg "github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
)

func TestSetInsecureSkipVerify_EnablesSkipVerify(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	handler.SetInsecureSkipVerify(true)

	if handler.transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil after SetInsecureSkipVerify(true)")
	}
	if !handler.transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestSetInsecureSkipVerify_FalseDoesNotModifyTransport(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	handler.SetInsecureSkipVerify(false)

	// When skip is false, TLSClientConfig should remain nil (not modified).
	if handler.transport.TLSClientConfig != nil {
		t.Errorf("TLSClientConfig = %v, want nil when skip is false", handler.transport.TLSClientConfig)
	}
}

func TestSetInsecureSkipVerify_PreservesExistingTLSConfig(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Pre-set a TLSClientConfig with a custom field.
	handler.transport.TLSClientConfig = &tls.Config{
		ServerName: "custom-server",
	}

	handler.SetInsecureSkipVerify(true)

	if handler.transport.TLSClientConfig.ServerName != "custom-server" {
		t.Errorf("ServerName = %q, want %q", handler.transport.TLSClientConfig.ServerName, "custom-server")
	}
	if !handler.transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestNewHandler_DefaultTransportHasNoInsecureSkipVerify(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Default transport should not have TLSClientConfig set.
	if handler.transport.TLSClientConfig != nil {
		t.Errorf("default transport TLSClientConfig = %v, want nil", handler.transport.TLSClientConfig)
	}
}

func TestInsecureSkipVerify_HTTPForwardToSelfSignedServer(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate (httptest.NewTLSServer).
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Insecure-Test", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "self-signed-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Enable InsecureSkipVerify so the handler can connect to the self-signed upstream.
	handler.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to the proxy and send a request targeting the self-signed HTTPS upstream.
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
	if string(body) != "self-signed-ok" {
		t.Errorf("body = %q, want %q", body, "self-signed-ok")
	}
	if resp.Header.Get("X-Insecure-Test") != "passed" {
		t.Errorf("X-Insecure-Test = %q, want %q", resp.Header.Get("X-Insecure-Test"), "passed")
	}
}

func TestInsecureSkipVerify_HTTPSConnectToSelfSignedServer(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Insecure-HTTPS", "ok")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "https-self-signed-ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())

	// Use SetInsecureSkipVerify instead of manually setting transport.
	handler.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /test-insecure HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusOK {
		t.Errorf("HTTPS status = %d, want %d", httpsResp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "https-self-signed-ok" {
		t.Errorf("body = %q, want %q", body, "https-self-signed-ok")
	}

	// Verify session was recorded.
	time.Sleep(100 * time.Millisecond)
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}
	if entries[0].Session.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTPS")
	}
}

func TestWithoutInsecureSkipVerify_SelfSignedServerFails(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "should-not-reach")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())
	// Do NOT set InsecureSkipVerify — default transport should reject self-signed cert.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send a request to the self-signed HTTPS upstream.
	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	// Without InsecureSkipVerify, the proxy should return 502 Bad Gateway
	// because it cannot verify the self-signed certificate.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d (502 Bad Gateway for self-signed cert)", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestApplyInterceptModifications_URLSchemeValidation(t *testing.T) {
	tests := []struct {
		name        string
		overrideURL string
		wantErr     bool
		errContains string
	}{
		{
			name:        "http scheme allowed",
			overrideURL: "http://example.com/path",
			wantErr:     false,
		},
		{
			name:        "https scheme allowed",
			overrideURL: "https://example.com/path",
			wantErr:     false,
		},
		{
			name:        "file scheme rejected",
			overrideURL: "file:///etc/passwd",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "ftp scheme rejected",
			overrideURL: "ftp://example.com/file",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "gopher scheme rejected",
			overrideURL: "gopher://example.com",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "javascript scheme rejected",
			overrideURL: "javascript:alert(1)",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "empty override URL is no-op",
			overrideURL: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := gohttp.NewRequest("GET", "http://original.com/path", nil)
			action := interceptPkg.InterceptAction{
				Type:        interceptPkg.ActionModifyAndForward,
				OverrideURL: tt.overrideURL,
			}

			result, err := applyInterceptModifications(req, action, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for URL %q, got nil", tt.overrideURL)
				}
				if tt.errContains != "" {
					errStr := err.Error()
					if !containsStr(errStr, tt.errContains) {
						t.Errorf("error %q should contain %q", errStr, tt.errContains)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
			}
		})
	}
}

// containsStr checks if s contains substr (simple helper to avoid importing strings).
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && searchStr(s, substr))
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
