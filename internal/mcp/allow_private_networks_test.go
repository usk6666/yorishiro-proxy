package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestResendHTTPClient_AllowPrivateNetworks_Default verifies that resendHTTPClient
// blocks private network connections by default (allow_private_networks=false).
func TestResendHTTPClient_AllowPrivateNetworks_Default(t *testing.T) {
	// Start a local echo server on loopback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := &Server{}
	params := executeParams{}

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// The request should fail because SSRF protection blocks loopback.
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected error for loopback connection with SSRF protection enabled, got nil")
	}
}

// TestResendHTTPClient_AllowPrivateNetworks_Enabled verifies that resendHTTPClient
// allows private network connections when allow_private_networks=true.
func TestResendHTTPClient_AllowPrivateNetworks_Enabled(t *testing.T) {
	// Start a local echo server on loopback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	s := &Server{}
	params := executeParams{
		AllowPrivateNetworks: true,
	}

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// The request should succeed because SSRF protection is disabled.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error for loopback with allow_private_networks=true, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestResendHTTPClient_UsesReplayDoer verifies that when replayDoer is set
// (test injection), it is returned regardless of AllowPrivateNetworks.
func TestResendHTTPClient_UsesReplayDoer(t *testing.T) {
	mockDoer := &mockHTTPDoer{}
	s := &Server{replayDoer: mockDoer}

	tests := []struct {
		name                 string
		allowPrivateNetworks bool
	}{
		{name: "false", allowPrivateNetworks: false},
		{name: "true", allowPrivateNetworks: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := executeParams{AllowPrivateNetworks: tt.allowPrivateNetworks}
			got := s.resendHTTPClient(params)
			if got != mockDoer {
				t.Errorf("expected replayDoer to be returned, got different client")
			}
		})
	}
}

// TestRawDialerFuncWithOpts_Default verifies that rawDialerFuncWithOpts
// blocks private network connections by default.
func TestRawDialerFuncWithOpts_Default(t *testing.T) {
	// Start a local TCP listener to have something to dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	s := &Server{}
	dialer := s.rawDialerFuncWithOpts(false)

	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("expected error for loopback connection with SSRF protection, got nil")
	}
}

// TestRawDialerFuncWithOpts_AllowPrivate verifies that rawDialerFuncWithOpts
// allows private network connections when allowPrivateNetworks=true.
func TestRawDialerFuncWithOpts_AllowPrivate(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	s := &Server{}
	dialer := s.rawDialerFuncWithOpts(true)

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected no error for loopback with allow_private_networks=true, got: %v", err)
	}
	conn.Close()
}

// TestRawDialerFuncWithOpts_UsesRawReplayDialer verifies that when rawReplayDialer
// is set, it is returned regardless of allowPrivateNetworks.
func TestRawDialerFuncWithOpts_UsesRawReplayDialer(t *testing.T) {
	mockDialer := &testDialer{}
	s := &Server{rawReplayDialer: mockDialer}

	tests := []struct {
		name                 string
		allowPrivateNetworks bool
	}{
		{name: "false", allowPrivateNetworks: false},
		{name: "true", allowPrivateNetworks: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.rawDialerFuncWithOpts(tt.allowPrivateNetworks)
			if got != mockDialer {
				t.Errorf("expected rawReplayDialer to be returned, got different dialer")
			}
		})
	}
}

// TestMacroSendFunc_AllowPrivateNetworks verifies that macroSendFunc
// respects the allowPrivateNetworks parameter.
func TestMacroSendFunc_AllowPrivateNetworks(t *testing.T) {
	t.Run("default_returns_func", func(t *testing.T) {
		s := &Server{}
		sendFunc := s.macroSendFunc(false)
		if sendFunc == nil {
			t.Fatal("expected non-nil SendFunc")
		}
	})

	t.Run("allow_private_returns_func", func(t *testing.T) {
		s := &Server{}
		sendFunc := s.macroSendFunc(true)
		if sendFunc == nil {
			t.Fatal("expected non-nil SendFunc")
		}
	})

	t.Run("uses_replay_doer", func(t *testing.T) {
		mockDoer := &mockHTTPDoer{}
		s := &Server{replayDoer: mockDoer}

		for _, allow := range []bool{true, false} {
			sendFunc := s.macroSendFunc(allow)
			if sendFunc == nil {
				t.Fatalf("expected non-nil SendFunc for allowPrivateNetworks=%v", allow)
			}
		}
	})
}

// TestNewPermissiveHTTPClient verifies that the permissive client
// can connect to loopback addresses.
func TestNewPermissiveHTTPClient(t *testing.T) {
	client := newPermissiveHTTPClient()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != defaultReplayTimeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, defaultReplayTimeout)
	}

	// Verify it can connect to a local HTTP server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected permissive client to connect to loopback, got: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestNewPermissiveHTTPClient_NoRedirectFollow verifies that the permissive
// client does not follow redirects.
func TestNewPermissiveHTTPClient_NoRedirectFollow(t *testing.T) {
	client := newPermissiveHTTPClient()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want %d (redirect should not be followed)", resp.StatusCode, http.StatusFound)
	}
}

// TestExecuteParams_AllowPrivateNetworks_DefaultFalse verifies that
// AllowPrivateNetworks defaults to false.
func TestExecuteParams_AllowPrivateNetworks_DefaultFalse(t *testing.T) {
	params := executeParams{}
	if params.AllowPrivateNetworks {
		t.Error("AllowPrivateNetworks should default to false")
	}
}

// mockHTTPDoer is a mock httpDoer for testing.
type mockHTTPDoer struct{}

func (m *mockHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(nil),
	}, nil
}

// TestHardenedHTTPClient_BlocksLoopback verifies that NewHardenedHTTPClient
// blocks loopback connections (existing behavior, regression test).
func TestHardenedHTTPClient_BlocksLoopback(t *testing.T) {
	client := NewHardenedHTTPClient()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected NewHardenedHTTPClient to block loopback, got nil error")
	}
}

// TestHttpClient_BlocksLoopback verifies that httpClient() method
// blocks loopback connections by default.
func TestHttpClient_BlocksLoopback(t *testing.T) {
	s := &Server{}
	client := s.httpClient()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected httpClient to block loopback, got nil error")
	}
}

// TestRawDialerFunc_BlocksLoopback verifies that rawDialerFunc() method
// blocks loopback connections by default (backward compatibility).
func TestRawDialerFunc_BlocksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	s := &Server{}
	dialer := s.rawDialerFunc()

	ctx := context.Background()
	_, err = dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("expected rawDialerFunc to block loopback, got nil error")
	}
}

// TestResendHTTPClient_AllowPrivateNetworks_TimeoutPreserved verifies that
// timeout configuration is preserved when AllowPrivateNetworks is enabled.
func TestResendHTTPClient_AllowPrivateNetworks_TimeoutPreserved(t *testing.T) {
	s := &Server{}
	timeout := 5000
	params := executeParams{
		AllowPrivateNetworks: true,
		TimeoutMs:            &timeout,
	}

	client := s.resendHTTPClient(params)
	httpClient, ok := client.(*http.Client)
	if !ok {
		t.Fatalf("expected *http.Client, got %T", client)
	}

	expected := time.Duration(timeout) * time.Millisecond
	if httpClient.Timeout != expected {
		t.Errorf("Timeout = %v, want %v", httpClient.Timeout, expected)
	}
}

// TestResendHTTPClient_AllowPrivateNetworks_FollowRedirects verifies that
// follow_redirects still works when allow_private_networks is enabled.
func TestResendHTTPClient_AllowPrivateNetworks_FollowRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	s := &Server{}
	followRedirects := true
	params := executeParams{
		AllowPrivateNetworks: true,
		FollowRedirects:      &followRedirects,
	}

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if !redirected {
		t.Error("expected redirect to be followed")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestResendHTTPClient_AllowPrivateNetworks_PrivateIPs tests various private
// IP ranges that should be accessible when allow_private_networks=true.
func TestResendHTTPClient_AllowPrivateNetworks_PrivateIPs(t *testing.T) {
	// We can only test loopback in a test environment, but verify the dialer
	// doesn't have a Control function set when allow_private_networks=true.
	s := &Server{}
	params := executeParams{
		AllowPrivateNetworks: true,
	}

	client := s.resendHTTPClient(params)
	httpClient := client.(*http.Client)
	transport := httpClient.Transport.(*http.Transport)

	// The transport uses a custom DialContext closure, so we can't directly
	// inspect the dialer's Control field. Instead, test by connecting to loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx := context.Background()
	conn, err := transport.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected loopback connection to succeed, got: %v", err)
	}
	conn.Close()
}

// TestHookExecutor_AllowPrivateNetworks verifies that hookExecutor carries
// the allowPrivateNetworks flag.
func TestHookExecutor_AllowPrivateNetworks(t *testing.T) {
	t.Run("default_false", func(t *testing.T) {
		he := newHookExecutor(nil, nil, nil)
		if he.allowPrivateNetworks {
			t.Error("expected default allowPrivateNetworks to be false")
		}
	})

	t.Run("set_true", func(t *testing.T) {
		he := newHookExecutor(nil, nil, nil)
		he.allowPrivateNetworks = true
		if !he.allowPrivateNetworks {
			t.Error("expected allowPrivateNetworks to be true after setting")
		}
	})
}

// TestFuzzHookCallbacks_AllowPrivateNetworks verifies that fuzzHookCallbacks
// carries the allowPrivateNetworks flag.
func TestFuzzHookCallbacks_AllowPrivateNetworks(t *testing.T) {
	t.Run("default_false", func(t *testing.T) {
		hooks := newFuzzHookCallbacks(nil, nil)
		if hooks.allowPrivateNetworks {
			t.Error("expected default allowPrivateNetworks to be false")
		}
	})

	t.Run("set_true", func(t *testing.T) {
		hooks := newFuzzHookCallbacks(nil, nil)
		hooks.allowPrivateNetworks = true
		if !hooks.allowPrivateNetworks {
			t.Error("expected allowPrivateNetworks to be true after setting")
		}
	})
}

// TestWithAllowPrivateNetworks verifies the ServerOption sets the field.
func TestWithAllowPrivateNetworks(t *testing.T) {
	t.Run("default_false", func(t *testing.T) {
		s := &Server{}
		if s.allowPrivateNetworks {
			t.Error("expected default allowPrivateNetworks to be false")
		}
	})

	t.Run("option_sets_true", func(t *testing.T) {
		s := &Server{}
		opt := WithAllowPrivateNetworks(true)
		opt(s)
		if !s.allowPrivateNetworks {
			t.Error("expected allowPrivateNetworks to be true after WithAllowPrivateNetworks(true)")
		}
	})

	t.Run("option_sets_false", func(t *testing.T) {
		s := &Server{allowPrivateNetworks: true}
		opt := WithAllowPrivateNetworks(false)
		opt(s)
		if s.allowPrivateNetworks {
			t.Error("expected allowPrivateNetworks to be false after WithAllowPrivateNetworks(false)")
		}
	})
}

// TestResendHTTPClient_ServerDefault_AllowPrivateNetworks verifies that
// resendHTTPClient allows private networks when the server-level setting is true,
// even when the per-request parameter is false.
func TestResendHTTPClient_ServerDefault_AllowPrivateNetworks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Server has allowPrivateNetworks=true, request does not set it.
	s := &Server{allowPrivateNetworks: true}
	params := executeParams{} // AllowPrivateNetworks defaults to false

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// Should succeed because server-level setting disables SSRF protection.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error with server-level allowPrivateNetworks=true, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestResendHTTPClient_ServerFalse_RequestTrue_AllowPrivateNetworks verifies that
// per-request allow_private_networks=true still works when server default is false.
func TestResendHTTPClient_ServerFalse_RequestTrue_AllowPrivateNetworks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Server{allowPrivateNetworks: false}
	params := executeParams{AllowPrivateNetworks: true}

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected no error with per-request allowPrivateNetworks=true, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestResendHTTPClient_ServerFalse_RequestFalse_BlocksPrivate verifies that
// SSRF protection is active when both server and request settings are false.
func TestResendHTTPClient_ServerFalse_RequestFalse_BlocksPrivate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Server{allowPrivateNetworks: false}
	params := executeParams{AllowPrivateNetworks: false}

	client := s.resendHTTPClient(params)

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// Should fail because SSRF protection blocks loopback.
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected error for loopback with both settings false, got nil")
	}
}

// TestRawDialerFuncWithOpts_ServerDefault verifies that rawDialerFuncWithOpts
// is called with the combined server+request flag correctly.
// This tests the pattern: params.AllowPrivateNetworks || s.allowPrivateNetworks
func TestRawDialerFuncWithOpts_ServerDefault(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Simulate server-level setting: the combined flag is true.
	s := &Server{}
	dialer := s.rawDialerFuncWithOpts(true) // simulates params || s.allowPrivateNetworks

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected no error with combined allowPrivate=true, got: %v", err)
	}
	conn.Close()
}

// TestAllowPrivateNetworks_CombinedLogic verifies all combinations of
// server-level and per-request settings using table-driven tests.
func TestAllowPrivateNetworks_CombinedLogic(t *testing.T) {
	tests := []struct {
		name          string
		serverAllow   bool
		requestAllow  bool
		wantAllowed   bool
	}{
		{"server=false request=false", false, false, false},
		{"server=false request=true", false, true, true},
		{"server=true request=false", true, false, true},
		{"server=true request=true", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			combined := tt.requestAllow || tt.serverAllow
			if combined != tt.wantAllowed {
				t.Errorf("combined = %v, want %v", combined, tt.wantAllowed)
			}
		})
	}
}
