package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// blockedResponseBody is the JSON structure returned when a request is blocked
// by the target scope.
type blockedResponseBody struct {
	Error  string `json:"error"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

func TestTargetScope_HTTPForwardProxy_BlockedHost(t *testing.T) {
	// When target scope has allow rules, requests to hosts outside the scope
	// should receive a 403 Forbidden response.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Configure target scope: only allow example.com
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send request to the upstream (which is not example.com).
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

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Verify response body is JSON with the expected format.
	var blocked blockedResponseBody
	if err := json.Unmarshal(body, &blocked); err != nil {
		t.Fatalf("failed to parse blocked response body: %v", err)
	}
	if blocked.Error != "blocked by target scope" {
		t.Errorf("error = %q, want %q", blocked.Error, "blocked by target scope")
	}
	if blocked.Reason != "not in agent allow list" {
		t.Errorf("reason = %q, want %q", blocked.Reason, "not in agent allow list")
	}

	// Verify Content-Type is application/json.
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestTargetScope_HTTPForwardProxy_AllowedHost(t *testing.T) {
	// Requests to hosts within the target scope should pass through normally.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "allowed")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Configure target scope: allow the upstream host.
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET http://127.0.0.1:%s/test HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n",
		port, port)
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
	if string(body) != "allowed" {
		t.Errorf("body = %q, want %q", body, "allowed")
	}
}

func TestTargetScope_HTTPForwardProxy_NoRules_AllAllowed(t *testing.T) {
	// When no target scope rules are configured, all requests should pass
	// through (backward compatibility).
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "no-rules-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Set target scope with no rules (open mode).
	ts := proxy.NewTargetScope()
	handler.SetTargetScope(ts)

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
	if string(body) != "no-rules-ok" {
		t.Errorf("body = %q, want %q", body, "no-rules-ok")
	}
}

func TestTargetScope_HTTPForwardProxy_NilScope_AllAllowed(t *testing.T) {
	// When no target scope is set (nil), all requests should pass through.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "nil-scope-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Do not set any target scope — handler.targetScope remains nil.

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
	if string(body) != "nil-scope-ok" {
		t.Errorf("body = %q, want %q", body, "nil-scope-ok")
	}
}

func TestTargetScope_HTTPForwardProxy_DenyRule(t *testing.T) {
	// When target scope has a deny rule for the host, requests should be blocked
	// even when no allow rules are configured (open mode with explicit denies).
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Configure target scope: deny 127.0.0.1 (the upstream test server).
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "127.0.0.1"},
	})
	handler.SetTargetScope(ts)

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

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	var blocked blockedResponseBody
	if err := json.Unmarshal(body, &blocked); err != nil {
		t.Fatalf("failed to parse blocked response body: %v", err)
	}
	if blocked.Error != "blocked by target scope" {
		t.Errorf("error = %q, want %q", blocked.Error, "blocked by target scope")
	}
	if blocked.Reason != "blocked by agent deny rule" {
		t.Errorf("reason = %q, want %q", blocked.Reason, "blocked by agent deny rule")
	}
}

func TestTargetScope_HTTPForwardProxy_BlockedSessionRecording(t *testing.T) {
	// When a request is blocked by target scope, a session should be recorded
	// with BlockedBy="target_scope".
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	handler.SetTargetScope(ts)

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

	// Wait for session recording.
	time.Sleep(100 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.BlockedBy != "target_scope" {
		t.Errorf("BlockedBy = %q, want %q", entry.Session.BlockedBy, "target_scope")
	}
	if entry.Session.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", entry.Session.Protocol, "HTTP/1.x")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("Method = %q, want %q", entry.Send.Method, "GET")
	}
	// Blocked sessions should not have a receive message.
	if entry.Receive != nil {
		t.Error("blocked session should not have a receive message")
	}
}

func TestTargetScope_CONNECT_BlockedHost(t *testing.T) {
	// CONNECT requests to hosts outside the target scope should receive
	// a 403 Forbidden response.
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request to a blocked host.
	connectReq := "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	var blocked blockedResponseBody
	if err := json.Unmarshal(body, &blocked); err != nil {
		t.Fatalf("failed to parse blocked response body: %v", err)
	}
	if blocked.Error != "blocked by target scope" {
		t.Errorf("error = %q, want %q", blocked.Error, "blocked by target scope")
	}
	if blocked.Target != "evil.com" {
		t.Errorf("target = %q, want %q", blocked.Target, "evil.com")
	}
}

func TestTargetScope_CONNECT_AllowedHost(t *testing.T) {
	// CONNECT requests to hosts within the target scope should receive
	// a 200 Connection Established response.
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request to an allowed host.
	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
}

func TestTargetScope_CONNECT_NoRules_AllAllowed(t *testing.T) {
	// When no target scope rules are configured, CONNECT requests should
	// pass through (backward compatibility).
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	// Set target scope with no rules.
	ts := proxy.NewTargetScope()
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT any-host.com:443 HTTP/1.1\r\nHost: any-host.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
}

func TestTargetScope_CONNECT_BlockedSessionRecording(t *testing.T) {
	// When a CONNECT request is blocked by target scope, a session should be
	// recorded with BlockedBy="target_scope".
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for session recording.
	time.Sleep(100 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.BlockedBy != "target_scope" {
		t.Errorf("BlockedBy = %q, want %q", entry.Session.BlockedBy, "target_scope")
	}
	if entry.Session.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want %q", entry.Session.Protocol, "HTTPS")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "CONNECT" {
		t.Errorf("Method = %q, want %q", entry.Send.Method, "CONNECT")
	}
	if entry.Send.URL == nil {
		t.Fatal("send URL is nil")
	}
	if entry.Send.URL.Host != "blocked.example.com:443" {
		t.Errorf("URL host = %q, want %q", entry.Send.URL.Host, "blocked.example.com:443")
	}
}

func TestTargetScope_CONNECT_DenyRule(t *testing.T) {
	// CONNECT requests to explicitly denied hosts should be blocked even
	// when no allow rules are configured (open mode with denies).
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "evil.com"},
	})
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	var blocked blockedResponseBody
	if err := json.Unmarshal(body, &blocked); err != nil {
		t.Fatalf("failed to parse blocked response body: %v", err)
	}
	if blocked.Reason != "blocked by agent deny rule" {
		t.Errorf("reason = %q, want %q", blocked.Reason, "blocked by agent deny rule")
	}
}

func TestTargetScope_CONNECT_WildcardAllow_Blocked(t *testing.T) {
	// Wildcard allow rules should block non-matching hosts for CONNECT.
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tests := []struct {
		name string
		host string
	}{
		{name: "non-matching host", host: "evil.com:443"},
		{name: "bare domain not matched by wildcard", host: "example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.host, tt.host)
			conn.Write([]byte(connectReq))

			reader := bufio.NewReader(conn)
			resp, err := gohttp.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("read CONNECT response: %v", err)
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != gohttp.StatusForbidden {
				t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
			}
		})
	}
}

func TestTargetScope_CONNECT_WildcardAllow_Allowed(t *testing.T) {
	// Wildcard allow rules should allow matching subdomains for CONNECT.
	// We use a real upstream server so the proxy can establish the tunnel.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	// The upstream is at localhost:<port>; use sub.localhost doesn't work,
	// so we just verify the scope check logic unit-tests pass. We test
	// that allowed hosts reach the "200 Connection Established" step
	// using the checkTargetScopeHost function.
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	// Subdomain should be allowed.
	blocked, reason := handler.checkTargetScopeHost("sub.example.com", 443)
	if blocked {
		t.Errorf("sub.example.com should be allowed, got blocked: %s", reason)
	}

	// Deep subdomain should be allowed.
	blocked, reason = handler.checkTargetScopeHost("deep.sub.example.com", 443)
	if blocked {
		t.Errorf("deep.sub.example.com should be allowed, got blocked: %s", reason)
	}

	_ = port // unused in this unit test variant
}

func TestTargetScope_CONNECT_PortRestriction_Blocked(t *testing.T) {
	// Port-restricted allow rules should block CONNECT to different ports.
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com", Ports: []int{443}},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// CONNECT to example.com:8443 (different port) should be blocked.
	connectReq := "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}
}

func TestTargetScope_CONNECT_PortRestriction_Unit(t *testing.T) {
	// Verify port restriction logic via the unit-level checkTargetScopeHost.
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com", Ports: []int{443}},
	}, nil)
	handler.SetTargetScope(ts)

	// Port 443 should be allowed.
	blocked, reason := handler.checkTargetScopeHost("example.com", 443)
	if blocked {
		t.Errorf("example.com:443 should be allowed, got blocked: %s", reason)
	}

	// Port 8443 should be blocked.
	blocked, reason = handler.checkTargetScopeHost("example.com", 8443)
	if !blocked {
		t.Error("example.com:8443 should be blocked, got allowed")
	}
	if reason != "not in agent allow list" {
		t.Errorf("reason = %q, want %q", reason, "not in agent allow list")
	}

	// Port 80 should be blocked.
	blocked, _ = handler.checkTargetScopeHost("example.com", 80)
	if !blocked {
		t.Error("example.com:80 should be blocked, got allowed")
	}
}

func TestTargetScope_HTTPS_HostHeaderRewrite(t *testing.T) {
	// When the Host header inside a MITM tunnel differs from the CONNECT
	// authority, the proxy should re-check against the target scope.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "https-ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

	// Allow localhost (the CONNECT target) but deny evil.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "localhost"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Establish CONNECT tunnel to localhost (allowed).
	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send request with matching Host header (should pass).
	httpReq := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", httpsResp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "https-ok" {
		t.Errorf("body = %q, want %q", body, "https-ok")
	}
}

func TestTargetScope_HTTPS_HostMismatchBlocked(t *testing.T) {
	// When the Host header inside a MITM tunnel differs from the CONNECT
	// authority and the Host is blocked, the request should be blocked.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

	// Allow localhost (the CONNECT target) but not evil.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "localhost"},
	}, nil)
	handler.SetTargetScope(ts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Establish CONNECT tunnel to localhost (allowed).
	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send request with a different Host header (evil.com).
	// The proxy should re-check the target scope and block it.
	httpReq := "GET /steal-data HTTP/1.1\r\nHost: evil.com\r\nConnection: close\r\n\r\n"
	tlsConn.Write([]byte(httpReq))

	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", httpsResp.StatusCode, gohttp.StatusForbidden)
	}

	var blocked blockedResponseBody
	if err := json.Unmarshal(body, &blocked); err != nil {
		t.Fatalf("failed to parse blocked response body: %v", err)
	}
	if blocked.Error != "blocked by target scope" {
		t.Errorf("error = %q, want %q", blocked.Error, "blocked by target scope")
	}
	if blocked.Target != "evil.com" {
		t.Errorf("target = %q, want %q", blocked.Target, "evil.com")
	}

	// Verify blocked HTTPS session is recorded.
	time.Sleep(100 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}
	if entries[0].Session.BlockedBy != "target_scope" {
		t.Errorf("BlockedBy = %q, want %q", entries[0].Session.BlockedBy, "target_scope")
	}
	if entries[0].Session.Protocol != "HTTPS" {
		t.Errorf("Protocol = %q, want %q", entries[0].Session.Protocol, "HTTPS")
	}
}

func TestTargetScope_SetterAndGetter(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	// Initially nil.
	if handler.TargetScope != nil {
		t.Error("expected nil target scope initially")
	}

	// Set a target scope.
	ts := proxy.NewTargetScope()
	handler.SetTargetScope(ts)

	if handler.TargetScope != ts {
		t.Error("SetTargetScope/TargetScope round-trip failed")
	}
}

func TestCheckTargetScope_NilScope(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	// With nil target scope, nothing should be blocked.
	blocked, reason := handler.checkTargetScope(mustParseURL("http://example.com"))
	if blocked {
		t.Errorf("expected not blocked with nil scope, got reason: %s", reason)
	}
}

func TestCheckTargetScope_EmptyRules(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())
	ts := proxy.NewTargetScope()
	handler.SetTargetScope(ts)

	// With empty rules, nothing should be blocked.
	blocked, reason := handler.checkTargetScope(mustParseURL("http://example.com"))
	if blocked {
		t.Errorf("expected not blocked with empty rules, got reason: %s", reason)
	}
}

func TestCheckTargetScopeHost_NilScope(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	blocked, reason := handler.checkTargetScopeHost("example.com", 443)
	if blocked {
		t.Errorf("expected not blocked with nil scope, got reason: %s", reason)
	}
}

func TestCheckTargetScopeHost_EmptyRules(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())
	ts := proxy.NewTargetScope()
	handler.SetTargetScope(ts)

	blocked, reason := handler.checkTargetScopeHost("example.com", 443)
	if blocked {
		t.Errorf("expected not blocked with empty rules, got reason: %s", reason)
	}
}

func TestCheckTargetScope_BlockedByAllowList(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)
	handler.SetTargetScope(ts)

	tests := []struct {
		name       string
		url        string
		blocked    bool
		wantReason string
	}{
		{
			name:    "allowed host passes",
			url:     "http://allowed.com/path",
			blocked: false,
		},
		{
			name:       "unlisted host is blocked",
			url:        "http://unlisted.com/path",
			blocked:    true,
			wantReason: "not in agent allow list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := handler.checkTargetScope(mustParseURL(tt.url))
			if blocked != tt.blocked {
				t.Errorf("blocked = %v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
			if tt.blocked && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestCheckTargetScopeHost_BlockedByDenyList(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "evil.com"},
	})
	handler.SetTargetScope(ts)

	tests := []struct {
		name       string
		hostname   string
		port       int
		blocked    bool
		wantReason string
	}{
		{
			name:       "denied host is blocked",
			hostname:   "evil.com",
			port:       443,
			blocked:    true,
			wantReason: "blocked by agent deny rule",
		},
		{
			name:     "other host is allowed",
			hostname: "good.com",
			port:     443,
			blocked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := handler.checkTargetScopeHost(tt.hostname, tt.port)
			if blocked != tt.blocked {
				t.Errorf("blocked = %v, want %v (reason: %s)", blocked, tt.blocked, reason)
			}
			if tt.blocked && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestParseConnectPort(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		want     int
	}{
		{name: "standard port", hostPort: "example.com:443", want: 443},
		{name: "custom port", hostPort: "example.com:8443", want: 8443},
		{name: "no port defaults to 443", hostPort: "example.com", want: 443},
		{name: "port 80", hostPort: "example.com:80", want: 80},
		{name: "invalid port returns 0", hostPort: "example.com:abc", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseConnectPort(tt.hostPort)
			if got != tt.want {
				t.Errorf("parseConnectPort(%q) = %d, want %d", tt.hostPort, got, tt.want)
			}
		})
	}
}

// mustParseURL parses a URL and panics on error. For use in tests only.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("mustParseURL(%q): %v", rawURL, err))
	}
	return u
}
