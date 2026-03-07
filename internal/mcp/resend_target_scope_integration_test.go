//go:build e2e

package mcp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupExecuteWithTargetScope creates a Server with a configured TargetScope and
// a permissive HTTP client for testing target scope enforcement in execute actions.
func setupExecuteWithTargetScope(t *testing.T, store flow.Store, ts *proxy.TargetScope) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if ts != nil {
		opts = append(opts, WithTargetScope(ts))
	}

	s := NewServer(ctx, nil, store, nil, opts...)
	s.deps.replayDoer = newPermissiveClient()
	s.deps.rawReplayDialer = &testDialer{}
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// --- Resend action target scope tests ---

func TestExecuteResend_TargetScope_Allowed(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	// Parse the echo server URL to get the hostname.
	serverURL, _ := url.Parse(echoServer.URL + "/api/test")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Configure target scope to allow the echo server host.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
}

func TestExecuteResend_TargetScope_BlockedByAllowList(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Configure target scope to only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked host, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
	if !strings.Contains(text, "evil.com") {
		t.Errorf("error message should mention blocked host, got: %s", text)
	}
}

func TestExecuteResend_TargetScope_BlockedByDenyRule(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://admin.internal/secret")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Configure target scope with a deny rule for admin.internal.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "admin.internal"},
	})

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for denied host, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
	if !strings.Contains(text, "blocked") {
		t.Errorf("error message should mention blocked, got: %s", text)
	}
}

func TestExecuteResend_TargetScope_OverrideURL_Blocked(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	// Original URL is allowed.
	serverURL, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Configure target scope to allow only the echo server.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)

	// Try to resend with override_url pointing to a different host.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":      entry.Session.ID,
			"override_url": "http://evil.com/api/test",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked override_url, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteResend_TargetScope_OverrideHost_Blocked(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	serverURL, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Configure target scope to allow the echo server.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)

	// Try to resend with override_host pointing to a different host.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":       entry.Session.ID,
			"override_host": "evil.com:8080",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked override_host, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteResend_TargetScope_NoRules_AllAllowed(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	serverURL, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Empty target scope (no rules) - everything should be allowed.
	ts := proxy.NewTargetScope()
	cs := setupExecuteWithTargetScope(t, store, ts)

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if result.IsError {
		t.Fatalf("expected success with no rules (open mode), got error: %v", result.Content)
	}
}

// --- Resend redirect target scope tests ---

func TestExecuteResend_TargetScope_RedirectBlocked(t *testing.T) {
	store := newTestStore(t)

	// Create a redirect server that redirects to evil.com.
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.com/malicious", http.StatusFound)
	}))
	t.Cleanup(redirectServer.Close)

	serverURL, _ := url.Parse(redirectServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 302,
			Body:       []byte(""),
		},
	)

	// Allow the redirect server host (127.0.0.1) but not evil.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	// Create a Server with target scope. The initial request to localhost succeeds
	// (since it is in scope), then the redirect to evil.com gets blocked by the
	// target scope check.
	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithTargetScope(ts))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	followRedirects := true
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          entry.Session.ID,
			"follow_redirects": followRedirects,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for redirect to blocked host, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// --- Resend raw target scope tests ---

func TestExecuteResendRaw_TargetScope_Blocked(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/test")
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: evil.com\r\n\r\n")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked host in resend_raw, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteResendRaw_TargetScope_TargetAddr_Blocked(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/test")
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Allow example.com but deny evil.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)

	// Override target_addr to an unauthorized host.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": "evil.com:80",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked target_addr in resend_raw, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteResendRaw_TargetScope_Allowed(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	host, port, _ := net.SplitHostPort(addr)
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	u, _ := url.Parse("http://" + addr + "/test")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Allow the test server host.
	ts := proxy.NewTargetScope()
	portInt := targetDefaultPort("http", port)
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: host, Ports: []int{portInt}},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if result.IsError {
		t.Fatalf("expected success for allowed host in resend_raw, got error: %v", result.Content)
	}
}

// --- TCP Replay target scope tests ---

func TestExecuteTcpReplay_TargetScope_Blocked(t *testing.T) {
	store := newTestStore(t)

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "TCP",
			FlowType:  "bidirectional",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			ConnInfo: &flow.ConnectionInfo{
				ServerAddr: "evil.com:1234",
			},
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Body:      []byte("hello"),
		},
		&flow.Message{
			Sequence:  1,
			Direction: "receive",
			Timestamp: time.Now(),
			Body:      []byte("world"),
		},
	)

	// Only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked host in tcp_replay, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteTcpReplay_TargetScope_TargetAddr_Blocked(t *testing.T) {
	store := newTestStore(t)

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "TCP",
			FlowType:  "bidirectional",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			ConnInfo: &flow.ConnectionInfo{
				ServerAddr: "example.com:1234",
			},
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Body:      []byte("hello"),
		},
		&flow.Message{
			Sequence:  1,
			Direction: "receive",
			Timestamp: time.Now(),
			Body:      []byte("world"),
		},
	)

	// Only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)

	// Override target_addr to evil.com.
	result := executeCallTool(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": "evil.com:1234",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked target_addr in tcp_replay, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// --- WebSocket resend target scope tests ---

func TestExecuteWebSocketResend_TargetScope_Blocked(t *testing.T) {
	store := newTestStore(t)

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "WebSocket",
			FlowType:  "bidirectional",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			ConnInfo: &flow.ConnectionInfo{
				ServerAddr: "evil.com:443",
				TLSVersion: "TLS 1.3",
			},
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Body:      []byte("ws message"),
			Metadata:  map[string]string{"opcode": "1"},
		},
		&flow.Message{
			Sequence:  1,
			Direction: "receive",
			Timestamp: time.Now(),
			Body:      []byte("ws response"),
		},
	)

	// Only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	msgSeq := 0
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          entry.Session.ID,
			"message_sequence": msgSeq,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked WebSocket target, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// --- Fuzz target scope tests ---

func TestExecuteFuzz_TargetScope_Blocked(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/api/test")
	saveTestEntry(t, store,
		&flow.Flow{
			ID:        "fuzz-template-blocked",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     "fuzz-template-blocked",
			"attack_type": "sequential",
			"positions": []map[string]any{
				{
					"id":          "pos-0",
					"location":    "header",
					"name":        "Content-Type",
					"payload_set": "types",
				},
			},
			"payload_sets": map[string]any{
				"types": map[string]any{
					"type":   "list",
					"values": []string{"text/html", "application/xml"},
				},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for blocked fuzz template host, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// --- Macro target scope tests ---

func TestExecuteRunMacro_TargetScope_Blocked(t *testing.T) {
	store := newTestStore(t)

	// Create a flow with a blocked URL.
	u, _ := url.Parse("http://evil.com/api/login")
	saveTestEntry(t, store,
		&flow.Flow{
			ID:        "macro-blocked-session",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"user":"admin"}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte(`{"token":"abc"}`),
		},
	)

	// Define a macro that uses the blocked flow.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithTargetScope(ts))
	s.deps.replayDoer = newPermissiveClient()
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// First define the macro.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test-blocked-macro",
			"steps": []map[string]any{
				{
					"id":      "step-1",
					"flow_id": "macro-blocked-session",
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro - should be blocked.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "test-blocked-macro",
		},
	})

	if !runResult.IsError {
		t.Fatal("expected error for blocked macro step host, got success")
	}
	text := runResult.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestExecuteRunMacro_TargetScope_OverrideURL_Blocked(t *testing.T) {
	store := newTestStore(t)

	// Create a flow with an allowed URL.
	u, _ := url.Parse("http://example.com/api/login")
	saveTestEntry(t, store,
		&flow.Flow{
			ID:        "macro-override-session",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"user":"admin"}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte(`{"token":"abc"}`),
		},
	)

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithTargetScope(ts))
	s.deps.replayDoer = newPermissiveClient()
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// Define a macro with override_url pointing to evil.com.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test-override-macro",
			"steps": []map[string]any{
				{
					"id":           "step-1",
					"flow_id":      "macro-override-session",
					"override_url": "http://evil.com/api/login",
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro - should be blocked because of override_url.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "test-override-macro",
		},
	})

	if !runResult.IsError {
		t.Fatal("expected error for blocked macro override_url, got success")
	}
	text := runResult.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// Test DryRun bypasses target scope (dry-run should still check).
func TestExecuteResend_TargetScope_DryRun_StillChecked(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"dry_run": true,
		},
	})

	// Target scope check happens before dry-run, so it should still block.
	if !result.IsError {
		t.Fatal("expected error for blocked host even in dry-run, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// Test resend_raw dry-run is also blocked by target scope check.
func TestExecuteResendRaw_TargetScope_DryRun_StillChecked(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/test")
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: evil.com\r\n\r\n")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"dry_run": true,
		},
	})

	// Target scope check now happens before dry-run, so it should block.
	if !result.IsError {
		t.Fatal("expected error for blocked host even in dry-run, got success")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}
