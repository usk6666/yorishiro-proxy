package mcp

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1312: an empty host (":80") or an unspecified address ("0.0.0.0",
// "[::]") is dialled by Go as the proxy's own host, so with a scope that
// denies the loopback names every MCP dial helper must refuse it before
// any dial. Open mode is unchanged.

func unspecifiedLoopbackDenies() []connector.TargetRule {
	return []connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "localhost"}, {Hostname: "::1"}}
}

// unspecifiedCountingListener accepts on 127.0.0.1, counts and closes.
func unspecifiedCountingListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts := new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), accepts
}

func setupUnspecifiedScopeSession(t *testing.T, scope *connector.TargetScope) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := newServer(ctx, nil, newTestStore(t), nil, WithTargetScope(scope))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "unspecified-host-scope", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// T8: the dialling tools, through the real MCP handlers and a real
// loopback listener.
func TestResendTools_UnspecifiedHostBlockedByScope(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	cs := setupUnspecifiedScopeSession(t, newScopeWithRules(t, nil, unspecifiedLoopbackDenies(), nil, nil))

	httpReq := func(authority string) map[string]any {
		return map[string]any{"method": "GET", "scheme": "http", "authority": authority, "path": "/", "timeout_ms": 2000}
	}
	cases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "resend_http authority ::", tool: "resend_http", args: httpReq("::")},
		{name: "resend_http authority :P", tool: "resend_http", args: httpReq(":" + port)},
		{name: "resend_http authority [::]:P", tool: "resend_http", args: httpReq("[::]:" + port)},
		{name: "resend_http authority 0.0.0.0:P", tool: "resend_http", args: httpReq("0.0.0.0:" + port)},
		{name: "resend_http override_host [::]:P", tool: "resend_http", args: func() map[string]any {
			a := httpReq("example.com")
			a["override_host"] = "[::]:" + port
			return a
		}()},
		{name: "resend_ws target_addr 0.0.0.0:P", tool: "resend_ws", args: map[string]any{
			"target_addr": "0.0.0.0:" + port, "scheme": "ws", "path": "/", "opcode": "text", "payload": "x", "timeout_ms": 2000,
		}},
		{name: "resend_ws target_addr :P", tool: "resend_ws", args: map[string]any{
			"target_addr": ":" + port, "scheme": "ws", "path": "/", "opcode": "text", "payload": "x", "timeout_ms": 2000,
		}},
		{name: "resend_grpc target_addr 0.0.0.0:P", tool: "resend_grpc", args: map[string]any{
			"target_addr": "0.0.0.0:" + port, "scheme": "http", "service": "pkg.S", "method": "M",
			"messages": []map[string]any{{"payload": "x"}}, "timeout_ms": 2000,
		}},
		{name: "resend_grpc target_addr [::]:P", tool: "resend_grpc", args: map[string]any{
			"target_addr": "[::]:" + port, "scheme": "http", "service": "pkg.S", "method": "M",
			"messages": []map[string]any{{"payload": "x"}}, "timeout_ms": 2000,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := accepts.Load()
			res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: c.tool, Arguments: c.args})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			text := extractTextContent(res)
			if !res.IsError || !strings.Contains(text, "blocked by target scope") {
				t.Errorf("%s = (IsError %v) %q, want a target scope block", c.tool, res.IsError, text)
			}
			time.Sleep(50 * time.Millisecond)
			if n := accepts.Load() - before; n != 0 {
				t.Errorf("loopback listener accepts = %d, want 0", n)
			}
		})
	}
}

// T8, open mode guard: the same dial is attempted with no rules.
func TestResendHTTP_UnspecifiedHostOpenModeDials(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	cs := setupUnspecifiedScopeSession(t, connector.NewTargetScope())
	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: "resend_http", Arguments: map[string]any{
		"method": "GET", "scheme": "http", "authority": "0.0.0.0:" + port, "path": "/", "timeout_ms": 2000,
	}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if accepts.Load() == 0 {
		t.Error("open mode resend_http to 0.0.0.0 never dialled, want it unchanged")
	}
}

// T8: the helpers whose tools need a recorded flow or a reflection
// server (resend_raw / fuzz_raw, fuzz_http, grpc_schema discover).
func TestScopeHelpers_UnspecifiedHostBlocked(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{targetScope: newScopeWithRules(t, nil, unspecifiedLoopbackDenies(), nil, nil)})
	for _, addr := range []string{"[::]:9", "0.0.0.0:9", "[::ffff:0.0.0.0]:9"} {
		if err := s.checkRawDialScope(false, addr); err == nil || !strings.Contains(err.Error(), "blocked by target scope") {
			t.Errorf("checkRawDialScope(%q) = %v, want a target scope block", addr, err)
		}
		params := grpcSchemaToolParams{TargetAddr: addr}
		scheme, u := buildGRPCSchemaDiscoverCanonical(params)
		if err := s.checkGRPCSchemaDiscoverGates(context.Background(), scheme, u, params); err == nil {
			t.Errorf("grpc_schema discover gates(%q) = nil, want a target scope block", addr)
		}
	}
	// fuzz_http's plan check shares checkResendHTTPScopeHostHeaders; the
	// unbracketed "::" authority dials [::]:80 with no override_host.
	msg := &envelope.HTTPMessage{Method: "GET", Scheme: "http", Authority: "::", Path: "/"}
	addr, _, _, err := resolveResendHTTPDial(msg, "")
	if err != nil {
		t.Fatalf("resolveResendHTTPDial: %v", err)
	}
	if err := s.checkResendHTTPScopeHostHeaders(msg, addr, "", nil); err == nil {
		t.Errorf("checkResendHTTPScopeHostHeaders(authority ::, dial %q) = nil, want a target scope block", addr)
	}
}

// T11: security test_target reports the new reason.
func TestSecurityTestTarget_UnspecifiedHostReason(t *testing.T) {
	cs := setupUnspecifiedScopeSession(t, newScopeWithRules(t, nil, unspecifiedLoopbackDenies(), nil, nil))
	for _, raw := range []string{"http://0.0.0.0/", "http://[::]:8080/"} {
		u, _ := url.Parse(raw)
		res := testTarget(t, cs, u.String())
		if res.Allowed || !strings.Contains(res.Reason, "unspecified host") {
			t.Errorf("test_target(%s) = (allowed %v, %q), want blocked with the unspecified-host reason", raw, res.Allowed, res.Reason)
		}
	}
}
