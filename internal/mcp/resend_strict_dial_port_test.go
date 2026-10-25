package mcp

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// USK-1262: the port an MCP tool's scope check reads must be the port its
// dial connects to. net.Dial wraps a decimal port modulo 2^32, skips a
// leading space or "+" and resolves service names, so a dial address such
// as "127.0.0.1:<p+2^32>" or "127.0.0.1: <p>" reaches p while the scope
// check read a port no rule names (or, when net/url could not split the
// port, the whole "host:port" as the hostname). Every MCP dial address
// is now validated with connector.SplitTargetHostPort's rule before the
// scope check — in open mode too — and CheckURL / the address leg fail
// closed on such a port when rules exist.

// strictPortWrap returns port + 2^32 as a decimal string: net.Dial reads
// it as port.
func strictPortWrap(port string) string {
	p, _ := strconv.ParseInt(port, 10, 64)
	return strconv.FormatInt(p+1<<32, 10)
}

// strictPortDeny is the operator policy of the report: 127.0.0.1 is
// denied on the listener's port only.
func strictPortDeny(t *testing.T, port string) *connector.TargetScope {
	t.Helper()
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return newScopeWithRules(t, nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{p}}}, nil, nil)
}

// setupStrictPortSession is setupUnspecifiedScopeSession with the store
// exposed, for flow_id-based cases.
func setupStrictPortSession(t *testing.T, scope *connector.TargetScope) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	ctx := context.Background()
	store := newTestStore(t)
	srv := newServer(ctx, nil, store, nil, WithTargetScope(scope))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "strict-dial-port", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

// callStrictPortTool calls a tool with a bounded context so a red run
// fails fast instead of hanging.
func callStrictPortTool(t *testing.T, cs *gomcp.ClientSession, tool string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &gomcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", tool, err)
	}
	return res
}

// assertNoAccept waits briefly and checks that the listener saw no new
// connection since before.
func assertNoAccept(t *testing.T, accepts *atomic.Int64, before int64) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if n := accepts.Load() - before; n != 0 {
		t.Errorf("loopback listener accepts = %d, want 0 (the dial reached the denied port)", n)
	}
}

func strictPortHTTPArgs(authority string) map[string]any {
	return map[string]any{
		"method": "GET", "scheme": "http", "authority": authority, "path": "/",
		"headers":    []map[string]any{{"name": "Host", "value": "127.0.0.1"}},
		"timeout_ms": 2000,
	}
}

func strictPortGRPCArgs(targetAddr string) map[string]any {
	return map[string]any{
		"target_addr": targetAddr, "scheme": "http", "service": "pkg.S", "method": "M",
		"messages": []map[string]any{{"payload": "x"}}, "timeout_ms": 2000,
	}
}

// T1-T5, T7: the dialling tools, through the real MCP handlers and a real
// loopback listener on the denied port.
func TestStrictDialPort_ToolsDoNotReachDeniedPort(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	big := strictPortWrap(port)
	cs, _ := setupStrictPortSession(t, strictPortDeny(t, port))

	h2c := strictPortHTTPArgs("127.0.0.1:" + big)
	h2c["http_version"] = "h2c"
	cases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"T1 resend_http authority p+2^32 + Host", "resend_http", strictPortHTTPArgs("127.0.0.1:" + big)},
		{"T2 resend_http h2c authority p+2^32", "resend_http", h2c},
		{"T3 resend_http authority leading space + Host", "resend_http", strictPortHTTPArgs("127.0.0.1: " + port)},
		{"T4 resend_grpc target_addr p+2^32", "resend_grpc", strictPortGRPCArgs("127.0.0.1:" + big)},
		{"T4 resend_grpc target_addr leading space", "resend_grpc", strictPortGRPCArgs("127.0.0.1: " + port)},
		{"T5 grpc_schema discover target_addr p+2^32", "grpc_schema", map[string]any{
			"action": "discover",
			"params": map[string]any{"target_addr": "127.0.0.1:" + big, "scheme": "http", "timeout_ms": 2000},
		}},
		{"T5 grpc_schema discover target_addr leading space", "grpc_schema", map[string]any{
			"action": "discover",
			"params": map[string]any{"target_addr": "127.0.0.1: " + port, "scheme": "http", "timeout_ms": 2000},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := accepts.Load()
			res := callStrictPortTool(t, cs, c.tool, c.args)
			if !res.IsError {
				t.Errorf("%s succeeded, want a tool error", c.tool)
			}
			assertNoAccept(t, accepts, before)
		})
	}
}

// seedStrictPortGRPCFlow records a gRPC Start flow whose client-declared
// :authority is authority (verbatim, as the store keeps it).
func seedStrictPortGRPCFlow(t *testing.T, store flow.Store, authority string) string {
	t.Helper()
	ctx := context.Background()
	streamID := "strict-port-grpc"
	if err := store.SaveStream(ctx, &flow.Stream{
		ID: streamID, ConnID: "conn-" + streamID, Protocol: "grpc", Scheme: "http",
		State: "complete", Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID: streamID + "-send-start", StreamID: streamID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST",
		URL:     envelope.URLFromWirePath("http", authority, "/pkg.S/M", ""),
		Headers: map[string][]string{"content-type": {"application/grpc"}},
		Metadata: map[string]string{
			"grpc_event": "start", "grpc_service": "pkg.S", "grpc_method": "M",
		},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return streamID
}

// T4b: resend_grpc by flow_id with target_addr omitted dials the recorded
// :authority. When that authority's port is not strict, CheckURL used to
// judge the whole "host:port" as the hostname (so even a hostname-only
// deny missed) and the address leg was skipped because the dial address
// equalled the URL host. "+p" and " p" are forms net.Dial reads as p.
func TestStrictDialPort_ResendGRPCRecordedAuthority(t *testing.T) {
	for _, form := range []string{"+", " "} {
		t.Run("authority 127.0.0.1:"+form+"p", func(t *testing.T) {
			port, accepts := unspecifiedCountingListener(t)
			deny := newScopeWithRules(t, nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, nil, nil)
			cs, store := setupStrictPortSession(t, deny)
			id := seedStrictPortGRPCFlow(t, store, "127.0.0.1:"+form+port)
			before := accepts.Load()
			res := callStrictPortTool(t, cs, "resend_grpc", map[string]any{
				"flow_id": id, "messages": []map[string]any{{"payload": "x"}}, "timeout_ms": 2000,
			})
			if !res.IsError {
				t.Errorf("resend_grpc succeeded, want a tool error")
			}
			assertNoAccept(t, accepts, before)
		})
	}
}

// T6: macro and hook send funcs check the template-expanded URL with
// CheckURL before net/http dials it.
func TestStrictDialPort_MacroAndHookSendFuncs(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	s := mkServerFromLegacyDeps(legacyDeps{targetScope: strictPortDeny(t, port)})
	target := "http://127.0.0.1:" + strictPortWrap(port) + "/"
	sends := map[string]macro.SendFunc{
		"macroSendFunc":     s.macroSendFunc("strict-port"),
		"hookMacroSendFunc": hookMacroSendFunc(s, "strict-port"),
	}
	for name, send := range sends {
		t.Run(name, func(t *testing.T) {
			before := accepts.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := send(ctx, &macro.SendRequest{Method: "GET", URL: target, StepID: "s1"})
			if err == nil || !strings.Contains(err.Error(), "target scope") {
				t.Errorf("%s(%s) = %v, want a target scope error", name, target, err)
			}
			assertNoAccept(t, accepts, before)
		})
	}
}

// T7: fuzz_http (from scratch, explicit Host) refuses at plan time, and
// the WS / gRPC dial resolvers (shared by resend_ws / fuzz_ws /
// resend_grpc / fuzz_grpc, with or without target_addr) refuse a
// non-strict dial port.
func TestStrictDialPort_FuzzHTTPPlanAndDialResolvers(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{targetScope: strictPortDeny(t, "8080")})
	big := strictPortWrap("8080")
	for _, authority := range []string{"127.0.0.1:" + big, "127.0.0.1: 8080", "127.0.0.1:+8080", "127.0.0.1:http"} {
		in := &fuzzHTTPInput{
			Method: "GET", Scheme: "http", Authority: authority, Path: "/",
			Headers:   []headerKV{{Name: "Host", Value: "127.0.0.1"}},
			Positions: []fuzzHTTPPosition{{Path: "body", Payloads: []string{"a"}}},
		}
		if _, err := s.buildFuzzHTTPPlan(context.Background(), in); err == nil {
			t.Errorf("buildFuzzHTTPPlan(authority %q) = nil error, want refused", authority)
		}
		if _, _, err := resolveResendWSDialTarget(authority, false); err == nil {
			t.Errorf("resolveResendWSDialTarget(%q) = nil error, want refused", authority)
		}
		if _, _, err := resolveResendGRPCDialTarget(authority, false); err == nil {
			t.Errorf("resolveResendGRPCDialTarget(%q) = nil error, want refused", authority)
		}
	}
	// Strict forms, port-less and IPv6 authorities still resolve.
	for authority, want := range map[string]string{
		"127.0.0.1:8080":   "127.0.0.1:8080",
		"127.0.0.1:008080": "127.0.0.1:008080",
		"127.0.0.1":        "127.0.0.1:80",
		"127.0.0.1:":       "127.0.0.1:80",
		"[::1]:8080":       "[::1]:8080",
		"::1":              "[::1]:80",
	} {
		addr, _, err := resolveResendWSDialTarget(authority, false)
		if err != nil || addr != want {
			t.Errorf("resolveResendWSDialTarget(%q) = (%q, %v), want (%q, nil)", authority, addr, err, want)
		}
	}
}

// T8: open mode — a non-strict dial port is a validation error, not a
// dial (input validation, not scope).
func TestStrictDialPort_OpenModeValidationError(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	big := strictPortWrap(port)
	cs, _ := setupStrictPortSession(t, connector.NewTargetScope())
	cases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"resend_http authority p+2^32", "resend_http", strictPortHTTPArgs("127.0.0.1:" + big)},
		{"resend_grpc target_addr p+2^32", "resend_grpc", strictPortGRPCArgs("127.0.0.1:" + big)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := accepts.Load()
			res := callStrictPortTool(t, cs, c.tool, c.args)
			text := extractTextContent(res)
			if !res.IsError || !strings.Contains(text, "1-65535") {
				t.Errorf("%s = (IsError %v) %q, want a dial port validation error", c.tool, res.IsError, text)
			}
			assertNoAccept(t, accepts, before)
		})
	}
}

// T9: open-mode regression guard — strict ports (leading zeros included)
// still dial.
func TestStrictDialPort_OpenModeStrictPortsDial(t *testing.T) {
	port, accepts := unspecifiedCountingListener(t)
	cs, _ := setupStrictPortSession(t, connector.NewTargetScope())
	for _, authority := range []string{"127.0.0.1:" + port, "127.0.0.1:00" + port} {
		before := accepts.Load()
		_ = callStrictPortTool(t, cs, "resend_http", strictPortHTTPArgs(authority))
		deadline := time.Now().Add(2 * time.Second)
		for accepts.Load() == before && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if accepts.Load() == before {
			t.Errorf("open mode resend_http to %q never dialled, want it unchanged", authority)
		}
	}
}

// T12: the address leg reads the port strictly when rules exist.
func TestStrictDialPort_AddrPathHelperBlocksNonStrictPort(t *testing.T) {
	ts := strictPortDeny(t, "8080")
	for _, addr := range []string{"127.0.0.1:" + strictPortWrap("8080"), "127.0.0.1: 8080", "127.0.0.1:+8080", "127.0.0.1:http", "127.0.0.1:0", "example.com:65536"} {
		if err := checkTargetScopeAddrPathHelper(ts, "http", addr, "/"); err == nil {
			t.Errorf("checkTargetScopeAddrPathHelper(%q) = nil, want a target scope block", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:9090", "127.0.0.1", "[::1]:8080", "example.com:0443"} {
		if err := checkTargetScopeAddrPathHelper(ts, "http", addr, "/"); err != nil {
			t.Errorf("checkTargetScopeAddrPathHelper(%q) = %v, want allowed", addr, err)
		}
	}
	if err := checkTargetScopeAddrPathHelper(connector.NewTargetScope(), "http", "127.0.0.1:http", "/"); err != nil {
		t.Errorf("open mode checkTargetScopeAddrPathHelper = %v, want nil", err)
	}
}

// T13: security test_target reports the verdict the send path enforces.
func TestStrictDialPort_SecurityTestTarget(t *testing.T) {
	cs := setupUnspecifiedScopeSession(t, strictPortDeny(t, "8080"))
	for _, raw := range []string{"http://127.0.0.1:" + strictPortWrap("8080") + "/", "http://127.0.0.1:0/", "http://127.0.0.1:65536/"} {
		u, _ := url.Parse(raw)
		res := testTarget(t, cs, u.String())
		if res.Allowed || !strings.Contains(res.Reason, "port") {
			t.Errorf("test_target(%s) = (allowed %v, %q), want blocked with a port reason", raw, res.Allowed, res.Reason)
		}
	}
}

// TestStrictDialPort_SecurityTestTargetReport is the reporting half of T13:
// test_target's tested_target.port, matched_rule and layer describe the
// port the strict rule yields. A port the scope check refused as
// uninterpretable is reported as 0 with no matched rule — not as the
// digit run's value (or its overflow) and not as a hostname-only deny that
// never took part in the decision. Strict ports, leading zeros and scheme
// defaults keep their values.
func TestStrictDialPort_SecurityTestTargetReport(t *testing.T) {
	cs := setupUnspecifiedScopeSession(t, newScopeWithRules(t, nil,
		[]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil, nil))
	for _, tc := range []struct {
		raw         string
		wantPort    int
		wantAllowed bool
		wantRule    bool
		wantLayer   string
	}{
		{"http://127.0.0.1:" + strictPortWrap("8080") + "/", 0, false, false, ""},
		{"http://127.0.0.1:99999999999999999999999/", 0, false, false, ""},
		{"http://127.0.0.1:65536/", 0, false, false, ""},
		{"http://127.0.0.1:0/", 0, false, false, ""},
		{"http://127.0.0.1:8080/", 8080, false, true, "policy"},
		{"http://127.0.0.1:0080/", 80, false, true, "policy"},
		{"https://127.0.0.1/", 443, false, true, "policy"},
		{"http://example.com:00443/", 443, true, false, ""},
		{"http://example.com/", 80, true, false, ""},
	} {
		res := testTarget(t, cs, tc.raw)
		if res.Allowed != tc.wantAllowed {
			t.Errorf("test_target(%s).allowed = %v (%q), want %v", tc.raw, res.Allowed, res.Reason, tc.wantAllowed)
		}
		if res.TestedTarget == nil || res.TestedTarget.Port != tc.wantPort {
			t.Errorf("test_target(%s).tested_target = %+v, want port %d", tc.raw, res.TestedTarget, tc.wantPort)
		}
		if (res.MatchedRule != nil) != tc.wantRule || res.Layer != tc.wantLayer {
			t.Errorf("test_target(%s) matched_rule = %v, layer = %q; want rule %v, layer %q", tc.raw, res.MatchedRule, res.Layer, tc.wantRule, tc.wantLayer)
		}
	}
}
