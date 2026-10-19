//go:build e2e

// USK-1083 smoke: raw (bytechunk) envelopes must carry the connection's
// EnvelopeContext so HostScopeStep gates them. Before the fix every raw
// envelope had an empty TargetHost, HostScopeStep short-circuited, and a
// tcp_forwards protocol=raw entry relayed bytes to a target the operator
// Policy denies.
//
// Helpers shared with the exhaustive tier
// (raw_target_scope_integration_test.go, live_conn_reconcile_*) live here
// because plain `//go:build e2e` files compile in both tiers.
package mcptest_test

import (
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// echoUpstream is a TCP echo server counting the bytes it received.
func echoUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var received atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						received.Add(int64(n))
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &received
}

// rawAddrPort returns the numeric port of a host:port address.
func rawAddrPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return port
}

// denyPolicyConfig returns a config document whose Policy denies
// 127.0.0.1:port, optionally only for the given schemes.
func denyPolicyConfig(port int, schemes ...string) string {
	rule := fmt.Sprintf(`{"hostname":"127.0.0.1","ports":[%d]`, port)
	if len(schemes) > 0 {
		rule += `,"schemes":[`
		for i, s := range schemes {
			if i > 0 {
				rule += ","
			}
			rule += strconv.Quote(s)
		}
		rule += `]`
	}
	rule += `}`
	return `{"target_scope_policy":{"denies":[` + rule + `]}}`
}

// startForwards calls proxy_start with the given tcp_forwards entries
// (keyed by a placeholder index; each gets a free port) and extra args,
// and returns the forward listener addresses in the same order.
func startForwards(t *testing.T, h *mcptest.Harness, extra map[string]any, entries ...map[string]any) []string {
	t.Helper()
	fwds := map[string]any{}
	addrs := make([]string, 0, len(entries))
	for _, e := range entries {
		port := pickFreePort(t)
		fwds[strconv.Itoa(port)] = e
		addrs = append(addrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	args := map[string]any{"listen_addr": "127.0.0.1:0", "tcp_forwards": fwds}
	for k, v := range extra {
		args[k] = v
	}
	h.MustOK(t, "proxy_start", args)
	return addrs
}

// queryRawFlows returns the raw-protocol Streams matching filter.
func queryRawFlows(t *testing.T, h *mcptest.Harness, filter map[string]any) []map[string]any {
	t.Helper()
	f := map[string]any{"protocol": "raw"}
	for k, v := range filter {
		f[k] = v
	}
	res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": f})
	raw, _ := res.Decoded["flows"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// waitRawFlows polls until at least one raw Stream matches filter and,
// when pred is non-nil, satisfies it; it fails the test after d.
func waitRawFlows(t *testing.T, h *mcptest.Harness, filter map[string]any, pred func(map[string]any) bool, d time.Duration, what string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		flows := queryRawFlows(t, h, filter)
		var hit []map[string]any
		for _, f := range flows {
			if pred == nil || pred(f) {
				hit = append(hit, f)
			}
		}
		if len(hit) > 0 {
			return hit
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: no raw Stream matching %v within %v (raw streams seen: %v)", what, filter, d, flows)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitBlockedRawStream waits for the target_scope audit Stream of a raw
// connection.
func waitBlockedRawStream(t *testing.T, h *mcptest.Harness) map[string]any {
	t.Helper()
	return waitRawFlows(t, h, map[string]any{"blocked_by": "target_scope"}, nil, 5*time.Second,
		"raw target_scope deny")[0]
}

// queryFlowDetail returns the query(resource=flow) document for id.
func queryFlowDetail(t *testing.T, h *mcptest.Harness, id string) map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	return res.Decoded
}

// writeRaw dials addr and writes payload, returning the open conn.
func writeRaw(t *testing.T, addr string, payload []byte) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	return c
}

// TestE2E_RawTargetScope_TCPForwardDenied is USK-1083 T1: a tcp_forwards
// protocol=raw entry whose target the Policy denies delivers no byte to
// the upstream, and the block is recorded as a raw audit Stream carrying
// the connection's conn_id.
func TestE2E_RawTargetScope_TCPForwardDenied(t *testing.T) {
	target, received := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: denyPolicyConfig(rawAddrPort(t, target)),
	})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	writeRaw(t, fwd, []byte{0x00, 0x01, 'r', 'a', 'w', '-', 'd', 'e', 'n', 'y'})

	blocked := waitBlockedRawStream(t, h)
	if got := received.Load(); got != 0 {
		t.Errorf("denied upstream received %d bytes, want 0", got)
	}
	if p, _ := blocked["protocol"].(string); p != "raw" {
		t.Errorf("audit Stream protocol = %q, want raw", p)
	}
	id, _ := blocked["id"].(string)
	detail := queryFlowDetail(t, h, id)
	if c, _ := detail["conn_id"].(string); c == "" {
		t.Errorf("audit Stream conn_id is empty; want the connection's conn_id")
	}
}
