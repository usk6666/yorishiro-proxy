//go:build e2e && !e2e_smoke

// USK-1142: connections refused because max_connections is saturated must
// be visible to the agent through MCP `query`, both as an aggregate in
// query(status).connection_rejections and as a blocked_by="capacity"
// Stream in query(flows). Drives the production server through the
// JSON-RPC harness with max_connections=1, a silent connection holding
// the only slot, and a real over-cap dial.
package mcptest_test

import (
	"bufio"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// capacityStatus is the subset of query(status) read by these tests.
type capacityStatus struct {
	ActiveConnections    int `json:"active_connections"`
	ConnectionRejections *struct {
		Total  int64  `json:"total"`
		LastAt string `json:"last_at"`
		ByKind struct {
			Connect int64 `json:"connect"`
			TCP     int64 `json:"tcp"`
		} `json:"by_kind"`
		Recent []struct {
			Listener       string `json:"listener"`
			ForwardPort    string `json:"forward_port"`
			RemoteAddr     string `json:"remote_addr"`
			DetectedKind   string `json:"detected_kind"`
			Method         string `json:"method"`
			Target         string `json:"target"`
			Wrote503       bool   `json:"wrote_503"`
			MaxConnections int    `json:"max_connections"`
			Recorded       bool   `json:"recorded"`
		} `json:"recent"`
		Unrecorded int64 `json:"unrecorded"`
	} `json:"connection_rejections"`
}

func queryCapacityStatus(t *testing.T, h *mcptest.Harness) capacityStatus {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "status"})
	var st capacityStatus
	if err := json.Unmarshal([]byte(res.Text), &st); err != nil {
		t.Fatalf("decode query(status): %v (text=%q)", err, res.Text)
	}
	return st
}

// holdOnlySlot dials addr without sending anything so the connection sits
// in protocol detection (PeekTimeout, 30s default) and occupies the only
// max_connections slot. Waits until the listener reports it as active via
// activeFn.
func holdOnlySlot(t *testing.T, addr string, activeFn func() bool) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial holder %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for !activeFn() {
		if time.Now().After(deadline) {
			t.Fatalf("holder connection to %s never became active", addr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return conn
}

// pollBlockedCapacityFlows polls query(flows) with blocked_by=capacity and
// the given host filter until at least one entry is returned.
func pollBlockedCapacityFlows(t *testing.T, h *mcptest.Harness, host string) []map[string]any {
	t.Helper()
	filter := map[string]any{"blocked_by": "capacity"}
	if host != "" {
		filter["host"] = host
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": filter})
		raw, _ := res.Decoded["flows"].([]any)
		if len(raw) > 0 {
			out := make([]map[string]any, 0, len(raw))
			for _, r := range raw {
				if m, ok := r.(map[string]any); ok {
					out = append(out, m)
				}
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(flows, blocked_by=capacity, host=%q) returned no flows: %s", host, res.Text)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func flowServerAddr(t *testing.T, h *mcptest.Harness, id string) string {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	ci, _ := res.Decoded["conn_info"].(map[string]any)
	addr, _ := ci["server_addr"].(string)
	return addr
}

func TestE2E_CapacityRejection_CONNECTVisibleInStatusAndFlows(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "http/1.1"})
	upstream, err := url.Parse(h.UpstreamTLS.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	authority := upstream.Host // host:port, used verbatim as the CONNECT target
	upstreamHost := upstream.Hostname()

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"max_connections": 1,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	holdOnlySlot(t, proxyAddr, func() bool {
		return queryCapacityStatus(t, h).ActiveConnections == 1
	})

	over, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial over-cap: %v", err)
	}
	defer over.Close()
	req := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
	if _, err := over.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := bufio.NewReader(over).ReadString('\n')
	if err != nil {
		t.Fatalf("read 503 status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 503") {
		t.Fatalf("status line = %q, want HTTP/1.1 503", statusLine)
	}

	// Status aggregate.
	var st capacityStatus
	deadline := time.Now().Add(5 * time.Second)
	for {
		st = queryCapacityStatus(t, h)
		if st.ConnectionRejections != nil && st.ConnectionRejections.Total >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(status).connection_rejections missing or zero after an over-cap CONNECT")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cr := st.ConnectionRejections
	if cr.ByKind.Connect < 1 {
		t.Errorf("by_kind.connect = %d, want >= 1", cr.ByKind.Connect)
	}
	if cr.LastAt == "" {
		t.Errorf("last_at is empty")
	}
	found := false
	for _, e := range cr.Recent {
		if e.DetectedKind == "connect" && e.Target == authority {
			found = true
			if !e.Wrote503 {
				t.Errorf("recent entry wrote_503 = false, want true")
			}
			if e.Method != "CONNECT" {
				t.Errorf("recent entry method = %q, want CONNECT", e.Method)
			}
			if e.MaxConnections != 1 {
				t.Errorf("recent entry max_connections = %d, want 1", e.MaxConnections)
			}
			if e.RemoteAddr != over.LocalAddr().String() {
				t.Errorf("recent entry remote_addr = %q, want %q", e.RemoteAddr, over.LocalAddr().String())
			}
			if !e.Recorded {
				t.Errorf("recent entry recorded = false, want true")
			}
		}
	}
	if !found {
		t.Fatalf("no recent entry with detected_kind=connect target=%q: %+v", authority, cr.Recent)
	}

	// Flow store: the agent searching flows for the target host sees the
	// refusal.
	flows := pollBlockedCapacityFlows(t, h, upstreamHost)
	got := flows[0]
	if s, _ := got["state"].(string); s != "error" {
		t.Errorf("flow state = %q, want error", s)
	}
	if b, _ := got["blocked_by"].(string); b != "capacity" {
		t.Errorf("flow blocked_by = %q, want capacity", b)
	}
	if p, _ := got["protocol"].(string); p != "http" {
		t.Errorf("flow protocol = %q, want http", p)
	}
	if fr, _ := got["failure_reason"].(string); !strings.Contains(fr, "max_connections=1") {
		t.Errorf("flow failure_reason = %q, want it to name max_connections=1", fr)
	}
	tags, _ := got["tags"].(map[string]any)
	if tg, _ := tags["target"].(string); tg != authority {
		t.Errorf("flow tags.target = %q, want %q", tg, authority)
	}
	if dk, _ := tags["detected_kind"].(string); dk != "connect" {
		t.Errorf("flow tags.detected_kind = %q, want connect", dk)
	}
	// No upstream socket ever existed, so server_addr is empty; the
	// refused target is tags.target and filter.host matched on it above.
	id, _ := got["id"].(string)
	if addr := flowServerAddr(t, h, id); addr != "" {
		t.Errorf("flow conn_info.server_addr = %q, want \"\" (no socket peer)", addr)
	}
}

func TestE2E_CapacityRejection_TCPForwardVisibleInStatusAndFlows(t *testing.T) {
	echoAddr := startTCPEchoServer(t)
	forwardPort := pickFreePort(t)
	portStr := strconv.Itoa(forwardPort)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"max_connections": 1,
		"tcp_forwards": map[string]any{
			portStr: echoAddr,
		},
	})
	forwardAddr := net.JoinHostPort("127.0.0.1", portStr)

	// The forward's raw handler dials the echo target and bridges; a
	// connection that sends nothing keeps the bridge (and the slot) open.
	holder, err := net.Dial("tcp", forwardAddr)
	if err != nil {
		t.Fatalf("dial forward holder: %v", err)
	}
	defer holder.Close()
	// The status view does not expose per-forward active counts, so give
	// the accept loop a moment to count the holder before the over-cap
	// dial. The assertion below retries the over-cap dial until the
	// rejection is observed, so a slow accept only costs a retry.
	var st capacityStatus
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", forwardAddr)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = c.Read(make([]byte, 1))
			_ = c.Close()
		}
		st = queryCapacityStatus(t, h)
		if st.ConnectionRejections != nil && st.ConnectionRejections.ByKind.TCP >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(status).connection_rejections.by_kind.tcp never reached 1 for the forward port")
		}
		time.Sleep(100 * time.Millisecond)
	}

	found := false
	for _, e := range st.ConnectionRejections.Recent {
		if e.DetectedKind == "tcp" && e.ForwardPort == portStr {
			found = true
			if e.Target != echoAddr {
				t.Errorf("forward entry target = %q, want configured %q", e.Target, echoAddr)
			}
			if e.Wrote503 {
				t.Errorf("forward entry wrote_503 = true, want false (raw TCP has no in-band rejection)")
			}
		}
	}
	if !found {
		t.Fatalf("no recent entry with detected_kind=tcp forward_port=%s: %+v", portStr, st.ConnectionRejections.Recent)
	}

	echoHost, _, _ := net.SplitHostPort(echoAddr)
	flows := pollBlockedCapacityFlows(t, h, echoHost)
	got := flows[0]
	if s, _ := got["state"].(string); s != "error" {
		t.Errorf("flow state = %q, want error", s)
	}
	if p, _ := got["protocol"].(string); p != "raw" {
		t.Errorf("flow protocol = %q, want raw", p)
	}
	tags, _ := got["tags"].(map[string]any)
	if fp, _ := tags["forward_port"].(string); fp != portStr {
		t.Errorf("flow tags.forward_port = %q, want %q", fp, portStr)
	}
	if tg, _ := tags["target"].(string); tg != echoAddr {
		t.Errorf("flow tags.target = %q, want %q", tg, echoAddr)
	}
	id, _ := got["id"].(string)
	if addr := flowServerAddr(t, h, id); addr != "" {
		t.Errorf("flow conn_info.server_addr = %q, want \"\" (no socket peer)", addr)
	}
}

// TestE2E_CapacityRejection_HTTP1AbsoluteFormFilterByHost: an over-cap
// plain-forward request with an absolute-form target is recorded with
// tags.target = the request-target as received (a full URL) and no
// server_addr; filter.host on the URL's host still finds it, while a
// host that merely prefixes the recorded one does not.
func TestE2E_CapacityRejection_HTTP1AbsoluteFormFilterByHost(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"max_connections": 1,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	holdOnlySlot(t, proxyAddr, func() bool {
		return queryCapacityStatus(t, h).ActiveConnections == 1
	})

	const target = "http://Ads.Example:8080/slot?id=1"
	over, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial over-cap: %v", err)
	}
	defer over.Close()
	req := "GET " + target + " HTTP/1.1\r\nHost: Ads.Example:8080\r\n\r\n"
	if _, err := over.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := bufio.NewReader(over).ReadString('\n')
	if err != nil {
		t.Fatalf("read 503 status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 503") {
		t.Fatalf("status line = %q, want HTTP/1.1 503", statusLine)
	}

	flows := pollBlockedCapacityFlows(t, h, "Ads.Example")
	got := flows[0]
	tags, _ := got["tags"].(map[string]any)
	if tg, _ := tags["target"].(string); tg != target {
		t.Errorf("flow tags.target = %q, want %q", tg, target)
	}
	if dk, _ := tags["detected_kind"].(string); dk != "http1" {
		t.Errorf("flow tags.detected_kind = %q, want http1", dk)
	}
	id, _ := got["id"].(string)
	if addr := flowServerAddr(t, h, id); addr != "" {
		t.Errorf("flow conn_info.server_addr = %q, want \"\" (no socket peer)", addr)
	}

	// Right-side anchoring: a host that merely prefixes the recorded one
	// must not match.
	res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": map[string]any{
		"blocked_by": "capacity",
		"host":       "Ads.Exam",
	}})
	if raw, _ := res.Decoded["flows"].([]any); len(raw) != 0 {
		t.Errorf("query(flows, host=Ads.Exam) returned %d flows, want 0: %s", len(raw), res.Text)
	}
}
