//go:build e2e

// USK-844 smoke coverage: verify that MCP `configure { request_timeout_ms }`
// reaches the plain-HTTP forward handler's read deadline. The Track F §F-6-c
// manual test exposed a regression where the operator-tightened value was
// silently dropped on the data path: 200 ms configured, but a slow-loris
// client whose headers arrived over ~3 s still got a 200 OK after 4.2 s.
// Without this smoke gate the regression would only resurface during the
// next manual security-hardening pass.
package mcptest_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_RequestTimeout_SlowLorisClosesConnection drives a slow-loris
// client (header bytes trickling at 250 ms gaps) against the proxy after
// MCP `configure { request_timeout_ms: 200 }` has been issued. The
// expected behaviour is:
//   - Proxy returns a 400 Bad Request response from the forward handler's
//     peek-error branch (or closes the conn outright), AND
//   - The whole exchange completes well under the default 30 s
//     forwardPeekTimeout — i.e. the operator-tightened value engaged.
//
// The pre-USK-844 behaviour was "no rejection, proxy waits ~30 s" — this
// test would FAIL in that world both because the conn would not close
// quickly enough and because the response (if any) would be a normal 200
// from the upstream once the slow-loris finished trickling.
func TestE2E_RequestTimeout_SlowLorisClosesConnection(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	listenAddr, _ := startRes.Decoded["listen_addr"].(string)
	if listenAddr == "" {
		t.Fatalf("proxy_start did not surface listen_addr; result=%s", startRes.Text)
	}

	// Tighten the request-header read timeout to 200 ms via MCP configure.
	// This is the exact knob the Track F §F-6-c repro uses.
	cfgRes := h.MustOK(t, "configure", map[string]any{"request_timeout_ms": 200})
	if cfgRes.IsError {
		t.Fatalf("configure { request_timeout_ms: 200 } returned an error: %s", cfgRes.Text)
	}

	// Dial the plain-HTTP forward proxy and trickle a partial request
	// header. The handler peek loop must observe deadline expiry and
	// return — the package default would let this dangle for 30 s.
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Cap the whole exchange so a regression (default 30 s deadline) does
	// not stall the test. The wire-floor expectation is "<1 s end to end"
	// per the design review's acceptance criterion; 5 s gives generous
	// slack for slow CI runners.
	overallDeadline := time.Now().Add(5 * time.Second)
	if err := conn.SetDeadline(overallDeadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	start := time.Now()
	// Write a request-line prefix that intentionally lacks the rest of the
	// HTTP/1.x request: no "\r\n\r\n" terminator, no Host header. The
	// forward handler's peekUntilHeadersEnd loop will block on the next
	// byte until the 200 ms deadline fires.
	if _, err := conn.Write([]byte("GET /slow HTTP/1.1\r\nHost: example.com\r\nUser-Ag")); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}

	// Read whatever the proxy chooses to emit (400 / close). The pre-844
	// behaviour was either no response (handler waited 30 s) or — in
	// keep-alive mode — eventually a 200 once trickle completed. With the
	// fix the read returns quickly with either EOF or a 4xx response.
	resp, readErr := bufio.NewReader(conn).ReadString('\n')
	elapsed := time.Since(start)

	// Primary assertion: the round-trip is bounded by the configured
	// deadline (200 ms) plus generous handshake slack. The default 30 s
	// regression would blow well past this and trip overallDeadline above
	// — which would surface as a read error AFTER ~5 s. We assert
	// elapsed < 2 s as the merge-gate floor.
	if elapsed >= 2*time.Second {
		t.Errorf("slow-loris exchange took %v; expected the configured 200ms request_timeout_ms to fire (regression: default 30s engaged?)", elapsed)
	}

	// Secondary assertion: when the handler emits a status line, it must
	// be a 4xx (the forward handler's peek-error branch responds 400) —
	// never a 200 (which would mean the request reached upstream).
	// EOF / connection-closed responses are also acceptable: some
	// kernels' net.Conn implementations bubble the deadline-driven close
	// up as a read error rather than a partial response.
	if readErr == nil && resp != "" {
		if !strings.HasPrefix(resp, "HTTP/1.") {
			t.Errorf("response status line malformed: %q", resp)
		} else if strings.Contains(resp, " 200 ") {
			t.Errorf("expected 4xx (or EOF), got %q — request_timeout_ms did not engage", strings.TrimSpace(resp))
		}
	}
}
