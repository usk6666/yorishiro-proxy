//go:build e2e && !e2e_smoke

// USK-1322: web_socket.max_frame_size governs the receive side of the
// live WebSocket relay, not only Send. Driven through the production
// wiring (config JSON → mcpserver init → connector.BuildConfig →
// proxybuild.buildSessionOptions → session.runUpgradeWS → ws.New on both
// legs) over CONNECT + TLS + RFC 6455 Upgrade.
package mcptest_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// wsMaxFrameSizeConfig sets web_socket.max_frame_size to n bytes.
func wsMaxFrameSizeConfig(n int64) string {
	return fmt.Sprintf(`{"web_socket": {"max_frame_size": %d}}`, n)
}

// startWSMaxFrameHarness boots a harness with the given proxy cap and
// upstream reader cap, starts the proxy, and opens a WS connection to
// the upstream through it.
func startWSMaxFrameHarness(t *testing.T, proxyCap, upstreamCap int64) (*mcptest.Harness, net.Conn) {
	t.Helper()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:             wsMaxFrameSizeConfig(proxyCap),
		UpstreamProto:          "ws",
		WSUpstreamMaxFrameSize: upstreamCap,
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, wsUpstreamHostPort(t, h.UpstreamTLS.URL))
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return h, conn
}

// writeBigMaskedFrame writes one masked client frame with a generous
// deadline (multi-MiB payloads under -race).
func writeBigMaskedFrame(conn net.Conn, opcode byte, payload []byte) error {
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	return wslayer.WriteFrame(conn, &wslayer.Frame{Fin: true, Opcode: opcode, Masked: true, MaskKey: key, Payload: payload})
}

// readBigFrame reads one frame with the given payload cap and deadline.
func readBigFrame(conn net.Conn, maxPayload int64, timeout time.Duration) (*wslayer.Frame, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	f, _, err := wslayer.ReadFrameRawLimit(conn, maxPayload)
	return f, err
}

// upgradeStreams returns the recorded Streams of the /ws Upgrade in
// state, or in any state when state is "" (whatever protocol they are
// tagged with: a Stream whose first WS frame fails before recording keeps
// its pre-swap http tag). The state
// filter keeps polling cheap: the flows listing loads every matched
// Stream's messages, which here carry tens of MiB.
func upgradeStreams(t *testing.T, h *mcptest.Harness, state string) []map[string]any {
	t.Helper()
	filter := map[string]any{"url_pattern": "/ws"}
	if state != "" {
		filter["state"] = state
	}
	res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": filter})
	raw, _ := res.Decoded["flows"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// waitUpgradeStreamState polls until a /ws Upgrade Stream reaches want
// and returns it; exactly one such Stream must exist.
func waitUpgradeStreamState(t *testing.T, h *mcptest.Harness, want string, d time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		got := upgradeStreams(t, h, want)
		if len(got) == 1 {
			return got[0]
		}
		if len(got) > 1 {
			t.Fatalf("%d /ws Streams in state %q, want 1: %v", len(got), want, got)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no /ws Stream reached state %q within %v", want, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// wsDataMessageSizes returns direction → body sizes of the recorded WS
// binary data frames of streamID (bodies are suppressed in the response;
// their size is reported in body_original_size).
func wsDataMessageSizes(t *testing.T, h *mcptest.Harness, streamID string) map[string][]int {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource":       "messages",
		"id":             streamID,
		"include_bodies": false,
	})
	msgs, _ := res.Decoded["messages"].([]any)
	out := map[string][]int{}
	for _, m := range msgs {
		e, _ := m.(map[string]any)
		md, _ := e["metadata"].(map[string]any)
		if op, _ := md["ws_opcode"].(string); op != strconv.Itoa(int(wslayer.OpcodeBinary)) {
			continue
		}
		dir, _ := e["direction"].(string)
		size, _ := e["body_original_size"].(float64)
		out[dir] = append(out[dir], int(size))
	}
	return out
}

// TestE2E_WSMaxFrameSize_RaisedCapRelaysLargeFrameBothWays: with
// web_socket.max_frame_size = 32 MiB, a 24 MiB frame reaches the upstream
// byte-identical, the upstream's 24 MiB echo reaches the client
// byte-identical, and both frames are recorded with their full bodies.
func TestE2E_WSMaxFrameSize_RaisedCapRelaysLargeFrameBothWays(t *testing.T) {
	const capN = 32 << 20
	const n = 24 << 20
	h, conn := startWSMaxFrameHarness(t, capN, capN)

	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*31 + i>>12)
	}
	if err := writeBigMaskedFrame(conn, wslayer.OpcodeBinary, payload); err != nil {
		t.Fatalf("write 24 MiB frame: %v", err)
	}
	echo, err := readBigFrame(conn, capN, 2*time.Minute)
	if err != nil {
		t.Fatalf("read 24 MiB echo: %v (upstream hits=%d)", err, h.WSObservedHits.Total())
	}
	if !bytes.Equal(echo.Payload, payload) {
		t.Fatalf("echo payload (len %d) differs from the sent %d-byte payload", len(echo.Payload), n)
	}
	if got := h.WSObservedHits.Total(); got != 1 {
		t.Errorf("upstream data-frame hits = %d, want 1", got)
	}

	// Close the WS conversation so the Stream completes.
	if err := writeBigMaskedFrame(conn, wslayer.OpcodeClose, []byte{0x03, 0xe8}); err != nil {
		t.Fatalf("write close: %v", err)
	}
	_, _ = readBigFrame(conn, capN, 30*time.Second)
	_ = conn.Close()

	st := waitUpgradeStreamState(t, h, "complete", 30*time.Second)
	if proto, _ := st["protocol"].(string); proto != "ws" {
		t.Errorf("Stream protocol = %q, want ws", proto)
	}
	streamID, _ := st["id"].(string)
	sizes := wsDataMessageSizes(t, h, streamID)
	if got := sizes["send"]; len(got) != 1 || got[0] != n {
		t.Errorf("recorded send data frames body sizes = %v, want [%d]", got, n)
	}
	if got := sizes["receive"]; len(got) != 1 || got[0] != n {
		t.Errorf("recorded receive data frames body sizes = %v, want [%d]", got, n)
	}
}

// TestE2E_WSMaxFrameSize_LoweredCapFailsOnReceive: with
// web_socket.max_frame_size = 1 MiB, a 2 MiB client frame is rejected
// when the proxy reads it — it never reaches the upstream, the client
// connection is closed, the Stream ends in "error", and no 2 MiB body is
// recorded.
func TestE2E_WSMaxFrameSize_LoweredCapFailsOnReceive(t *testing.T) {
	const capN = 1 << 20
	const n = 2 << 20
	h, conn := startWSMaxFrameHarness(t, capN, 0)

	// The proxy may stop reading after the header, so the write can fail.
	_ = writeBigMaskedFrame(conn, wslayer.OpcodeBinary, make([]byte, n))
	if f, err := readBigFrame(conn, 0, 10*time.Second); err == nil {
		t.Errorf("client received a frame (opcode %d, %d bytes) after the over-cap frame; want the connection closed", f.Opcode, len(f.Payload))
	} else {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			t.Errorf("client connection still open 10s after the over-cap frame; want it closed")
		}
	}
	if got := h.WSObservedHits.Total(); got != 0 {
		t.Errorf("upstream data-frame hits = %d, want 0 (the over-cap frame was forwarded)", got)
	}

	waitUpgradeStreamState(t, h, "error", 15*time.Second)
	// No large body is recorded here, so an unfiltered listing is cheap:
	// exactly one /ws Stream may exist in total, and the size scan covers
	// every one of them rather than only the "error" Stream.
	all := upgradeStreams(t, h, "")
	if len(all) != 1 {
		t.Errorf("%d /ws Streams recorded in total, want 1: %v", len(all), all)
	}
	for _, st := range all {
		streamID, _ := st["id"].(string)
		for dir, got := range wsDataMessageSizes(t, h, streamID) {
			for _, size := range got {
				if size == n {
					t.Errorf("Stream %s: a %s data frame with the %d-byte over-cap body was recorded", streamID, dir, n)
				}
			}
		}
	}
}
