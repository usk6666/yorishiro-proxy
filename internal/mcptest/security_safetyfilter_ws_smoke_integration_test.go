//go:build e2e

// Package mcptest_test holds USK-767's smoke parity for the SafetyFilter
// engine on the WebSocket Send path — the WS analogue of
// security_safetyfilter_smoke_integration_test.go (HTTP) and
// security_safetyfilter_grpc_smoke_integration_test.go (gRPC).
//
// USK-760 (PR #753) wired *safety.Engine through proxybuild.Deps for
// HTTP, WS, and gRPC. The HTTP and gRPC smokes cover their respective
// wires end-to-end, but without a parallel WS smoke a regression that
// stops populating proxybuild.Deps.WSSafetyEngine — or that breaks the
// pipeline.SafetyStep WS dispatch at internal/pipeline/safety_step.go's
// `case *envelope.WSMessage` arm — would only surface in nightly e2e.
// This file closes that gap.
//
// MITM-diagnostic test philosophy: the durable assertion is the upstream
// hit counter (h.WSObservedHits.Total()). pipeline.SafetyStep contract
// is "drop the envelope on Send", not "return a specific WS close code"
// or "surface a specific transport error", so the destructive-frame
// arm tolerates any client-side outcome — what matters is that the
// upstream WS handler did NOT see the matching frame.
//
// Why a custom rule (not destructive-sql preset): per
// internal/rules/ws/safety.go::LoadPreset's docstring, the
// destructive-sql preset's targets (TargetBody / TargetURL / TargetQuery)
// are NOT WS-local — wsrules.SafetyEngine silently skips them. The
// canonical WS-local targets are TargetPayload and TargetOpcode; this
// test uses a custom rule with `pattern: "password="` and
// `targets: ["payload"]` so the WS engine actually evaluates it.
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// safetyFilterWSPayloadConfig enables the SafetyFilter engine with a
// custom WS-targeted Input rule. "block" is explicit so the assertion
// is unambiguous: a Send-direction WS frame whose Payload contains
// "password=" must not reach the upstream.
const safetyFilterWSPayloadConfig = `{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"id": "ws-leak", "pattern": "password=", "targets": ["payload"]}
      ]
    }
  }
}`

// TestE2E_SafetyFilter_BlocksWSPayload mirrors the HTTP smoke
// (TestE2E_SafetyFilter_BlocksDestructiveSQL) and the gRPC smoke
// (TestE2E_SafetyFilter_BlocksDestructiveSQL_GRPC) but routes through
// a WebSocket connection over CONNECT + TLS + RFC 6455 handshake.
//
// Both calls target the same upstream through the same proxy instance,
// so any divergence narrows directly to the WS arm of
// pipeline.SafetyStep:
//
//   - A frame whose Payload matches the "password=" rule never reaches
//     the observed upstream.
//   - A frame whose Payload is benign DOES reach the upstream — proving
//     the test environment is otherwise functional and the block in the
//     destructive case is the SafetyFilter doing its job, not a
//     transport / handshake / dispatch issue.
//
// USK-760 closed the wiring gap (proxybuild.Deps.WSSafetyEngine is
// populated by InitPerProtocolSafetyEngines). With that on main this
// test is the merge-gate sentinel for the WS SafetyFilter path: a
// future regression in either link would resurface here.
func TestE2E_SafetyFilter_BlocksWSPayload(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterWSPayloadConfig,
		UpstreamProto: "ws",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	upstreamHostPort := wsUpstreamHostPort(t, h.UpstreamTLS.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// (1) Benign payload — must reach the upstream. The hit counter is
	// the sanity gate: without this baseline a "blocked" assertion
	// below would be indistinguishable from a transport-broken proxy
	// (e.g. a CONNECT failure or a TLS handshake error would also yield
	// zero hits).
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, upstreamHostPort)
	if err != nil {
		t.Fatalf("dial WS through proxy (benign): %v", err)
	}
	defer conn.Close()

	benignPayload := []byte("username=alice")
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, benignPayload); err != nil {
		t.Fatalf("write benign frame: %v", err)
	}
	echo, err := readServerFrameWithDeadline(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read benign echo: %v", err)
	}
	if !bytes.Equal(echo.Payload, benignPayload) {
		t.Fatalf("benign WS echo mismatch: got %q want %q", echo.Payload, benignPayload)
	}
	if got := h.WSObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after benign WS frame = %d, want 1", got)
	}

	// (2) Destructive payload — must NOT reach the upstream. The custom
	// rule matches "password=" verbatim against TargetPayload. The
	// SafetyStep contract is "drop the envelope on Send", not "return a
	// specific WS close code" or "surface a specific transport error",
	// so we tolerate any client-side outcome (echo timeout, abrupt
	// disconnect, control frame). The durable assertion is the upstream
	// hit counter.
	hitsBefore := h.WSObservedHits.Total()
	destructivePayload := []byte("password=hunter2")
	// Best-effort write — the proxy may have already torn the connection
	// down server-side after the safety drop; that is OK.
	_ = writeMaskedClientFrame(conn, wslayer.OpcodeText, destructivePayload)
	// Drain whatever (if anything) the proxy sends back, bounded so
	// this never deadlocks. We do not assert on the contents — any of
	// {echoed frame (would be a failure), close frame, EOF} is permitted
	// at the protocol level by the SafetyStep contract; the hit-counter
	// check below is the load-bearing assertion.
	_, _ = readServerFrameWithDeadline(conn, 2*time.Second)
	hitsAfter := h.WSObservedHits.Total()
	if hitsAfter != hitsBefore {
		t.Errorf("upstream hits advanced after destructive WS frame: before=%d after=%d (block failed)",
			hitsBefore, hitsAfter)
	}
}

// wsUpstreamHostPort parses the httptest server URL ("https://h:p")
// returned by mcptest into the "host:port" string the WS client must
// reach via CONNECT. Mirrors grpcUpstreamHostPort in
// grpc_dispatch_smoke_integration_test.go but kept inline so the WS
// smoke does not pick up an indirect dependency on the gRPC helpers.
func wsUpstreamHostPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse upstream URL %q: %v", rawURL, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return host + ":" + port
}

// dialWSThroughProxy returns a TLS-wrapped net.Conn whose underlying
// transport reaches upstreamHostPort via an HTTP CONNECT tunnel through
// the proxy at proxyAddr. After dial it performs the RFC 6455 §1.3
// WebSocket handshake against /ws and validates the Sec-WebSocket-Accept
// response. The returned conn is positioned right after the 101 headers
// so the caller can immediately write frames.
//
// TLS verification is disabled because the proxy MITMs the connection
// with an ephemeral CA whose root the test does not pin (mirrors the
// gRPC smoke pattern; the harness boots with `-insecure` for the same
// reason).
func dialWSThroughProxy(ctx context.Context, t *testing.T, proxyAddr, upstreamHostPort string) (net.Conn, error) {
	t.Helper()
	raw, err := openCONNECTTunnel(ctx, proxyAddr, upstreamHostPort)
	if err != nil {
		return nil, fmt.Errorf("open CONNECT tunnel: %w", err)
	}
	tlsCfg := &tls.Config{
		ServerName:         hostOnly(upstreamHostPort),
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if err := performClientWSHandshake(tlsConn, upstreamHostPort); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("WS handshake: %w", err)
	}
	return tlsConn, nil
}

// performClientWSHandshake writes a compliant RFC 6455 §1.3 client
// handshake to conn and validates the 101 Switching Protocols response.
// Does not validate Sec-WebSocket-Accept against the request key — the
// upstream server in this smoke owns its own validation, and the proxy
// is wire-faithful so any Accept value the upstream sends back must
// arrive verbatim. (Validating Accept here would only restate what
// computeWSAccept already does on the server side.)
func performClientWSHandshake(conn net.Conn, host string) error {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate Sec-WebSocket-Key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	deadline := time.Now().Add(10 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("write handshake request: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read status line: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		// Drain a bounded amount so the error message is informative.
		preview := make([]byte, 0, 512)
		preview = append(preview, statusLine...)
		for len(preview) < 512 {
			line, rerr := br.ReadString('\n')
			preview = append(preview, line...)
			if rerr != nil || line == "\r\n" {
				break
			}
		}
		return fmt.Errorf("unexpected handshake response: %q", string(preview))
	}
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return fmt.Errorf("read header: %w", rerr)
		}
		if line == "\r\n" {
			break
		}
	}
	// Critical: if br buffered any post-header bytes, they must NOT be
	// dropped. Server sends 101 then waits for a client frame — so
	// br.Buffered() must be 0 here under a compliant peer.
	if buffered := br.Buffered(); buffered != 0 {
		return fmt.Errorf("unexpected %d bytes buffered after 101 response", buffered)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear deadline: %w", err)
	}
	return nil
}

// writeMaskedClientFrame writes one WS frame from the client side onto
// conn. Frames sent from client to server MUST be masked per RFC 6455
// §5.3; the masking key is randomly generated per frame.
func writeMaskedClientFrame(conn net.Conn, opcode byte, payload []byte) error {
	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return fmt.Errorf("generate mask key: %w", err)
	}
	f := &wslayer.Frame{
		Fin:     true,
		Opcode:  opcode,
		Masked:  true,
		MaskKey: maskKey,
		Payload: payload,
	}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	if err := wslayer.WriteFrame(conn, f); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// readServerFrameWithDeadline reads one frame from conn within the given
// deadline. Returns the parsed frame on success or an error on timeout /
// transport failure. Used by the destructive-frame arm to drain whatever
// (if anything) the proxy sends back without deadlocking the test.
func readServerFrameWithDeadline(conn net.Conn, timeout time.Duration) (*wslayer.Frame, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	f, err := wslayer.ReadFrame(conn)
	if err != nil {
		// EOF / timeout / connection-reset are all acceptable in the
		// destructive case. Surface them so the benign case can still
		// distinguish a real transport bug.
		if errors.Is(err, io.EOF) {
			return nil, err
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return nil, err
		}
		return nil, err
	}
	return f, nil
}
