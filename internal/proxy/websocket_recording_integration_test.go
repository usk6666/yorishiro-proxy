//go:build e2e

package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// wsTestEnv bundles the proxy test environment for WebSocket tests.
type wsTestEnv struct {
	store    *flow.SQLiteStore
	listener *proxy.Listener
	cancel   context.CancelFunc
}

// setupWSProxy creates a proxy with flow recording for WebSocket tests.
// The caller must call env.cancel() and env.store.Close() when done.
func setupWSProxy(t *testing.T, ctx context.Context) *wsTestEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		store.Close()
		t.Fatal("proxy did not become ready")
	}
	return &wsTestEnv{store: store, listener: listener, cancel: proxyCancel}
}

// wsEchoServer creates a WebSocket echo upstream that echoes back frames.
// It handles text and binary frames, responds to ping with pong, and
// processes close frames.
func wsEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(gohttp.StatusBadRequest)
			return
		}
		hj, ok := w.(gohttp.Hijacker)
		if !ok {
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: dummy\r\n\r\n"
		conn.Write([]byte(resp))

		for {
			opcode, payload, err := readWSFrame(buf.Reader)
			if err != nil {
				return
			}
			switch opcode {
			case 0x8: // Close
				writeWSFrame(conn, true, 0x8, payload, false)
				return
			case 0x9: // Ping — respond with Pong
				writeWSFrame(conn, true, 0xA, payload, false)
			default:
				// Echo back text and binary frames.
				if err := writeWSFrame(conn, true, opcode, payload, false); err != nil {
					return
				}
			}
		}
	}))
}

// wsUpgradeAndConnect dials the proxy, sends a WebSocket upgrade to the given upstream host,
// reads the 101 response, and returns the connection and a bufio.Reader for frame reading.
func wsUpgradeAndConnect(t *testing.T, proxyAddr, upstreamHost string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	upgradeReq := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		upstreamHost, upstreamHost)
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		conn.Close()
		t.Fatalf("write upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != gohttp.StatusSwitchingProtocols {
		conn.Close()
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}
	return conn, reader
}

// closeWSConn sends a close frame and drains the echo close response.
func closeWSConn(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	writeWSFrame(conn, true, 0x8, []byte{0x03, 0xE8}, true) // 1000 Normal Closure
	// Best-effort read close response; ignore errors.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	readWSFrame(reader)
	conn.Close()
}

// pollWSFlows polls for WebSocket flows and returns them.
func pollWSFlows(t *testing.T, ctx context.Context, store flow.Store, wantCount int) []*flow.Flow {
	t.Helper()
	return pollFlows(t, ctx, store, flow.ListOptions{
		Protocol: "WebSocket",
		Limit:    50,
	}, wantCount)
}

// pollFlowState polls until the flow reaches the expected state.
func pollFlowState(t *testing.T, ctx context.Context, store flow.Store, flowID, wantState string) *flow.Flow {
	t.Helper()
	var fl *flow.Flow
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		fl, err = store.GetFlow(ctx, flowID)
		if err != nil {
			t.Fatalf("GetFlow(%s): %v", flowID, err)
		}
		if fl.State == wantState {
			return fl
		}
	}
	t.Fatalf("flow %s state = %q, want %q after polling", flowID, fl.State, wantState)
	return nil
}

// pollMessages polls until the expected number of messages appear for a flow.
func pollMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string, wantCount int) []*flow.Message {
	t.Helper()
	var msgs []*flow.Message
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		msgs, err = store.GetMessages(ctx, flowID, flow.MessageListOptions{})
		if err != nil {
			t.Fatalf("GetMessages(%s): %v", flowID, err)
		}
		if len(msgs) >= wantCount {
			return msgs
		}
	}
	t.Fatalf("flow %s: expected >= %d messages, got %d after polling", flowID, wantCount, len(msgs))
	return nil
}

func TestIntegration_WebSocket_TextFrameRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send a text frame (opcode 0x1).
	msg := []byte("pentest-payload: <script>alert(1)</script>")
	if err := writeWSFrame(conn, true, 0x1, msg, true); err != nil {
		t.Fatalf("write text frame: %v", err)
	}

	// Read echo.
	opcode, payload, err := readWSFrame(reader)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if opcode != 0x1 || string(payload) != string(msg) {
		t.Fatalf("echo mismatch: opcode=%d payload=%q", opcode, payload)
	}

	closeWSConn(t, conn, reader)

	// Wait for flows.
	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]

	// Verify flow attributes.
	if fl.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "WebSocket")
	}
	if fl.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "bidirectional")
	}
	if fl.Scheme != "ws" {
		t.Errorf("scheme = %q, want %q", fl.Scheme, "ws")
	}

	// Wait for state to become complete.
	fl = pollFlowState(t, ctx, env.store, fl.ID, "complete")

	// Verify messages: upgrade req (seq 0), upgrade resp (seq 1), data frames.
	// Expect at least 4 messages: upgrade req, upgrade resp, sent text, received text echo.
	// Close frames may also be recorded.
	msgs := pollMessages(t, ctx, env.store, fl.ID, 4)

	// Check upgrade request (sequence 0).
	var upgradeReqMsg *flow.Message
	var upgradeRespMsg *flow.Message
	var sendDataMsgs []*flow.Message
	var recvDataMsgs []*flow.Message
	for _, m := range msgs {
		if m.Sequence == 0 && m.Direction == "send" {
			upgradeReqMsg = m
		} else if m.Sequence == 1 && m.Direction == "receive" {
			upgradeRespMsg = m
		} else if m.Direction == "send" && m.Metadata != nil && m.Metadata["opcode"] == "1" {
			sendDataMsgs = append(sendDataMsgs, m)
		} else if m.Direction == "receive" && m.Metadata != nil && m.Metadata["opcode"] == "1" {
			recvDataMsgs = append(recvDataMsgs, m)
		}
	}

	if upgradeReqMsg == nil {
		t.Fatal("upgrade request message (seq 0) not found")
	}
	if upgradeReqMsg.Method != "GET" {
		t.Errorf("upgrade request method = %q, want %q", upgradeReqMsg.Method, "GET")
	}

	if upgradeRespMsg == nil {
		t.Fatal("upgrade response message (seq 1) not found")
	}
	if upgradeRespMsg.StatusCode != 101 {
		t.Errorf("upgrade response status = %d, want 101", upgradeRespMsg.StatusCode)
	}

	// Verify text frame content: for text frames, body is stored in Body (not RawBytes).
	if len(sendDataMsgs) == 0 {
		t.Fatal("no send text data messages recorded")
	}
	if string(sendDataMsgs[0].Body) != string(msg) {
		t.Errorf("send text body = %q, want %q", sendDataMsgs[0].Body, msg)
	}

	if len(recvDataMsgs) == 0 {
		t.Fatal("no receive text data messages recorded")
	}
	if string(recvDataMsgs[0].Body) != string(msg) {
		t.Errorf("recv text body = %q, want %q", recvDataMsgs[0].Body, msg)
	}

	// Verify send/receive direction metadata.
	if sendDataMsgs[0].Metadata["opcode"] != "1" {
		t.Errorf("send metadata opcode = %q, want %q", sendDataMsgs[0].Metadata["opcode"], "1")
	}
	if sendDataMsgs[0].Metadata["fin"] != "true" {
		t.Errorf("send metadata fin = %q, want %q", sendDataMsgs[0].Metadata["fin"], "true")
	}
}

func TestIntegration_WebSocket_BinaryFrameRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send a binary frame (opcode 0x2) with arbitrary bytes including null bytes.
	binaryPayload := make([]byte, 256)
	for i := range binaryPayload {
		binaryPayload[i] = byte(i)
	}
	if err := writeWSFrame(conn, true, 0x2, binaryPayload, true); err != nil {
		t.Fatalf("write binary frame: %v", err)
	}

	// Read echo.
	opcode, payload, err := readWSFrame(reader)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if opcode != 0x2 {
		t.Fatalf("echo opcode = %d, want 2 (binary)", opcode)
	}
	if !bytes.Equal(payload, binaryPayload) {
		t.Fatal("echo binary payload mismatch")
	}

	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	msgs := pollMessages(t, ctx, env.store, fl.ID, 4)

	// Find binary data messages.
	var sendBinary, recvBinary *flow.Message
	for _, m := range msgs {
		if m.Metadata != nil && m.Metadata["opcode"] == "2" {
			if m.Direction == "send" {
				sendBinary = m
			} else if m.Direction == "receive" {
				recvBinary = m
			}
		}
	}

	// For binary frames, the handler stores payload in RawBytes (not Body).
	if sendBinary == nil {
		t.Fatal("no send binary message recorded")
	}
	if !bytes.Equal(sendBinary.RawBytes, binaryPayload) {
		t.Errorf("send binary RawBytes length = %d, want %d", len(sendBinary.RawBytes), len(binaryPayload))
	}

	if recvBinary == nil {
		t.Fatal("no receive binary message recorded")
	}
	if !bytes.Equal(recvBinary.RawBytes, binaryPayload) {
		t.Errorf("recv binary RawBytes length = %d, want %d", len(recvBinary.RawBytes), len(binaryPayload))
	}
}

func TestIntegration_WebSocket_MultipleMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send 15 messages and verify all echoes.
	const messageCount = 15
	for i := 0; i < messageCount; i++ {
		msg := []byte(fmt.Sprintf("message-%d", i))
		if err := writeWSFrame(conn, true, 0x1, msg, true); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
		opcode, payload, err := readWSFrame(reader)
		if err != nil {
			t.Fatalf("read echo %d: %v", i, err)
		}
		if opcode != 0x1 || string(payload) != string(msg) {
			t.Fatalf("echo %d mismatch: opcode=%d payload=%q", i, opcode, payload)
		}
	}

	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	// Expect: upgrade req (1) + upgrade resp (1) + send data (15) + recv data (15) + close frames.
	// Minimum: 2 + 30 = 32 messages.
	msgs := pollMessages(t, ctx, env.store, fl.ID, 32)

	// Count send and receive data messages.
	var sendCount, recvCount int
	for _, m := range msgs {
		if m.Metadata != nil && m.Metadata["opcode"] == "1" {
			if m.Direction == "send" {
				sendCount++
			} else if m.Direction == "receive" {
				recvCount++
			}
		}
	}
	if sendCount != messageCount {
		t.Errorf("send text message count = %d, want %d", sendCount, messageCount)
	}
	if recvCount != messageCount {
		t.Errorf("recv text message count = %d, want %d", recvCount, messageCount)
	}

	// Verify message ordering: sequence numbers should be strictly increasing.
	for i := 1; i < len(msgs); i++ {
		if msgs[i].Sequence <= msgs[i-1].Sequence {
			t.Errorf("message sequence not increasing: msgs[%d].Sequence=%d <= msgs[%d].Sequence=%d",
				i, msgs[i].Sequence, i-1, msgs[i-1].Sequence)
		}
	}
}

func TestIntegration_WebSocket_LargeFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send a 128KB binary payload (tests 16-bit and potentially 64-bit length encoding).
	largePayload := make([]byte, 128*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 251) // prime modulus to avoid simple patterns
	}
	if err := writeWSFrame(conn, true, 0x2, largePayload, true); err != nil {
		t.Fatalf("write large frame: %v", err)
	}

	opcode, payload, err := readWSFrame(reader)
	if err != nil {
		t.Fatalf("read large echo: %v", err)
	}
	if opcode != 0x2 {
		t.Fatalf("echo opcode = %d, want 2", opcode)
	}
	if !bytes.Equal(payload, largePayload) {
		t.Fatal("large frame echo payload mismatch")
	}

	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	msgs := pollMessages(t, ctx, env.store, fl.ID, 4)

	// Find the binary send message and verify raw bytes are recorded.
	var sendBinary *flow.Message
	for _, m := range msgs {
		if m.Metadata != nil && m.Metadata["opcode"] == "2" && m.Direction == "send" {
			sendBinary = m
			break
		}
	}
	if sendBinary == nil {
		t.Fatal("no send binary message for large frame")
	}
	// Payload may be truncated by MaxWebSocketRecordPayloadSize, but should be non-empty.
	if len(sendBinary.RawBytes) == 0 {
		t.Error("large frame RawBytes is empty")
	}
	// If not truncated, verify exact content.
	if !sendBinary.BodyTruncated && !bytes.Equal(sendBinary.RawBytes, largePayload) {
		t.Errorf("large frame RawBytes length = %d, want %d", len(sendBinary.RawBytes), len(largePayload))
	}
	if sendBinary.BodyTruncated {
		// Verify that the truncated prefix matches.
		if !bytes.HasPrefix(largePayload, sendBinary.RawBytes) {
			t.Error("truncated RawBytes does not match payload prefix")
		}
	}
}

func TestIntegration_WebSocket_PingPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send a Ping frame (opcode 0x9) with payload.
	pingPayload := []byte("heartbeat")
	if err := writeWSFrame(conn, true, 0x9, pingPayload, true); err != nil {
		t.Fatalf("write ping: %v", err)
	}

	// Expect Pong frame (opcode 0xA) with same payload.
	opcode, payload, err := readWSFrame(reader)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if opcode != 0xA {
		t.Fatalf("expected pong opcode 0xA, got 0x%X", opcode)
	}
	if !bytes.Equal(payload, pingPayload) {
		t.Errorf("pong payload = %q, want %q", payload, pingPayload)
	}

	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	// Verify control frames are recorded. Find ping and pong messages.
	msgs := pollMessages(t, ctx, env.store, fl.ID, 4) // upgrade req/resp + ping + pong + close

	var pingMsg, pongMsg *flow.Message
	for _, m := range msgs {
		if m.Metadata == nil {
			continue
		}
		switch m.Metadata["opcode"] {
		case strconv.Itoa(0x9):
			pingMsg = m
		case strconv.Itoa(0xA):
			pongMsg = m
		}
	}

	if pingMsg == nil {
		t.Fatal("ping frame not recorded")
	}
	if pongMsg == nil {
		t.Fatal("pong frame not recorded")
	}
	// Control frame payloads are stored in RawBytes.
	if !bytes.Equal(pingMsg.RawBytes, pingPayload) {
		t.Errorf("ping RawBytes = %q, want %q", pingMsg.RawBytes, pingPayload)
	}
	if !bytes.Equal(pongMsg.RawBytes, pingPayload) {
		t.Errorf("pong RawBytes = %q, want %q", pongMsg.RawBytes, pingPayload)
	}
}

func TestIntegration_WebSocket_CloseCodeRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send close frame with code 1001 (Going Away) and reason.
	closePayload := make([]byte, 2+len("goodbye"))
	closePayload[0] = 0x03 // 1001 >> 8
	closePayload[1] = 0xE9 // 1001 & 0xFF
	copy(closePayload[2:], "goodbye")
	if err := writeWSFrame(conn, true, 0x8, closePayload, true); err != nil {
		t.Fatalf("write close: %v", err)
	}

	// Best-effort read close echo.
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	readWSFrame(reader)
	conn.Close()

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	msgs := pollMessages(t, ctx, env.store, fl.ID, 3)

	// Find close frame messages.
	var closeMsg *flow.Message
	for _, m := range msgs {
		if m.Metadata != nil && m.Metadata["opcode"] == strconv.Itoa(0x8) && m.Direction == "send" {
			closeMsg = m
			break
		}
	}

	if closeMsg == nil {
		t.Fatal("close frame not recorded in flow messages")
	}
	// Close frame payload contains the 2-byte code + reason string.
	if len(closeMsg.RawBytes) < 2 {
		t.Fatalf("close frame RawBytes too short: %d bytes", len(closeMsg.RawBytes))
	}
	code := int(closeMsg.RawBytes[0])<<8 | int(closeMsg.RawBytes[1])
	if code != 1001 {
		t.Errorf("close code = %d, want 1001", code)
	}
	if len(closeMsg.RawBytes) > 2 {
		reason := string(closeMsg.RawBytes[2:])
		if reason != "goodbye" {
			t.Errorf("close reason = %q, want %q", reason, "goodbye")
		}
	}
}

func TestIntegration_WebSocket_AbnormalDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create an upstream that accepts the upgrade but then closes abruptly.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(gohttp.StatusBadRequest)
			return
		}
		hj, ok := w.(gohttp.Hijacker)
		if !ok {
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: dummy\r\n\r\n"
		conn.Write([]byte(resp))

		// Close abruptly without sending a Close frame.
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)
	defer conn.Close()

	// Send a text message; it may succeed or fail depending on timing.
	writeWSFrame(conn, true, 0x1, []byte("hello"), true)

	// Try to read; should fail due to upstream closing.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	readWSFrame(reader) // may error

	// Wait for flows to be recorded.
	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]

	// Wait for the flow state to settle.
	var finalFlow *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		finalFlow, _ = env.store.GetFlow(ctx, fl.ID)
		if finalFlow != nil && (finalFlow.State == "error" || finalFlow.State == "complete") {
			break
		}
	}

	if finalFlow == nil {
		t.Fatal("flow not found after abnormal disconnect")
	}
	// An abnormal disconnect (no Close frame exchange) should result in "error" state.
	if finalFlow.State != "error" {
		t.Errorf("flow state after abnormal disconnect = %q, want %q", finalFlow.State, "error")
	}
}

func TestIntegration_WebSocket_ConcurrentConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	const numConns = 5
	var wg sync.WaitGroup
	errs := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

			// Each connection sends a unique message.
			uniqueMsg := []byte(fmt.Sprintf("conn-%d-unique-payload", idx))
			if err := writeWSFrame(conn, true, 0x1, uniqueMsg, true); err != nil {
				errs <- fmt.Errorf("conn %d write: %w", idx, err)
				conn.Close()
				return
			}

			opcode, payload, err := readWSFrame(reader)
			if err != nil {
				errs <- fmt.Errorf("conn %d read: %w", idx, err)
				conn.Close()
				return
			}
			if opcode != 0x1 || string(payload) != string(uniqueMsg) {
				errs <- fmt.Errorf("conn %d echo mismatch: got %q, want %q", idx, payload, uniqueMsg)
				conn.Close()
				return
			}

			closeWSConn(t, conn, reader)
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Wait for all WebSocket flows to be recorded.
	flows := pollWSFlows(t, ctx, env.store, numConns)

	// Verify each flow has its own unique messages — no cross-contamination.
	seenPayloads := make(map[string]string) // payload -> flow ID
	for _, fl := range flows {
		if fl.Protocol != "WebSocket" {
			continue
		}
		msgs, err := env.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
		if err != nil {
			t.Fatalf("GetMessages(%s): %v", fl.ID, err)
		}
		for _, m := range msgs {
			if m.Metadata != nil && m.Metadata["opcode"] == "1" && m.Direction == "send" {
				payloadStr := string(m.Body)
				if prevFlowID, exists := seenPayloads[payloadStr]; exists {
					t.Errorf("cross-contamination: payload %q found in flows %s and %s",
						payloadStr, prevFlowID, fl.ID)
				}
				seenPayloads[payloadStr] = fl.ID
			}
		}
	}

	if len(seenPayloads) != numConns {
		t.Errorf("unique payloads = %d, want %d", len(seenPayloads), numConns)
	}
}

func TestIntegration_WebSocket_FlowAttributes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send one message to ensure flow is properly created.
	writeWSFrame(conn, true, 0x1, []byte("attr-test"), true)
	readWSFrame(reader)
	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	fl = pollFlowState(t, ctx, env.store, fl.ID, "complete")

	// Verify all expected flow attributes.
	if fl.Protocol != "WebSocket" {
		t.Errorf("Protocol = %q, want %q", fl.Protocol, "WebSocket")
	}
	if fl.FlowType != "bidirectional" {
		t.Errorf("FlowType = %q, want %q", fl.FlowType, "bidirectional")
	}
	if fl.Scheme != "ws" {
		t.Errorf("Scheme = %q, want %q", fl.Scheme, "ws")
	}
	if fl.State != "complete" {
		t.Errorf("State = %q, want %q", fl.State, "complete")
	}
	if fl.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", fl.Duration)
	}
	if fl.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}

	// Verify flow is findable by protocol filter.
	wsFlows, err := env.store.ListFlows(ctx, flow.ListOptions{Protocol: "WebSocket", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows with protocol filter: %v", err)
	}
	found := false
	for _, f := range wsFlows {
		if f.ID == fl.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("flow not found with Protocol=WebSocket filter")
	}
}

func TestIntegration_WebSocket_SendReceiveDirection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send text, read echo.
	testMsg := []byte("direction-test")
	writeWSFrame(conn, true, 0x1, testMsg, true)
	readWSFrame(reader)
	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	// Filter messages by direction.
	sendMsgs, err := env.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetMessages(send): %v", err)
	}
	recvMsgs, err := env.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages(receive): %v", err)
	}

	// Both directions should have messages.
	if len(sendMsgs) == 0 {
		t.Error("no send messages")
	}
	if len(recvMsgs) == 0 {
		t.Error("no receive messages")
	}

	// Verify all send messages have direction "send".
	for _, m := range sendMsgs {
		if m.Direction != "send" {
			t.Errorf("send message has direction = %q", m.Direction)
		}
	}
	for _, m := range recvMsgs {
		if m.Direction != "receive" {
			t.Errorf("receive message has direction = %q", m.Direction)
		}
	}

	// Find the data text messages specifically.
	var sendText, recvText *flow.Message
	for _, m := range sendMsgs {
		if m.Metadata != nil && m.Metadata["opcode"] == "1" {
			sendText = m
			break
		}
	}
	for _, m := range recvMsgs {
		if m.Metadata != nil && m.Metadata["opcode"] == "1" {
			recvText = m
			break
		}
	}

	if sendText == nil {
		t.Fatal("no send text message found")
	}
	if recvText == nil {
		t.Fatal("no receive text message found")
	}

	// Both should contain the same payload (echo).
	if string(sendText.Body) != string(testMsg) {
		t.Errorf("send text body = %q, want %q", sendText.Body, testMsg)
	}
	if string(recvText.Body) != string(testMsg) {
		t.Errorf("recv text body = %q, want %q", recvText.Body, testMsg)
	}

	// Verify masked metadata: client->server should be masked, server->client unmasked.
	if sendText.Metadata["masked"] != "true" {
		t.Errorf("send text masked = %q, want %q", sendText.Metadata["masked"], "true")
	}
	if recvText.Metadata["masked"] != "false" {
		t.Errorf("recv text masked = %q, want %q", recvText.Metadata["masked"], "false")
	}
}

func TestIntegration_WebSocket_RawBytesRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := wsEchoServer(t)
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	env := setupWSProxy(t, ctx)
	defer env.cancel()
	defer env.store.Close()

	conn, reader := wsUpgradeAndConnect(t, env.listener.Addr(), upstreamURL.Host)

	// Send a binary frame to verify raw bytes are captured.
	rawData := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F, 0xAA, 0x55}
	if err := writeWSFrame(conn, true, 0x2, rawData, true); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	readWSFrame(reader)
	closeWSConn(t, conn, reader)

	flows := pollWSFlows(t, ctx, env.store, 1)
	fl := flows[0]
	pollFlowState(t, ctx, env.store, fl.ID, "complete")

	msgs := pollMessages(t, ctx, env.store, fl.ID, 4)

	// Find the binary send and receive messages.
	for _, m := range msgs {
		if m.Metadata == nil || m.Metadata["opcode"] != "2" {
			continue
		}
		if len(m.RawBytes) == 0 {
			t.Errorf("binary frame (direction=%s) has empty RawBytes", m.Direction)
			continue
		}
		if !bytes.Equal(m.RawBytes, rawData) {
			t.Errorf("binary frame (direction=%s) RawBytes = %x, want %x", m.Direction, m.RawBytes, rawData)
		}
	}
}
