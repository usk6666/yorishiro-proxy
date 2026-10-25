//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newForwardTestManagerWSCap is newForwardTestManager with
// BuildConfig.WSMaxFrameSize set (the value mcpserver resolves from
// web_socket.max_frame_size).
func newForwardTestManagerWSCap(t *testing.T, store flow.Writer, wsMaxFrameSize int64) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
		WSMaxFrameSize:     wsMaxFrameSize,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{Logger: logger, StackFactory: factory})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// startWSBinaryEchoUpstream is a plain-TCP WS upstream that reads frames
// with ws.ReadFrameRawLimit(maxFrame) and echoes binary frames unmasked.
func startWSBinaryEchoUpstream(t *testing.T, maxFrame int64, hits *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				var key string
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if line == "\r\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						key = strings.TrimSpace(line[len("sec-websocket-key:"):])
					}
				}
				if key == "" {
					return
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + computeWSAcceptForUSK913(key) + "\r\n\r\n"
				if _, werr := c.Write([]byte(resp)); werr != nil {
					return
				}
				for {
					_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
					f, _, rerr := ws.ReadFrameRawLimit(br, maxFrame)
					if rerr != nil {
						return
					}
					if f.Opcode == ws.OpcodeClose {
						_ = ws.WriteFrame(c, &ws.Frame{Fin: true, Opcode: ws.OpcodeClose, Payload: f.Payload})
						return
					}
					if f.Opcode != ws.OpcodeBinary {
						continue
					}
					hits.Add(1)
					_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
					if werr := ws.WriteFrame(c, &ws.Frame{Fin: true, Opcode: ws.OpcodeBinary, Payload: f.Payload}); werr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestProxybuild_TCPForward_WS_MaxFrameSizeRaised: a tcp_forwards
// Protocol="websocket" listener honors BuildConfig.WSMaxFrameSize (32 MiB)
// on both legs: a 24 MiB frame reaches the upstream and its 24 MiB echo
// reaches the client, byte-identical; both are recorded with full bodies
// and full raw frames, and the Stream completes.
func TestProxybuild_TCPForward_WS_MaxFrameSizeRaised(t *testing.T) {
	const capN = 32 << 20
	const n = 24 << 20
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var hits atomic.Int64
	upstreamAddr := startWSBinaryEchoUpstream(t, capN, &hits)
	store := &flowStoreCapture{}
	mgr := newForwardTestManagerWSCap(t, store, capN)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: upstreamAddr, Protocol: "websocket"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	if err := writeWSClientHandshakeForUSK913(conn, "example.test"); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	if err := readWS101ForUSK913(br); err != nil {
		t.Fatalf("read 101: %v", err)
	}

	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*13 + i>>10)
	}
	sent := &ws.Frame{Fin: true, Opcode: ws.OpcodeBinary, Masked: true, MaskKey: [4]byte{9, 8, 7, 6}, Payload: payload}
	var sentWire bytes.Buffer
	if err := ws.WriteFrame(&sentWire, sent); err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write(sentWire.Bytes()); err != nil {
		t.Fatalf("write 24 MiB frame: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	echo, echoRaw, err := ws.ReadFrameRawLimit(br, capN)
	if err != nil {
		t.Fatalf("read 24 MiB echo: %v (upstream hits=%d)", err, hits.Load())
	}
	_ = conn.SetReadDeadline(time.Time{})
	if !bytes.Equal(echo.Payload, payload) {
		t.Fatalf("echo payload (len %d) differs from the sent %d-byte payload", len(echo.Payload), n)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream binary hits = %d, want 1", got)
	}

	_ = ws.WriteFrame(conn, &ws.Frame{Fin: true, Opcode: ws.OpcodeClose, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte{0x03, 0xe8}})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = ws.ReadFrame(br)
	_ = conn.Close()

	// Recording: one Send and one Receive binary flow with the full body
	// and the full wire frame, on a Stream that completes.
	var sendFl, recvFl *flow.Flow
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (sendFl == nil || recvFl == nil) {
		sendFl, recvFl = nil, nil
		for _, fl := range store.Flows() {
			if fl.Metadata["ws_opcode"] != "2" {
				continue
			}
			switch fl.Direction {
			case "send":
				sendFl = fl
			case "receive":
				recvFl = fl
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sendFl == nil || recvFl == nil {
		t.Fatalf("binary flows not recorded (send=%v receive=%v)", sendFl != nil, recvFl != nil)
	}
	if len(sendFl.Body) != n || !bytes.Equal(sendFl.RawBytes, sentWire.Bytes()) {
		t.Errorf("send flow: body %d bytes (want %d), raw %d bytes (want the %d-byte client frame)",
			len(sendFl.Body), n, len(sendFl.RawBytes), sentWire.Len())
	}
	// The upstream's frame is relayed verbatim to the client, so the
	// recorded Receive raw equals what the client read.
	if len(recvFl.Body) != n || !bytes.Equal(recvFl.RawBytes, echoRaw) {
		t.Errorf("receive flow: body %d bytes (want %d), raw %d bytes (want the %d-byte upstream frame)",
			len(recvFl.Body), n, len(recvFl.RawBytes), len(echoRaw))
	}
	if !waitStreamStateUpdate(store, sendFl.StreamID, "complete", 10*time.Second) {
		t.Errorf("Stream %s did not reach state complete; updates=%+v", sendFl.StreamID, store.StreamUpdates(sendFl.StreamID))
	}
}

// waitStreamStateUpdate polls until an UpdateStream with State=want lands
// on streamID.
func waitStreamStateUpdate(store *flowStoreCapture, streamID, want string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		for _, upd := range store.StreamUpdates(streamID) {
			if upd.State == want {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
