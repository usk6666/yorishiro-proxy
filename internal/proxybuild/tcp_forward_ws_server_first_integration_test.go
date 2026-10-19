//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// startServerFirstWSUpstreamUSK1171 runs a plaintext WebSocket upstream
// that answers the RFC 6455 handshake with 101 and immediately pushes
// greeting, without waiting for any client frame. It then discards client
// frames until the connection ends.
func startServerFirstWSUpstreamUSK1171(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
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
				if _, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + computeWSAcceptForUSK913(key) + "\r\n\r\n")); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
				if err := ws.WriteFrame(c, &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte(greeting)}); err != nil {
					return
				}
				for {
					if _, err := ws.ReadFrame(br); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestProxybuild_TCPForward_WS_ServerSpeaksFirst_RelayedWithoutClientSend
// pins USK-1171 on the tcp_forwards protocol=websocket path: a frame the
// upstream sends right after the 101 reaches the client although the
// client never sends a frame, and it is recorded as a Receive flow on the
// ws Stream.
func TestProxybuild_TCPForward_WS_ServerSpeaksFirst_RelayedWithoutClientSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const greeting = "server-hello-forward"
	upstreamAddr := startServerFirstWSUpstreamUSK1171(t, greeting)

	store := &flowStoreCapture{}
	mgr := newForwardTestManager(t, store)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: "websocket"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0")
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

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := ws.ReadFrame(br)
	if err != nil {
		t.Fatalf("server-first frame not relayed within 2s without a client send: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if frame.Opcode != ws.OpcodeText || string(frame.Payload) != greeting {
		t.Fatalf("relayed frame = opcode %d payload %q, want text %q", frame.Opcode, frame.Payload, greeting)
	}

	var found bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !found {
		for _, f := range store.Flows() {
			if f.Direction != "receive" || string(f.Body) != greeting {
				continue
			}
			found = true
			if len(f.RawBytes) == 0 {
				t.Error("greeting Receive flow has empty RawBytes")
			}
			var proto string
			for _, st := range store.Streams() {
				if st.ID == f.StreamID {
					proto = st.Protocol
				}
			}
			for _, u := range store.StreamUpdates(f.StreamID) {
				if u.Protocol != "" {
					proto = u.Protocol
				}
			}
			if proto != "ws" {
				t.Errorf("greeting Stream protocol = %q, want ws", proto)
			}
			break
		}
		if !found {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !found {
		t.Fatal("no Receive flow recorded for the server-first greeting")
	}
}
