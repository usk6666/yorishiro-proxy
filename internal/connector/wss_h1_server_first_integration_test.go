//go:build e2e && !e2e_smoke

package connector_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// USK-1171: server-speaks-first WebSocket over a CONNECT-MITM'd wss://
// (HTTP/1.1 inside the tunnel). The upstream sends a text frame right
// after the 101 and the client never sends anything. The frame must reach
// the client promptly (browser parity: a direct connection delivers it
// immediately), be recorded as a Receive flow on the handshake Stream,
// and the Stream must leave state=active once the client goes away.

// startServerFirstWSSUpstream runs a TLS WebSocket upstream that answers
// the handshake with 101 and then pushes greeting on its own initiative.
// It then reads (and discards) client frames until the connection ends,
// so it never closes the connection by itself.
func startServerFirstWSSUpstream(t *testing.T, greeting string) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newFlyedgeUpstreamTLSConfig(t))
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
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
					"Sec-WebSocket-Accept: " + computeWSAcceptUSK841(key) + "\r\n\r\n")); err != nil {
					return
				}
				// Let the 101 cross the proxy so the greeting arrives after
				// the swap rather than as 101 leftover bytes.
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
	return ln
}

// streamStateSnapshot returns the State of stream id under the store lock
// (UpdateStream mutates the stored *flow.Stream in place).
func streamStateSnapshot(s *testStore, id string) (protocol, state string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID == id {
			return st.Protocol, st.State, true
		}
	}
	return "", "", false
}

func TestWSS_H1_ServerSpeaksFirst_RelayedWithoutClientSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const greeting = "server-hello"
	ln := startServerFirstWSSUpstream(t, greeting)

	proxyAddr, store, shutdown := startWSH1H2AdvertProxy(t, ctx)
	defer shutdown()

	raw, err := dialCONNECTH1(ctx, proxyAddr, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial CONNECT: %v", err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}
	if err := writeWSClientHandshakeUSK839(tc, ln.Addr().String()); err != nil {
		t.Fatalf("WS client handshake: %v", err)
	}
	br := bufio.NewReader(tc)
	if err := readWS101StatusUSK839(br); err != nil {
		t.Fatalf("read WS 101: %v", err)
	}

	// 1. Communication: the greeting reaches the client with no client send.
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := ws.ReadFrame(br)
	if err != nil {
		t.Fatalf("server-first frame not relayed within 2s without a client send: %v", err)
	}
	_ = tc.SetReadDeadline(time.Time{})
	if frame.Opcode != ws.OpcodeText || string(frame.Payload) != greeting {
		t.Fatalf("relayed frame = opcode %d payload %q, want text %q", frame.Opcode, frame.Payload, greeting)
	}

	// 2. Recording: a Receive flow under the handshake StreamID, seq 2,
	// with wire raw bytes, on a Stream whose protocol is ws.
	var recvStreamID string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && recvStreamID == "" {
		for _, f := range store.flowsByDirection("receive") {
			if string(f.Body) != greeting {
				continue
			}
			recvStreamID = f.StreamID
			if f.Sequence != 2 {
				t.Errorf("greeting Receive flow Sequence = %d, want 2 (after handshake Send 0 + 101 Receive 1)", f.Sequence)
			}
			if len(f.RawBytes) == 0 {
				t.Error("greeting Receive flow has empty RawBytes")
			}
			break
		}
		if recvStreamID == "" {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if recvStreamID == "" {
		t.Fatal("no Receive flow recorded for the server-first greeting")
	}
	var handshakeID string
	for _, f := range store.flowsByDirection("send") {
		if f.Sequence == 0 && f.Method == "GET" {
			handshakeID = f.StreamID
		}
	}
	if handshakeID == "" {
		t.Fatal("no handshake Send flow recorded")
	}
	if recvStreamID != handshakeID {
		t.Errorf("greeting recorded under StreamID %q, want handshake StreamID %q", recvStreamID, handshakeID)
	}
	if proto, _, ok := streamStateSnapshot(store, handshakeID); !ok || proto != "ws" {
		t.Errorf("handshake Stream protocol = %q (found=%v), want ws", proto, ok)
	}

	// 3. State: the client goes away without ever sending a frame while
	// the upstream stays idle; the Stream must leave state=active and
	// settle at complete.
	_ = tc.Close()
	var state string
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, state, _ = streamStateSnapshot(store, handshakeID)
		if state != "" && state != "active" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A client FIN is a clean end of the session: the upstream read error
	// provoked by the proxy's own teardown must not be recorded as error.
	if state != "complete" {
		t.Errorf("handshake Stream state = %q after client close, want complete", state)
	}
}
