//go:build e2e

package mcp

import (
	"bufio"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// newWebSocketEchoServer creates a TCP server that accepts HTTP Upgrade requests,
// performs the WebSocket handshake, and echoes back any received frames.
//
// Restored in USK-695 — the original definition lived in the legacy
// `resend_ws_test.go` deleted by USK-693, but `fuzz_ws_integration_test.go`
// and `resend_ws_integration_test.go` (both `//go:build e2e`) still depend
// on the helper. USK-693's `make test` was green because e2e tests are
// excluded from that target; the latent break only surfaces under
// `make test-e2e`.
func newWebSocketEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWSEchoConn(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// handleWSEchoConn handles a single WebSocket echo connection.
func handleWSEchoConn(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Header.Get("Upgrade") != "websocket" {
		resp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
		conn.Write([]byte(resp))
		return
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	for {
		frame, err := ws.ReadFrame(reader)
		if err != nil {
			return
		}

		if frame.Opcode == ws.OpcodeClose {
			closeFrame := &ws.Frame{
				Fin:     true,
				Opcode:  ws.OpcodeClose,
				Payload: frame.Payload,
			}
			ws.WriteFrame(conn, closeFrame)
			return
		}

		echoFrame := &ws.Frame{
			Fin:     true,
			Opcode:  frame.Opcode,
			Payload: frame.Payload,
		}
		if err := ws.WriteFrame(conn, echoFrame); err != nil {
			return
		}
	}
}
