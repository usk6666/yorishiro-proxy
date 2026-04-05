//go:build e2e

package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// writeWSFrame writes a minimal WebSocket frame (no masking on server side, masking on client).
func writeWSFrame(conn net.Conn, fin bool, opcode byte, payload []byte, mask bool) error {
	var frame []byte
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	frame = append(frame, b0)

	var maskBit byte
	if mask {
		maskBit = 0x80
	}

	length := len(payload)
	switch {
	case length < 126:
		frame = append(frame, maskBit|byte(length))
	case length < 65536:
		frame = append(frame, maskBit|126)
		frame = append(frame, byte(length>>8), byte(length))
	default:
		frame = append(frame, maskBit|127)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(length))
		frame = append(frame, buf...)
	}

	if mask {
		maskKey := []byte{0x12, 0x34, 0x56, 0x78}
		frame = append(frame, maskKey...)
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ maskKey[i%4]
		}
		frame = append(frame, masked...)
	} else {
		frame = append(frame, payload...)
	}

	_, err := conn.Write(frame)
	return err
}

// readWSFrame reads a minimal WebSocket frame and returns the opcode and payload.
func readWSFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	opcode = b0 & 0x0F

	b1, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := (b1 & 0x80) != 0
	length := uint64(b1 & 0x7F)

	switch length {
	case 126:
		buf := make([]byte, 2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(buf))
	case 127:
		buf := make([]byte, 8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(buf)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i, b := range payload {
			payload[i] = b ^ maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func TestIntegration_WebSocket_EchoRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a WebSocket echo upstream.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(gohttp.StatusBadRequest)
			return
		}
		// Perform server-side WebSocket handshake.
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

		// Send 101 response.
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: dummy\r\n\r\n"
		conn.Write([]byte(resp))

		// Echo loop: read frames and echo back.
		for {
			opcode, payload, err := readWSFrame(buf.Reader)
			if err != nil {
				return
			}
			if opcode == 0x8 { // Close
				writeWSFrame(conn, true, 0x8, payload, false)
				return
			}
			// Echo the message back (server doesn't mask).
			if err := writeWSFrame(conn, true, opcode, payload, false); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	// Create SQLite store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Start proxy.
	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Connect to proxy, send HTTP CONNECT-like request with upgrade.
	upstreamURL, _ := url.Parse(upstream.URL)
	conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send WebSocket upgrade request (HTTP forward proxy style).
	upgradeReq := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		upstreamURL.Host, upstreamURL.Host)
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read 101 response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != gohttp.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}

	// Send a text message (client must mask).
	msg := []byte("hello websocket")
	if err := writeWSFrame(conn, true, 0x1, msg, true); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	// Read echo response.
	opcode, payload, err := readWSFrame(reader)
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("opcode = %d, want 1 (text)", opcode)
	}
	if string(payload) != "hello websocket" {
		t.Errorf("payload = %q, want %q", payload, "hello websocket")
	}

	// Send close frame.
	if err := writeWSFrame(conn, true, 0x8, []byte{0x03, 0xE8}, true); err != nil {
		t.Logf("write close frame: %v", err)
	}

	// Verify flow recording.
	var flows []*flow.Stream
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		// Expect at least the HTTP upgrade flow and the WebSocket flow.
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded for WebSocket session")
	}
}

func TestIntegration_WebSocket_WSS_EchoRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a WSS echo upstream (TLS).
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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
			if opcode == 0x8 {
				writeWSFrame(conn, true, 0x8, payload, false)
				return
			}
			if err := writeWSFrame(conn, true, opcode, payload, false); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	// Create store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Generate test CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Start proxy with HTTPS MITM.
	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	// Configure the proxy to trust the test upstream.
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	upstreamURL, _ := url.Parse(upstream.URL)
	_, upstreamPort, _ := net.SplitHostPort(upstreamURL.Host)

	// Step 1: CONNECT to establish tunnel.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n",
		upstreamPort, upstreamPort)
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Step 2: TLS handshake over the CONNECT tunnel.
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// Step 3: Send WebSocket upgrade over TLS.
	upgradeReq := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: localhost:%s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		upstreamPort)
	tlsConn.Write([]byte(upgradeReq))

	tlsReader := bufio.NewReader(tlsConn)
	wsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read ws upgrade response: %v", err)
	}
	if wsResp.StatusCode != gohttp.StatusSwitchingProtocols {
		t.Fatalf("ws upgrade status = %d, want 101", wsResp.StatusCode)
	}

	// Step 4: Send and receive WebSocket messages.
	msg := []byte("wss echo test")
	if err := writeWSFrame(tlsConn, true, 0x1, msg, true); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	opcode, payload, err := readWSFrame(tlsReader)
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	if opcode != 0x1 {
		t.Errorf("opcode = %d, want 1", opcode)
	}
	if string(payload) != "wss echo test" {
		t.Errorf("payload = %q, want %q", payload, "wss echo test")
	}

	// Close.
	if err := writeWSFrame(tlsConn, true, 0x8, []byte{0x03, 0xE8}, true); err != nil {
		t.Logf("write close frame: %v", err)
	}

	// Verify flow recording.
	var flows []*flow.Stream
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded for WSS session")
	}
}
