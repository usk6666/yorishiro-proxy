package socks5

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
)

func TestHandleRequest_ConnectIPv4(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// CONNECT to 192.168.1.1:8080
	go func() {
		req := []byte{
			0x05,           // VER
			cmdConnect,     // CMD
			0x00,           // RSV
			atypIPv4,       // ATYP
			192, 168, 1, 1, // DST.ADDR
			0x1F, 0x90, // DST.PORT (8080)
		}
		client.Write(req)
	}()

	target, err := h.handleRequest(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "192.168.1.1:8080" {
		t.Fatalf("expected 192.168.1.1:8080, got %s", target)
	}
}

func TestHandleRequest_ConnectDomain(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	domain := "example.com"
	go func() {
		req := []byte{
			0x05,              // VER
			cmdConnect,        // CMD
			0x00,              // RSV
			atypDomain,        // ATYP
			byte(len(domain)), // domain length
		}
		req = append(req, []byte(domain)...)
		req = append(req, 0x00, 0x50) // port 80
		client.Write(req)
	}()

	target, err := h.handleRequest(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com:80" {
		t.Fatalf("expected example.com:80, got %s", target)
	}
}

func TestHandleRequest_ConnectIPv6(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// ::1 (loopback)
	ip6 := net.ParseIP("::1").To16()
	go func() {
		req := []byte{
			0x05,       // VER
			cmdConnect, // CMD
			0x00,       // RSV
			atypIPv6,   // ATYP
		}
		req = append(req, ip6...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, 443)
		req = append(req, portBuf...)
		client.Write(req)
	}()

	target, err := h.handleRequest(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "[::1]:443" {
		t.Fatalf("expected [::1]:443, got %s", target)
	}
}

func TestHandleRequest_UnsupportedCommand_Bind(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Use separate goroutines for writing and reading to avoid pipe deadlock.
	go func() {
		client.Write([]byte{
			0x05,     // VER
			cmdBind,  // CMD (BIND - unsupported)
			0x00,     // RSV
			atypIPv4, // ATYP
			127, 0, 0, 1,
			0x00, 0x50,
		})
	}()
	// Drain any reply from server in a separate goroutine to prevent
	// writeReply from blocking on the synchronous pipe.
	go func() {
		io.Copy(io.Discard, client)
	}()

	_, err := h.handleRequest(server)
	if err == nil {
		t.Fatal("expected error for unsupported BIND command")
	}
}

func TestHandleRequest_UnsupportedCommand_UDPAssociate(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte{
			0x05,            // VER
			cmdUDPAssociate, // CMD (UDP ASSOCIATE - unsupported)
			0x00,            // RSV
			atypIPv4,        // ATYP
			127, 0, 0, 1,
			0x00, 0x50,
		})
	}()
	go func() {
		io.Copy(io.Discard, client)
	}()

	_, err := h.handleRequest(server)
	if err == nil {
		t.Fatal("expected error for unsupported UDP ASSOCIATE command")
	}
}

func TestHandleRequest_UnsupportedAddressType(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte{
			0x05,       // VER
			cmdConnect, // CMD
			0x00,       // RSV
			0x05,       // ATYP (invalid)
			127, 0, 0, 1,
			0x00, 0x50,
		})
	}()
	go func() {
		io.Copy(io.Discard, client)
	}()

	_, err := h.handleRequest(server)
	if err == nil {
		t.Fatal("expected error for unsupported address type")
	}
}

func TestHandleRequest_BadVersion(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte{
			0x04,       // VER (SOCKS4)
			cmdConnect, // CMD
			0x00,       // RSV
			atypIPv4,   // ATYP
			127, 0, 0, 1,
			0x00, 0x50,
		})
	}()
	go func() {
		io.Copy(io.Discard, client)
	}()

	_, err := h.handleRequest(server)
	if err == nil {
		t.Fatal("expected error for bad SOCKS version")
	}
}

func TestHandleRequest_EmptyDomain(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte{
			0x05,       // VER
			cmdConnect, // CMD
			0x00,       // RSV
			atypDomain, // ATYP
			0x00,       // domain length = 0
			0x00, 0x50, // port 80
		})
	}()
	go func() {
		io.Copy(io.Discard, client)
	}()

	_, err := h.handleRequest(server)
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestWriteReply_Success_IPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	bindAddr := &net.TCPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 1234,
	}

	go func() {
		writeReply(server, replySuccess, bindAddr)
	}()

	// Read reply: VER(1) + REP(1) + RSV(1) + ATYP(1) + IPv4(4) + PORT(2) = 10 bytes
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if reply[0] != socks5Version {
		t.Fatalf("expected version 0x05, got 0x%02x", reply[0])
	}
	if reply[1] != replySuccess {
		t.Fatalf("expected success (0x00), got 0x%02x", reply[1])
	}
	if reply[2] != 0x00 {
		t.Fatalf("expected RSV 0x00, got 0x%02x", reply[2])
	}
	if reply[3] != atypIPv4 {
		t.Fatalf("expected ATYP IPv4 (0x01), got 0x%02x", reply[3])
	}

	ip := net.IP(reply[4:8])
	if !ip.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}

	port := binary.BigEndian.Uint16(reply[8:10])
	if port != 1234 {
		t.Fatalf("expected port 1234, got %d", port)
	}
}

func TestWriteReply_Error(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		writeReply(server, replyConnectionNotAllowed, nil)
	}()

	// Reply with nil addr uses default IPv4 0.0.0.0:0 = 10 bytes.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if reply[1] != replyConnectionNotAllowed {
		t.Fatalf("expected connection not allowed (0x02), got 0x%02x", reply[1])
	}
}

func TestWriteReply_IPv6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	bindAddr := &net.TCPAddr{
		IP:   net.ParseIP("::1"),
		Port: 9999,
	}

	go func() {
		writeReply(server, replySuccess, bindAddr)
	}()

	// VER(1) + REP(1) + RSV(1) + ATYP(1) + IPv6(16) + PORT(2) = 22 bytes
	reply := make([]byte, 22)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	if reply[3] != atypIPv6 {
		t.Fatalf("expected ATYP IPv6 (0x04), got 0x%02x", reply[3])
	}

	port := binary.BigEndian.Uint16(reply[20:22])
	if port != 9999 {
		t.Fatalf("expected port 9999, got %d", port)
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		host    string
		port    int
		wantErr bool
	}{
		{
			name:  "ipv4 with port",
			input: "192.168.1.1:8080",
			host:  "192.168.1.1",
			port:  8080,
		},
		{
			name:  "domain with port",
			input: "example.com:443",
			host:  "example.com",
			port:  443,
		},
		{
			name:    "no port",
			input:   "example.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseHostPort(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.host {
				t.Fatalf("host: expected %s, got %s", tt.host, host)
			}
			if port != tt.port {
				t.Fatalf("port: expected %d, got %d", tt.port, port)
			}
		})
	}
}
