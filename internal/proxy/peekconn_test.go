package proxy

import (
	"io"
	"net"
	"testing"
)

func TestPeekConn_PeekThenRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	go func() {
		server.Write(data)
		server.Close()
	}()

	pc := NewPeekConn(client)

	// Peek first 4 bytes
	peeked, err := pc.Peek(4)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if string(peeked) != "GET " {
		t.Fatalf("Peek got %q, want %q", peeked, "GET ")
	}

	// Read all — peeked bytes should be included
	all, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(all) != string(data) {
		t.Fatalf("ReadAll got %q, want %q", all, data)
	}
}

func TestPeekConn_MultiplePeeks(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	data := []byte("POST /api HTTP/1.1\r\n\r\n")
	go func() {
		server.Write(data)
		server.Close()
	}()

	pc := NewPeekConn(client)

	// First peek
	p1, err := pc.Peek(4)
	if err != nil {
		t.Fatalf("Peek(4): %v", err)
	}
	if string(p1) != "POST" {
		t.Fatalf("Peek(4) got %q, want %q", p1, "POST")
	}

	// Second larger peek — should still work
	p2, err := pc.Peek(8)
	if err != nil {
		t.Fatalf("Peek(8): %v", err)
	}
	if string(p2) != "POST /ap" {
		t.Fatalf("Peek(8) got %q, want %q", p2, "POST /ap")
	}

	// Read all
	all, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(all) != string(data) {
		t.Fatalf("ReadAll got %q, want %q", all, data)
	}
}

func TestPeekConn_ImplementsNetConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pc := NewPeekConn(client)

	// Verify it satisfies net.Conn
	var _ net.Conn = pc

	// LocalAddr and RemoteAddr should delegate
	if pc.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}
