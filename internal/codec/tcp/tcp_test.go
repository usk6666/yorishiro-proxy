package tcp

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// Compile-time interface check.
var _ codec.Codec = (*Codec)(nil)

func TestNext_ReadsBodyFromConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	want := []byte("hello world")
	go func() {
		client.Write(want)
	}()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if string(ex.Body) != string(want) {
		t.Errorf("Body = %q, want %q", ex.Body, want)
	}
}

func TestNext_RawBytesMatchesBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	data := []byte("raw data")
	go func() {
		client.Write(data)
	}()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if string(ex.RawBytes) != string(data) {
		t.Errorf("RawBytes = %q, want %q", ex.RawBytes, data)
	}
}

func TestSend_WritesBodyToConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := New(client, "stream-1", exchange.Send)
	defer c.Close()

	want := []byte("outgoing data")
	ex := &exchange.Exchange{Body: want}

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, _ := server.Read(buf)
		done <- buf[:n]
	}()

	if err := c.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := <-done
	if string(got) != string(want) {
		t.Errorf("sent = %q, want %q", got, want)
	}
}

func TestNext_ReturnsEOFOnClose(t *testing.T) {
	client, server := net.Pipe()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	// Close the writing side so Next sees EOF.
	client.Close()

	_, err := c.Next(context.Background())
	if err != io.EOF {
		t.Fatalf("Next() error = %v, want io.EOF", err)
	}
}

func TestNext_StreamIDConsistent(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	const streamID = "consistent-stream"
	c := New(server, streamID, exchange.Send)
	defer c.Close()

	go func() {
		client.Write([]byte("first"))
		client.Write([]byte("second"))
	}()

	ex1, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() #1 error: %v", err)
	}
	ex2, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() #2 error: %v", err)
	}

	if ex1.StreamID != streamID {
		t.Errorf("ex1.StreamID = %q, want %q", ex1.StreamID, streamID)
	}
	if ex2.StreamID != streamID {
		t.Errorf("ex2.StreamID = %q, want %q", ex2.StreamID, streamID)
	}
}

func TestNext_FlowIDUnique(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	go func() {
		client.Write([]byte("a"))
		client.Write([]byte("b"))
		client.Write([]byte("c"))
	}()

	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		ex, err := c.Next(context.Background())
		if err != nil {
			t.Fatalf("Next() #%d error: %v", i, err)
		}
		if seen[ex.FlowID] {
			t.Fatalf("duplicate FlowID %q at index %d", ex.FlowID, i)
		}
		seen[ex.FlowID] = true
	}
}

func TestNext_SequenceIncrements(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	go func() {
		client.Write([]byte("x"))
		client.Write([]byte("y"))
		client.Write([]byte("z"))
	}()

	for want := 0; want < 3; want++ {
		ex, err := c.Next(context.Background())
		if err != nil {
			t.Fatalf("Next() #%d error: %v", want, err)
		}
		if ex.Sequence != want {
			t.Errorf("Sequence = %d, want %d", ex.Sequence, want)
		}
	}
}

func TestNext_DirectionSet(t *testing.T) {
	tests := []struct {
		name      string
		direction exchange.Direction
	}{
		{"Send", exchange.Send},
		{"Receive", exchange.Receive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			c := New(server, "stream-1", tt.direction)
			defer c.Close()

			go func() {
				client.Write([]byte("data"))
			}()

			ex, err := c.Next(context.Background())
			if err != nil {
				t.Fatalf("Next() error: %v", err)
			}
			if ex.Direction != tt.direction {
				t.Errorf("Direction = %v, want %v", ex.Direction, tt.direction)
			}
		})
	}
}

func TestNext_ProtocolIsTCP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	go func() {
		client.Write([]byte("data"))
	}()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}
	if ex.Protocol != exchange.TCP {
		t.Errorf("Protocol = %q, want %q", ex.Protocol, exchange.TCP)
	}
}

func TestNewWithStreamID_GeneratesUUID(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	c := NewWithStreamID(server, exchange.Send)
	defer c.Close()

	if c.streamID == "" {
		t.Fatal("streamID is empty")
	}
	// UUID v4 format: 8-4-4-4-12 hex digits = 36 chars.
	if len(c.streamID) != 36 {
		t.Errorf("streamID length = %d, want 36 (UUID format)", len(c.streamID))
	}
}

func TestNext_BodyAndRawBytesSeparate(t *testing.T) {
	// Verify that modifying Body in-place does not affect RawBytes
	// (wire fidelity preservation).
	client, server := net.Pipe()
	defer client.Close()

	c := New(server, "stream-1", exchange.Send)
	defer c.Close()

	go func() {
		client.Write([]byte("original"))
	}()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Mutate Body in-place (simulating a Pipeline Step or plugin).
	for i := range ex.Body {
		ex.Body[i] = 'X'
	}

	// RawBytes must still contain the original wire data.
	if string(ex.RawBytes) != "original" {
		t.Errorf("RawBytes = %q after Body mutation, want %q", ex.RawBytes, "original")
	}
}

func TestClose_ClosesConnection(t *testing.T) {
	_, server := net.Pipe()

	c := New(server, "stream-1", exchange.Send)
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Writing to a closed connection should fail.
	_, err := server.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error writing to closed connection, got nil")
	}
}
