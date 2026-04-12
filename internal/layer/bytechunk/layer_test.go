package bytechunk

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Compile-time interface compliance checks.
var (
	_ layer.Layer   = (*Layer)(nil)
	_ layer.Channel = (*Channel)(nil)
)

func TestLayer_YieldsSingleChannel(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	l := New(client, "stream-1", envelope.Send)

	var count int
	for ch := range l.Channels() {
		count++
		if ch.StreamID() != "stream-1" {
			t.Errorf("StreamID() = %q, want %q", ch.StreamID(), "stream-1")
		}
	}
	if count != 1 {
		t.Errorf("Channels() yielded %d channels, want 1", count)
	}
}

func TestChannel_NextAndSend_Bidirectional(t *testing.T) {
	// Simulate client→upstream with two net.Pipe endpoints.
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientSide.Close()
	defer proxyUpstreamSide.Close()
	defer upstreamConn.Close()

	// Proxy reads from client side (Send direction), writes to upstream side.
	clientLayer := New(proxyClientSide, "stream-1", envelope.Send)
	upstreamLayer := New(proxyUpstreamSide, "stream-1", envelope.Receive)

	clientCh := <-clientLayer.Channels()
	upstreamCh := <-upstreamLayer.Channels()

	ctx := context.Background()
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Client writes → proxy client channel reads
	go func() {
		clientConn.Write(payload)
	}()

	env, err := clientCh.Next(ctx)
	if err != nil {
		t.Fatalf("clientCh.Next() error: %v", err)
	}

	// Verify envelope fields
	if env.Protocol != envelope.ProtocolRaw {
		t.Errorf("Protocol = %q, want %q", env.Protocol, envelope.ProtocolRaw)
	}
	if env.Direction != envelope.Send {
		t.Errorf("Direction = %v, want Send", env.Direction)
	}
	if env.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", env.Sequence)
	}
	if env.StreamID != "stream-1" {
		t.Errorf("StreamID = %q, want %q", env.StreamID, "stream-1")
	}
	if env.FlowID == "" {
		t.Error("FlowID should be non-empty")
	}

	// Verify RawMessage
	msg, ok := env.Message.(*envelope.RawMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *RawMessage", env.Message)
	}
	if string(msg.Bytes) != string(payload) {
		t.Errorf("Message.Bytes = %q, want %q", msg.Bytes, payload)
	}

	// Verify Raw == Message.Bytes (wire fidelity)
	if string(env.Raw) != string(msg.Bytes) {
		t.Error("Envelope.Raw should equal RawMessage.Bytes")
	}

	// Forward to upstream via Send
	go func() {
		upstreamCh.Send(ctx, env)
	}()

	// Upstream reads the forwarded data
	buf := make([]byte, len(payload)+100)
	n, err := upstreamConn.Read(buf)
	if err != nil {
		t.Fatalf("upstream read error: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("upstream received %q, want %q", buf[:n], payload)
	}
}

func TestChannel_Next_EOF(t *testing.T) {
	client, server := net.Pipe()

	l := New(server, "stream-1", envelope.Send)
	ch := <-l.Channels()

	// Close the client side to trigger EOF on the server side
	client.Close()

	_, err := ch.Next(context.Background())
	if err != io.EOF {
		t.Errorf("Next() error = %v, want io.EOF", err)
	}
}

func TestChannel_Next_SequenceIncrements(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send)
	ch := <-l.Channels()

	ctx := context.Background()

	// Write 3 chunks
	go func() {
		client.Write([]byte("chunk1"))
		time.Sleep(10 * time.Millisecond)
		client.Write([]byte("chunk2"))
		time.Sleep(10 * time.Millisecond)
		client.Write([]byte("chunk3"))
	}()

	for i := 0; i < 3; i++ {
		env, err := ch.Next(ctx)
		if err != nil {
			t.Fatalf("Next() #%d error: %v", i, err)
		}
		if env.Sequence != i {
			t.Errorf("envelope #%d: Sequence = %d, want %d", i, env.Sequence, i)
		}
	}
}

func TestChannel_Send_NonRawMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send)
	ch := <-l.Channels()

	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{Method: "GET"},
	}
	err := ch.Send(context.Background(), env)
	if err == nil {
		t.Fatal("Send() with HTTPMessage should return error")
	}
}

func TestLayer_Close_ClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	l := New(server, "stream-1", envelope.Send)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Writing to client should fail because server side is closed
	_, err := client.Write([]byte("test"))
	if err == nil {
		t.Error("write to closed pipe should fail")
	}
}

func TestChannel_Next_ContextCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send)
	ch := <-l.Channels()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := ch.Next(ctx)
	if err == nil {
		t.Fatal("Next() with cancelled context should return error")
	}
}
