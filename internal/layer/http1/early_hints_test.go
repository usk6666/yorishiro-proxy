package http1

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-721. HTTP/1.x channel must emit a 1xx informational response and the
// final response as two distinct envelopes with monotonically increasing
// sequence numbers, both carrying the same StreamID. Pre-fix behavior was
// to emit both with Sequence=1 (c.sequence+1 without advancing c.sequence
// per emitted response), which made the 103 and 200 indistinguishable in
// the same Stream.
func TestChannel_NextResponse_EarlyHints_ThenFinal(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	// Upstream writes 103 Early Hints, then 200 OK with body. Both are valid
	// HTTP/1.1 sequences per RFC 9110 §15.2.1.
	resp := "HTTP/1.1 103 Early Hints\r\n" +
		"Link: </style.css>; rel=preload; as=style\r\n" +
		"\r\n" +
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 15\r\n" +
		"\r\n" +
		"<html>hi</html>"
	go func() {
		_, _ = client.Write([]byte(resp))
		client.Close()
	}()

	ch := <-l.Channels()
	ch.(*channel).currentStreamID = "stream-req-1"
	ch.(*channel).sequence = 0

	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	msg1, ok := env1.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("env1.Message = %T, want *HTTPMessage", env1.Message)
	}
	if msg1.Status != 103 {
		t.Errorf("Status #1 = %d, want 103", msg1.Status)
	}
	if env1.Sequence != 1 {
		t.Errorf("Sequence #1 = %d, want 1", env1.Sequence)
	}
	if env1.Direction != envelope.Receive {
		t.Errorf("Direction #1 = %v, want Receive", env1.Direction)
	}
	if len(msg1.Body) != 0 || msg1.BodyBuffer != nil {
		t.Errorf("103 must be bodyless, got Body=%q BodyBuffer=%v", msg1.Body, msg1.BodyBuffer)
	}

	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2: %v", err)
	}
	msg2, ok := env2.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("env2.Message = %T, want *HTTPMessage", env2.Message)
	}
	if msg2.Status != 200 {
		t.Errorf("Status #2 = %d, want 200", msg2.Status)
	}
	if env2.Sequence != 2 {
		t.Errorf("Sequence #2 = %d, want 2 (must differ from 103's sequence)", env2.Sequence)
	}
	if string(msg2.Body) != "<html>hi</html>" {
		t.Errorf("Body #2 = %q, want <html>hi</html>", msg2.Body)
	}

	// Both envelopes share the StreamID (same exchange).
	if env1.StreamID != env2.StreamID {
		t.Errorf("StreamIDs differ: %q vs %q", env1.StreamID, env2.StreamID)
	}
	// FlowIDs differ (independent flows).
	if env1.FlowID == env2.FlowID {
		t.Error("FlowIDs identical; 103 and 200 must record as distinct flows")
	}
}

// 100 Continue + final response. Common for clients that send Expect:
// 100-continue with a request body.
func TestChannel_NextResponse_Continue_ThenFinal(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	resp := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 201 Created\r\n" +
		"Content-Length: 2\r\n" +
		"\r\n" +
		"ok"
	go func() {
		_, _ = client.Write([]byte(resp))
		client.Close()
	}()

	ch := <-l.Channels()
	ch.(*channel).currentStreamID = "stream-req-1"
	ch.(*channel).sequence = 0

	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	if msg, ok := env1.Message.(*envelope.HTTPMessage); !ok || msg.Status != 100 {
		t.Fatalf("first response Status != 100 (got %v)", env1.Message)
	}
	if env1.Sequence != 1 {
		t.Errorf("Sequence #1 = %d, want 1", env1.Sequence)
	}

	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2: %v", err)
	}
	msg2 := env2.Message.(*envelope.HTTPMessage)
	if msg2.Status != 201 {
		t.Errorf("Status #2 = %d, want 201", msg2.Status)
	}
	if env2.Sequence != 2 {
		t.Errorf("Sequence #2 = %d, want 2", env2.Sequence)
	}
}
