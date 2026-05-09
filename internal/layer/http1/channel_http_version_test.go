package http1

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestChannel_HTTPVersion_Request_HTTP10 pins that an HTTP/1.0 request
// produces HTTPMessage.HTTPVersion == "http/1.0" (USK-788). The HTTP/1.x
// parser sets RawRequest.Proto from the request line; the channel
// translates that to the canonical lowercased form on emission.
func TestChannel_HTTPVersion_Request_HTTP10(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	req := "GET /foo HTTP/1.0\r\n" +
		"Host: example.com\r\n" +
		"\r\n"
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersion10 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersion10)
	}
}

// TestChannel_HTTPVersion_Request_HTTP11 pins that an HTTP/1.1 request
// produces HTTPMessage.HTTPVersion == "http/1.1" (USK-788).
func TestChannel_HTTPVersion_Request_HTTP11(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	req := "GET /bar HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n"
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersion11 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersion11)
	}
}

// TestChannel_HTTPVersion_Response_HTTP11 pins that an HTTP/1.1 response
// produces HTTPMessage.HTTPVersion == "http/1.1" (USK-788). Response-side
// version is read from the status line by the parser and translated by
// the channel.
func TestChannel_HTTPVersion_Response_HTTP11(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	go func() {
		client.Write([]byte(resp))
		client.Close()
	}()

	ch := <-l.Channels()
	ch.(*channel).currentStreamID = "stream-1"

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersion11 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersion11)
	}
}

// TestChannel_HTTPVersion_Response_HTTP10 pins that an HTTP/1.0 response
// (rare today but legal — RFC 1945) produces HTTPMessage.HTTPVersion ==
// "http/1.0" (USK-788).
func TestChannel_HTTPVersion_Response_HTTP10(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	resp := "HTTP/1.0 200 OK\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	go func() {
		client.Write([]byte(resp))
		client.Close()
	}()

	ch := <-l.Channels()
	ch.(*channel).currentStreamID = "stream-1"

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersion10 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersion10)
	}
}
