package http1_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// loopbackPair returns both ends of a real loopback TCP connection.
func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server, ok := <-accepted
	if !ok {
		client.Close()
		t.Fatal("accept failed")
	}
	return client, server
}

// TestLayer_Send_RequestLineTooLong_PeekConnHalfCloses pins USK-1163: on
// the plain-HTTP path the client-facing Layer sits on a *connector.PeekConn
// (FullListener wraps every accepted conn in one). The 414 reject path must
// half-close that conn right after the 414, so the client sees the full
// response and EOF while the Layer is still draining the rejected request —
// not only once the drain gives up and closes.
//
// The linger is stretched to 30s so that, without the half-close, EOF
// cannot arrive within the client's read deadline.
func TestLayer_Send_RequestLineTooLong_PeekConnHalfCloses(t *testing.T) {
	http1.SetRejectLingerTimeoutForTest(t, 30*time.Second)

	client, server := loopbackPair(t)
	defer client.Close()
	defer server.Close()

	l := http1.New(connector.NewPeekConn(server), "conn-414-peekconn", envelope.Send)
	defer l.Close()

	nextErr := make(chan error, 1)
	go func() {
		ch := <-l.Channels()
		_, err := ch.Next(context.Background())
		nextErr <- err
	}()

	// Past the 4 MiB request-line limit by one full read buffer, no line
	// terminator (see TestLayer_Send_RequestLineTooLong_DrainsBeforeClose).
	head := "GET /" + strings.Repeat("x", 4<<20+4096)
	headErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte(head))
		headErr <- err
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client ReadAll: %v (want the 414 followed by EOF from the half-close, before the drain ends)", err)
	}
	if !strings.HasPrefix(string(resp), "HTTP/1.1 414 URI Too Long\r\n") {
		t.Fatalf("response = %q, want a 414 status line", resp)
	}
	if !strings.HasSuffix(string(resp), http1.URITooLongBodyForTest) {
		t.Fatalf("response = %q, want it to end with the 414 body", resp)
	}
	if err := <-headErr; err != nil {
		t.Fatalf("writing the over-limit request line: %v", err)
	}

	// Only the write side was closed: the Layer is still draining, so the
	// client can keep uploading without hitting RST.
	tail := []byte(strings.Repeat("y", 64<<10))
	if _, err := client.Write(tail); err != nil {
		t.Fatalf("client write after EOF: %v (want the drain still reading)", err)
	}
	_ = client.Close()

	select {
	case err := <-nextErr:
		if !errors.Is(err, parser.ErrRequestLineTooLong) {
			t.Errorf("Next err = %v, want parser.ErrRequestLineTooLong", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Channel Next did not return after the client closed")
	}
}
