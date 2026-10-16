package http1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-1137 (defect D): a request line over the parser's limit used to make
// the client-facing Layer drop the connection without a response (curl:
// "Empty reply from server"). It now answers 414 URI Too Long with
// Connection: close before closing, as nginx (large_client_header_buffers)
// and Apache (HTTP_REQUEST_URI_TOO_LARGE) do (RFC 9110 §15.5.15).

// overLimitRequestLine is one byte past the 4 MiB request-line limit.
func overLimitRequestLine() string {
	return "GET /" + strings.Repeat("x", 4<<20) + " HTTP/1.1\r\nHost: example.com\r\n\r\n"
}

// pipeConn returns a synchronous in-memory pair (no CloseWrite support).
func pipeConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	return net.Pipe()
}

// TestLayer_Send_RequestLineTooLong_Writes414 covers Test Plan #12: the
// client-facing (envelope.Send) Layer answers an over-limit request line
// with 414 + Connection: close, then closes; the Channel yields an error and
// no envelope. Covered for the first request (deferred-parse path) and for a
// keep-alive follow-up (spawn-loop path), over net.Pipe (no CloseWrite) and
// loopback TCP (CloseWrite available).
func TestLayer_Send_RequestLineTooLong_Writes414(t *testing.T) {
	transports := []struct {
		name string
		dial func(t *testing.T) (net.Conn, net.Conn)
	}{
		{name: "net.Pipe", dial: pipeConn},
		{name: "tcp", dial: testConn},
	}
	cases := []struct {
		name      string
		keepAlive bool
	}{
		{name: "first request", keepAlive: false},
		{name: "second keep-alive request", keepAlive: true},
	}
	for _, tr := range transports {
		for _, tc := range cases {
			t.Run(tr.name+"/"+tc.name, func(t *testing.T) {
				client, server := tr.dial(t)
				defer client.Close()
				defer server.Close()

				l := New(server, "conn-414", envelope.Send)
				defer l.Close()

				payload := overLimitRequestLine()
				if tc.keepAlive {
					payload = "GET /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n" + payload
				}
				// The Layer stops reading once the limit trips, so on
				// net.Pipe the tail of this write only completes when the
				// Layer drains or closes; never block the test on it.
				go func() { _, _ = client.Write([]byte(payload)) }()

				type nextResult struct {
					env *envelope.Envelope
					err error
				}
				nextCh := make(chan nextResult, 1)
				go func() {
					ch := <-l.Channels()
					if tc.keepAlive {
						env, err := ch.Next(context.Background())
						if err != nil {
							nextCh <- nextResult{env, err}
							return
						}
						if msg, ok := env.Message.(*envelope.HTTPMessage); !ok || msg.Path != "/first" {
							nextCh <- nextResult{env, errors.New("first keep-alive request not parsed as /first")}
							return
						}
						_ = ch.Close()
						ch = <-l.Channels()
						if ch == nil {
							nextCh <- nextResult{nil, errors.New("Channels closed before the over-limit request")}
							return
						}
					}
					env, err := ch.Next(context.Background())
					nextCh <- nextResult{env, err}
				}()

				_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
				resp, readErr := io.ReadAll(client)
				if readErr != nil {
					t.Errorf("reading the response: %v (want the 414 followed by a clean EOF)", readErr)
				}
				if !strings.HasPrefix(string(resp), "HTTP/1.1 414 URI Too Long\r\n") {
					t.Fatalf("response = %q, want an HTTP/1.1 414 URI Too Long status line", truncateForLog(resp))
				}
				rr, err := parser.ParseResponse(bufio.NewReader(strings.NewReader(string(resp))))
				if err != nil {
					t.Fatalf("parse 414 response: %v", err)
				}
				if got := rr.Headers.Get("Connection"); !strings.EqualFold(got, "close") {
					t.Errorf("Connection = %q, want close", got)
				}
				if rr.Headers.Get("Content-Length") == "" {
					t.Error("414 response has no Content-Length")
				}

				select {
				case res := <-nextCh:
					if res.env != nil {
						t.Errorf("Next returned an envelope (%T), want none", res.env.Message)
					}
					if res.err == nil {
						t.Fatal("Next err = nil, want the request-line error")
					}
					if !tc.keepAlive {
						if !errors.Is(res.err, parser.ErrRequestLineTooLong) {
							t.Errorf("Next err = %v, want parser.ErrRequestLineTooLong", res.err)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Channel Next did not return")
				}
			})
		}
	}
}

// TestLayer_Receive_StatusLineTooLong_NoResponseWritten covers Test Plan #13:
// the upstream-facing (envelope.Receive) Layer treats an over-limit status
// line as an error and writes nothing back to the upstream — 414 is a
// client-facing answer only.
func TestLayer_Receive_StatusLineTooLong_NoResponseWritten(t *testing.T) {
	upstream, server := testConn(t)
	defer upstream.Close()
	defer server.Close()

	l := New(server, "conn-up", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	reqRead := make(chan error, 1)
	go func() {
		br := bufio.NewReader(upstream)
		if _, err := parser.ParseRequest(br); err != nil {
			reqRead <- err
			return
		}
		reqRead <- nil
		_, _ = upstream.Write([]byte("HTTP/1.1 200 " + strings.Repeat("x", 4<<20) + "\r\nContent-Length: 0\r\n\r\n"))
	}()

	if err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := <-reqRead; err != nil {
		t.Fatalf("upstream reading the request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err == nil {
		t.Fatalf("Next returned %T, want an error for the over-limit status line", env.Message)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Next timed out, want the status-line error")
	}

	_ = upstream.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _ := upstream.Read(buf); n > 0 {
		t.Errorf("upstream-facing Layer wrote %q after the status-line error, want nothing", buf[:n])
	}
}

func truncateForLog(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}
