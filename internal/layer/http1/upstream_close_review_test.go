package http1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1229 review round 1.
//
// F-1: a response to HEAD has no body whatever its framing headers say
// (RFC 9112 §6.3 rule 1), so an upstream that answers HEAD with a
// Content-Length / chunked head and then closes has answered completely;
// and on a keep-alive conn the next response is not swallowed as the HEAD
// response's body.
//
// F-2: once the upstream receive loop has ended on a terminal condition the
// Layer can never answer another request, so it must report itself retired
// and refuse further exchanges immediately instead of queueing them behind
// a parser that is gone.

func sendMethod(t *testing.T, ch layer.Channel, method, path string) {
	t.Helper()
	req := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:  method,
			Path:    path,
			Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	}
	if err := ch.Send(context.Background(), req); err != nil {
		t.Fatalf("Send %s %s: %v", method, path, err)
	}
}

// TestLayer_Receive_HEADResponse_Bodyless covers F-1: the HEAD response is
// complete as soon as its head is read, so an upstream close afterwards is
// not a truncation.
func TestLayer_Receive_HEADResponse_Bodyless(t *testing.T) {
	cases := []struct{ name, reply string }{
		{name: "content-length then close", reply: "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"},
		{name: "chunked then close", reply: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()
			go upstreamPeer(server, tc.reply)

			l := New(client, "up-1", envelope.Receive)
			defer l.Close()
			ch := l.OpenExchange()
			sendMethod(t, ch, "HEAD", "/")

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			env, err := ch.Next(ctx)
			if err != nil {
				t.Fatalf("Next: %v; want the HEAD response", err)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.Status != 200 {
				t.Errorf("status = %d, want 200", msg.Status)
			}
			if hasAnomaly(msg, envelope.AnomalyTruncatedBody) {
				t.Errorf("HEAD response flagged %s; a HEAD response has no body (RFC 9112 §6.3)", envelope.AnomalyTruncatedBody)
			}
			if len(msg.Body) != 0 {
				t.Errorf("body = %q, want empty", msg.Body)
			}
			wire, werr := env.WireBytes(ctx)
			if werr != nil {
				t.Fatalf("WireBytes: %v", werr)
			}
			if string(wire) != tc.reply {
				t.Errorf("wire bytes = %q, want %q", wire, tc.reply)
			}
			if _, err := ch.Next(ctx); !errors.Is(err, io.EOF) {
				t.Errorf("second Next = %v, want io.EOF (the exchange completed)", err)
			}
		})
	}
}

// TestLayer_Receive_HEADKeepAlive_NextResponseNotSwallowed covers F-1 on a
// keep-alive conn: the response after a HEAD response is parsed as the
// next exchange's response, not consumed as the HEAD response's body.
func TestLayer_Receive_HEADKeepAlive_NextResponseNotSwallowed(t *testing.T) {
	cases := []struct{ name, headReply string }{
		{name: "content-length", headReply: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"},
		{name: "chunked", headReply: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
	}
	const getReply = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()
			go func() {
				br := bufio.NewReader(server)
				for _, reply := range []string{tc.headReply, getReply} {
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if line == "\r\n" {
							break
						}
					}
					if _, err := server.Write([]byte(reply)); err != nil {
						return
					}
				}
			}()

			l := New(client, "up-1", envelope.Receive)
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ch1 := l.OpenExchange()
			sendMethod(t, ch1, "HEAD", "/h")
			env1, err := ch1.Next(ctx)
			if err != nil {
				t.Fatalf("HEAD Next: %v", err)
			}
			if m := env1.Message.(*envelope.HTTPMessage); len(m.Body) != 0 || hasAnomaly(m, envelope.AnomalyTruncatedBody) {
				t.Errorf("HEAD response body=%q anomalies=%+v, want empty body and no anomaly", m.Body, m.Anomalies)
			}

			ch2 := l.OpenExchange()
			if ch2 == nil {
				t.Fatal("OpenExchange after a complete HEAD exchange = nil; want the conn reusable")
			}
			sendMethod(t, ch2, "GET", "/g")
			env2, err := ch2.Next(ctx)
			if err != nil {
				t.Fatalf("GET Next: %v", err)
			}
			if m := env2.Message.(*envelope.HTTPMessage); string(m.Body) != "hello" {
				t.Errorf("GET body = %q, want %q", m.Body, "hello")
			}
		})
	}
}

// TestLayer_Receive_TerminalExit_RetiresLayer covers F-2: after the receive
// loop ends on a terminal condition the Layer reports Retired, OpenExchange
// returns nil, HealthCheck reports stale, and a Channel opened before the
// loop ended fails its Send immediately instead of queueing a request
// nobody will answer.
func TestLayer_Receive_TerminalExit_RetiresLayer(t *testing.T) {
	cases := []struct{ name, reply string }{
		{name: "truncated body", reply: "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"},
		{name: "closed before response", reply: ""},
		// The status line is parsed best-effort, so an unparseable
		// response needs a hard parser limit: header count over 10000.
		{name: "response parse error", reply: "HTTP/1.1 200 OK\r\n" + strings.Repeat("A: b\r\n", 10001) + "\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()
			go upstreamPeer(server, tc.reply)

			l := New(client, "up-1", envelope.Receive)
			defer l.Close()
			ch := l.OpenExchange()
			// Opened before the receive loop can end (it parses only once a
			// request is registered); its request is sent after it ended.
			late := l.OpenExchange()
			if late == nil {
				t.Fatal("OpenExchange before the loop ended = nil")
			}
			sendGET(t, ch)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for {
				if _, err := ch.Next(ctx); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("Next blocked: %v", err)
					}
					break
				}
			}

			if !l.Retired() {
				t.Error("Retired() = false after the receive loop ended; want true so an owner without a redial chain ends the client")
			}
			if got := l.OpenExchange(); got != nil {
				t.Error("OpenExchange after the receive loop ended returned a Channel; want nil")
			}
			if err := l.HealthCheck(); err == nil {
				t.Error("HealthCheck = nil after the receive loop ended; want stale")
			}

			done := make(chan error, 1)
			go func() {
				req := &envelope.Envelope{
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolHTTP,
					Message: &envelope.HTTPMessage{
						Method:  "GET",
						Path:    "/late",
						Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
					},
				}
				if err := late.Send(context.Background(), req); err != nil {
					done <- err
					return
				}
				nctx, ncancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer ncancel()
				_, err := late.Next(nctx)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late exchange succeeded on a dead Layer; want an error")
				}
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("late exchange Next blocked until its deadline (%v); want an immediate error", err)
				}
				var stale *StaleUpstreamError
				if !errors.As(err, &stale) {
					t.Errorf("late exchange err = %v (%T), want *StaleUpstreamError from Send", err, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("late exchange still blocked after 3s")
			}
		})
	}
}

// TestLayer_Receive_HealthyAfterCompleteResponse guards F-2's scope: a
// complete keep-alive response leaves the Layer usable (not retired).
func TestLayer_Receive_HealthyAfterCompleteResponse(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}
		}
	}()

	l := New(client, "up-1", envelope.Receive)
	defer l.Close()
	ch := l.OpenExchange()
	sendGET(t, ch)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if l.Retired() {
		t.Error("Retired() = true after a complete keep-alive response; want false")
	}
	if l.OpenExchange() == nil {
		t.Error("OpenExchange = nil after a complete keep-alive response")
	}
}
