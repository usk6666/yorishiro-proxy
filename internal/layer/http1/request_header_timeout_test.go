package http1

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1162: client-side request head deadline (net/http ReadHeaderTimeout
// equivalent) on Send-direction Layers.

func constDuration(d time.Duration) func() (time.Duration, bool) {
	return func() (time.Duration, bool) { return d, true }
}

// trickle writes b one byte at a time with gap between bytes until it runs
// out or a write fails. It returns when done is closed.
func trickle(conn net.Conn, b []byte, gap time.Duration, done <-chan struct{}) {
	for i := range b {
		select {
		case <-done:
			return
		case <-time.After(gap):
		}
		if _, err := conn.Write(b[i : i+1]); err != nil {
			return
		}
	}
}

type nextResult struct {
	env *envelope.Envelope
	err error
}

// nextAsync runs ch.Next in a goroutine and returns its result channel.
func nextAsync(ch layer.Channel) <-chan nextResult {
	out := make(chan nextResult, 1)
	go func() {
		env, err := ch.Next(context.Background())
		out <- nextResult{env, err}
	}()
	return out
}

// recvChannel takes the next Channel from l within d.
func recvChannel(t *testing.T, l *Layer, d time.Duration) layer.Channel {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			t.Fatal("Channels() closed before yielding a Channel")
		}
		return ch
	case <-time.After(d):
		t.Fatalf("no Channel yielded within %v", d)
	}
	return nil
}

const slowRequest = "GET /slowloris-path-that-is-long-enough HTTP/1.1\r\nHost: example.com\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n"

func TestLayer_RequestHeaderTimeout_TrickledRequestLine(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send, WithRequestHeaderTimeout(constDuration(200*time.Millisecond)))
	defer l.Close()

	done := make(chan struct{})
	defer close(done)
	go trickle(client, []byte(slowRequest), 50*time.Millisecond, done)

	ch := recvChannel(t, l, 2*time.Second)
	start := time.Now()
	select {
	case r := <-nextAsync(ch):
		if r.err == nil {
			t.Fatalf("Next returned an envelope for a trickled request; want deadline error")
		}
		if !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Errorf("Next error = %v, want one wrapping os.ErrDeadlineExceeded", r.err)
		}
		if el := time.Since(start); el > 1500*time.Millisecond {
			t.Errorf("Next returned after %v, want within ~200ms header bound", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next still blocked after 3s; trickled request line was not bounded")
	}
}

// Guard: without the option, the Layer keeps its pre-USK-1162 behavior.
func TestLayer_RequestHeaderTimeout_AbsentOptionNoDeadline(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send)
	defer l.Close()

	done := make(chan struct{})
	defer close(done)
	go trickle(client, []byte(slowRequest), 50*time.Millisecond, done)

	ch := recvChannel(t, l, 2*time.Second)
	select {
	case r := <-nextAsync(ch):
		t.Fatalf("Next returned early without a header timeout: env=%v err=%v", r.env, r.err)
	case <-time.After(1 * time.Second):
	}
}

// The first-byte wait uses the idle bound, not the header bound: a silent
// client is closed after the idle bound.
func TestLayer_RequestHeaderTimeout_IdlePhaseUsesIdleBound(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(constDuration(200*time.Millisecond)),
		WithKeepAliveIdleTimeout(constDuration(800*time.Millisecond)))
	defer l.Close()

	ch := recvChannel(t, l, 2*time.Second)
	start := time.Now()
	select {
	case r := <-nextAsync(ch):
		el := time.Since(start)
		if r.err == nil {
			t.Fatal("Next returned an envelope from a silent client")
		}
		if el < 600*time.Millisecond {
			t.Errorf("idle client closed after %v, want >= ~800ms idle bound (not the 200ms header bound)", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next still blocked after 3s on a silent client")
	}
}

// The idle bound is never shorter than the header bound.
func TestLayer_RequestHeaderTimeout_IdleNotShorterThanHeader(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(constDuration(800*time.Millisecond)),
		WithKeepAliveIdleTimeout(constDuration(100*time.Millisecond)))
	defer l.Close()

	ch := recvChannel(t, l, 2*time.Second)
	start := time.Now()
	select {
	case r := <-nextAsync(ch):
		if r.err == nil {
			t.Fatal("Next returned an envelope from a silent client")
		}
		if el := time.Since(start); el < 600*time.Millisecond {
			t.Errorf("idle client closed after %v, want >= header bound 800ms", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next still blocked after 3s on a silent client")
	}
}

// Keep-alive: a completed exchange followed by a trickled second request
// is cut off by the header bound; a fast second request still parses.
func TestLayer_RequestHeaderTimeout_KeepAliveSecondRequest(t *testing.T) {
	const req1 = "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n"

	t.Run("trickled", func(t *testing.T) {
		client, server := testConn(t)
		defer client.Close()
		defer server.Close()

		l := New(server, "s", envelope.Send,
			WithRequestHeaderTimeout(constDuration(200*time.Millisecond)),
			WithKeepAliveIdleTimeout(constDuration(5*time.Second)))
		defer l.Close()

		if _, err := client.Write([]byte(req1)); err != nil {
			t.Fatal(err)
		}
		ch1 := recvChannel(t, l, 2*time.Second)
		if r := <-nextAsync(ch1); r.err != nil {
			t.Fatalf("request 1: %v", r.err)
		}
		answerOK(t, ch1) // USK-1229: an unanswered request ends the connection
		_ = ch1.Close()

		done := make(chan struct{})
		defer close(done)
		go trickle(client, []byte(slowRequest), 50*time.Millisecond, done)

		start := time.Now()
		select {
		case ch2, ok := <-l.Channels():
			if ok {
				r := <-nextAsync(ch2)
				if r.err == nil {
					t.Fatal("trickled request 2 parsed; want terminal error")
				}
			}
			if el := time.Since(start); el > 2*time.Second {
				t.Errorf("request 2 cut off after %v, want within ~200ms header bound", el)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("trickled keep-alive request 2 still being parsed after 3s")
		}
	})

	t.Run("spaced beyond header bound", func(t *testing.T) {
		client, server := testConn(t)
		defer client.Close()
		defer server.Close()

		l := New(server, "s", envelope.Send,
			WithRequestHeaderTimeout(constDuration(200*time.Millisecond)),
			WithKeepAliveIdleTimeout(constDuration(5*time.Second)))
		defer l.Close()

		for i, path := range []string{"/one", "/two", "/three"} {
			if i > 0 {
				time.Sleep(500 * time.Millisecond) // > header bound, < idle bound
			}
			if _, err := client.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			ch := recvChannel(t, l, 2*time.Second)
			r := <-nextAsync(ch)
			if r.err != nil {
				t.Fatalf("request %d (%s) after idle gap: %v", i+1, path, r.err)
			}
			answerOK(t, ch) // USK-1229: an unanswered request ends the connection
			_ = ch.Close()
		}
	})
}

// The deadline is cleared before the body: a body sent well after the
// header bound still parses.
func TestLayer_RequestHeaderTimeout_DoesNotCoverBody(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send, WithRequestHeaderTimeout(constDuration(200*time.Millisecond)))
	defer l.Close()

	if _, err := client.Write([]byte("POST /p HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	ch := recvChannel(t, l, 2*time.Second)
	res := nextAsync(ch)
	time.Sleep(600 * time.Millisecond)
	if _, err := client.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("slow body: %v", r.err)
		}
		if msg, ok := r.env.Message.(*envelope.HTTPMessage); !ok || string(msg.Body) != "body" {
			t.Errorf("body = %#v, want \"body\"", r.env.Message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next did not return")
	}
}

// Receive-direction Layers ignore the option.
func TestLayer_RequestHeaderTimeout_IgnoredOnReceive(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(client, "s", envelope.Receive, WithRequestHeaderTimeout(constDuration(100*time.Millisecond)))
	defer l.Close()
	ch := recvChannel(t, l, 2*time.Second)
	res := nextAsync(ch)
	time.Sleep(500 * time.Millisecond)
	if _, err := server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("Receive Layer response after 500ms: %v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next did not return")
	}
}
