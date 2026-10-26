package http1

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1185: the header bound (request_timeout_ms) and the idle bound
// (client_idle_timeout_ms) are independent; either can be switched off.

// disabledBound is a phase bound that is switched off.
func disabledBound() (time.Duration, bool) { return 0, false }

// shortTrickled is a complete request head that takes ~1.4s to trickle at
// 40ms/byte — well past every short bound below.
const shortTrickled = "GET /t HTTP/1.1\r\nHost: a.example\r\n\r\n"

// Header disabled: a head trickled far past any short bound still parses,
// while the idle bound stays armed.
func TestLayer_RequestHeaderTimeout_HeaderDisabledTrickledHeadParses(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(disabledBound),
		WithKeepAliveIdleTimeout(constDuration(300*time.Millisecond)))
	defer l.Close()

	done := make(chan struct{})
	defer close(done)
	go trickle(client, []byte(shortTrickled), 40*time.Millisecond, done)

	ch := recvChannel(t, l, 2*time.Second)
	select {
	case r := <-nextAsync(ch):
		if r.err != nil {
			t.Fatalf("trickled head with the header bound disabled: %v", r.err)
		}
		if msg, ok := r.env.Message.(*envelope.HTTPMessage); !ok || msg.Path != "/t" {
			t.Errorf("message = %#v, want path /t", r.env.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Next did not return")
	}
}

// Header disabled + idle enabled: the first-byte wait is the idle bound
// alone, so a silent client is closed at ~300ms.
func TestLayer_RequestHeaderTimeout_HeaderDisabledIdleBoundStillApplies(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(disabledBound),
		WithKeepAliveIdleTimeout(constDuration(300*time.Millisecond)))
	defer l.Close()

	ch := recvChannel(t, l, 2*time.Second)
	start := time.Now()
	select {
	case r := <-nextAsync(ch):
		el := time.Since(start)
		if r.err == nil {
			t.Fatal("Next returned an envelope from a silent client")
		}
		if el < 200*time.Millisecond {
			t.Errorf("idle client closed after %v, want ~300ms idle bound", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent client still open after 3s; the 300ms idle bound did not apply with the header bound disabled")
	}
}

// Idle disabled: a silent client is not closed by the header bound, and
// its later request — sent promptly — parses.
func TestLayer_RequestHeaderTimeout_IdleDisabledSilentClientStaysOpen(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(constDuration(200*time.Millisecond)),
		WithKeepAliveIdleTimeout(disabledBound))
	defer l.Close()

	ch := recvChannel(t, l, 2*time.Second)
	res := nextAsync(ch)
	select {
	case r := <-res:
		t.Fatalf("silent client closed with the idle bound disabled: env=%v err=%v", r.env, r.err)
	case <-time.After(1 * time.Second):
	}
	if _, err := client.Write([]byte("GET /late HTTP/1.1\r\nHost: a.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("request after a long idle gap: %v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Next did not return")
	}
}

// Idle disabled keeps the header bound: once the first byte arrives, a
// trickled head is still cut off at ~200ms.
func TestLayer_RequestHeaderTimeout_IdleDisabledHeaderBoundStillApplies(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "s", envelope.Send,
		WithRequestHeaderTimeout(constDuration(200*time.Millisecond)),
		WithKeepAliveIdleTimeout(disabledBound))
	defer l.Close()

	done := make(chan struct{})
	defer close(done)
	go trickle(client, []byte(slowRequest), 50*time.Millisecond, done)

	ch := recvChannel(t, l, 2*time.Second)
	select {
	case r := <-nextAsync(ch):
		if !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Errorf("Next error = %v, want one wrapping os.ErrDeadlineExceeded", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("trickled request not bounded with the idle bound disabled")
	}
}
