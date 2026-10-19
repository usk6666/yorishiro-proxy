package http1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1079: RFC-001 §9.3 D4 "Raw wins" on HTTP/1.x.

// epipeConn wraps a net.Conn and fails every Write with the EPIPE shape
// the Go net stack produces when the peer has closed.
type epipeConn struct{ net.Conn }

func (c epipeConn) Write([]byte) (int, error) {
	return 0, &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EPIPE)}
}

func rawWinsGET(raw []byte) *envelope.Envelope {
	env := BuildSendEnvelope("GET", "http", "example.com", "/orig", "",
		[]envelope.KeyValue{{Name: "Host", Value: "example.com"}}, nil)
	env.Raw = raw
	env.RawAuthoritative = true
	return env
}

// TestRawWins_StaleSendIsNotReplaySafe (Test Plan #11): a verbatim send
// that hits a stale upstream must not be replayed, even for GET — the
// Message does not describe the bytes, and a replay would duplicate a
// smuggling payload.
func TestRawWins_StaleSendIsNotReplaySafe(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(epipeConn{server}, "conn-raw-wins-stale", envelope.Receive)
	defer l.Close()

	ch := l.OpenExchange()
	err := ch.Send(context.Background(), rawWinsGET([]byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")))
	var stale *StaleUpstreamError
	if !errors.As(err, &stale) {
		t.Fatalf("Send err = %v, want *StaleUpstreamError", err)
	}
	if stale.ReplaySafe {
		t.Error("ReplaySafe = true for a raw-authoritative send; the retry wrapper would re-send the plugin bytes")
	}
}

// TestRawWins_RequestWrittenVerbatim: the upstream-facing Channel writes
// env.Raw verbatim when the marker is set.
func TestRawWins_RequestWrittenVerbatim(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-raw-wins-req", envelope.Receive)
	defer l.Close()

	raw := []byte("POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi")
	ch := l.OpenExchange()
	if err := ch.Send(context.Background(), rawWinsGET(raw)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Read whatever arrives within the deadline so a short (wrong) write
	// surfaces as a byte mismatch rather than a read timeout.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	got, _ := io.ReadAll(io.LimitReader(client, int64(len(raw))))
	if string(got) != string(raw) {
		t.Errorf("wire = %q, want %q", got, raw)
	}
}

// TestRawWins_UpstreamRetiredAfterResponse: after a raw-authoritative
// exchange the upstream Layer must not be reused — the plugin bytes may
// have carried extra requests whose responses are still in flight.
func TestRawWins_UpstreamRetiredAfterResponse(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-raw-wins-retire", envelope.Receive)
	defer l.Close()

	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck before exchange: %v", err)
	}

	ch := l.OpenExchange()
	if err := ch.Send(context.Background(), rawWinsGET([]byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"))); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Upstream answers both pipelined requests.
	go func() {
		br := bufio.NewReader(client)
		_, _ = br.Peek(1)
		_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if m := resp.Message.(*envelope.HTTPMessage); string(m.Body) != "a" {
		t.Errorf("first response body = %q, want %q", m.Body, "a")
	}
	_ = ch.Close()

	if err := l.HealthCheck(); err == nil {
		t.Error("HealthCheck = nil after a raw-authoritative exchange; the next request would read the leftover response")
	}
	if next := l.OpenExchange(); next != nil {
		t.Error("OpenExchange returned a Channel on a retired Layer")
	}
}

// TestRawWins_UnmarkedEnvelopeKeepsUpstreamAlive: the reverse guard — an
// ordinary exchange leaves the Layer reusable.
func TestRawWins_UnmarkedEnvelopeKeepsUpstreamAlive(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-raw-wins-guard", envelope.Receive)
	defer l.Close()

	env := rawWinsGET([]byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
	env.RawAuthoritative = false
	ch := l.OpenExchange()
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}
	go func() {
		br := bufio.NewReader(client)
		_, _ = br.Peek(1)
		_, _ = client.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}
	_ = ch.Close()
	if err := l.HealthCheck(); err != nil {
		t.Errorf("HealthCheck = %v after an ordinary exchange, want nil", err)
	}
}
