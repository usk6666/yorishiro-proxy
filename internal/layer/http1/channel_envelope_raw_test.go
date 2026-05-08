package http1

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-773: Channel-level wire-fidelity tests proving Envelope.Raw is the
// complete wire snapshot (header section + on-wire body section) for both
// chunked and identity bodies.

// TestChannel_EnvelopeRaw_Chunked_Complete_Response verifies that a chunked
// HTTP/1.1 response yields Envelope.Raw == the verbatim upstream wire bytes,
// including chunk-size lines, chunk extensions, trailer, and the terminating
// "0\r\n...\r\n".
func TestChannel_EnvelopeRaw_Chunked_Complete_Response(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	// Hand-crafted chunked body — multiple chunks, mixed-case hex sizes, an
	// extension, and a trailer (mirrors USK-769 chunkedResponseBytes).
	body := "5\r\nhello\r\n" +
		"6;name=val\r\n world\r\n" +
		"A\r\n0123456789\r\n" +
		"0\r\nX-Trailer: yes\r\n\r\n"
	header := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: text/plain\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	resp := header + body
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

	if env.Raw == nil {
		t.Fatal("Envelope.Raw is nil")
	}
	if !bytes.Equal(env.Raw, []byte(resp)) {
		t.Errorf("Envelope.Raw wire mismatch:\n got=%q\nwant=%q", string(env.Raw), resp)
	}

	// Sanity: the chunk framing markers must survive verbatim.
	for _, marker := range []string{
		"5\r\nhello\r\n",
		"6;name=val\r\n",
		"A\r\n0123456789\r\n",
		"0\r\nX-Trailer: yes\r\n\r\n",
	} {
		if !bytes.Contains(env.Raw, []byte(marker)) {
			t.Errorf("Envelope.Raw missing chunk marker %q", marker)
		}
	}
}

// TestChannel_EnvelopeRaw_Chunked_Complete_Request verifies the request-side
// twin of the chunked response test. Chunked requests are rare on the wire
// but legal (RFC 9112 §6.1).
func TestChannel_EnvelopeRaw_Chunked_Complete_Request(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	body := "3\r\nfoo\r\n" +
		"4\r\nbarx\r\n" +
		"0\r\n\r\n"
	header := "POST /upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n"
	req := header + body
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if env.Raw == nil {
		t.Fatal("Envelope.Raw is nil")
	}
	if !bytes.Equal(env.Raw, []byte(req)) {
		t.Errorf("Envelope.Raw wire mismatch:\n got=%q\nwant=%q", string(env.Raw), req)
	}
}

// TestChannel_EnvelopeRaw_Identity_Complete verifies that a Content-Length
// body yields Envelope.Raw = header + identity body bytes.
func TestChannel_EnvelopeRaw_Identity_Complete(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	bodyContent := "hello world"
	req := "POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Length: 11\r\n" +
		"\r\n" + bodyContent
	go func() {
		client.Write([]byte(req))
		client.Close()
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(env.Raw, []byte(req)) {
		t.Errorf("Envelope.Raw wire mismatch:\n got=%q\nwant=%q", string(env.Raw), req)
	}
}

// TestChannel_EnvelopeRaw_NoBody verifies that a bodyless request (no
// Content-Length / no Transfer-Encoding) yields Envelope.Raw equal to the
// header section only — Raw is the wire snapshot, and a wire with no body
// has no body bytes to carry.
func TestChannel_EnvelopeRaw_NoBody(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	req := "GET /healthz HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: probe/1.0\r\n" +
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

	if !bytes.Equal(env.Raw, []byte(req)) {
		t.Errorf("Envelope.Raw wire mismatch:\n got=%q\nwant=%q", string(env.Raw), req)
	}
}

// TestChannel_EnvelopeRaw_HeaderPrefix verifies the contract that
// Envelope.Raw always begins with the parser's header section (RawBytes).
// Combined with the explicit equality assertions in the chunked / identity
// tests above, this gives us a one-line invariant useful for cross-checking
// the projection from many call sites.
func TestChannel_EnvelopeRaw_HeaderPrefix(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Receive)
	defer l.Close()

	header := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	resp := header + "hello"
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

	if !bytes.HasPrefix(env.Raw, []byte(header)) {
		t.Errorf("Envelope.Raw missing header prefix:\n got=%q", string(env.Raw))
	}

	// And the rawResp.RawBytes (kept on Opaque as the header-only source) is
	// still header-only — RawBytes is not promoted, only Envelope.Raw is.
	op := env.Opaque.(*opaqueHTTP1)
	if op.rawResp == nil {
		t.Fatal("rawResp opaque missing")
	}
	if !bytes.Equal(op.rawResp.RawBytes, []byte(header)) {
		t.Errorf("opaque RawBytes mutated: header-only semantics must be preserved\n got=%q\nwant=%q",
			string(op.rawResp.RawBytes), header)
	}
	// Sanity: the body was extracted into rawResp.RawBody.
	if string(op.rawResp.RawBody) != "hello" {
		t.Errorf("opaque RawBody = %q, want %q", string(op.rawResp.RawBody), "hello")
	}
}
