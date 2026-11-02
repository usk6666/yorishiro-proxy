package parser

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"time"
)

// rawTapResult collects the raw tap output of one body.
type rawTapResult struct {
	buf bytes.Buffer
}

func (r *rawTapResult) tap(p []byte) { r.buf.Write(p) }

// readWithin reads one chunk from r, failing the test when it does not
// return within 5s.
func readWithin(t *testing.T, r io.Reader, p []byte) (int, error) {
	t.Helper()
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := r.Read(p)
		ch <- res{n, err}
	}()
	select {
	case got := <-ch:
		return got.n, got.err
	case <-time.After(5 * time.Second):
		t.Fatal("body Read did not return within 5s")
		return 0, nil
	}
}

// TestRawTap_ChunkedIncremental: the raw tap sees the exact wire bytes of
// each chunk — size line with its extension, data, CRLF — as soon as that
// chunk is read, before the upstream has sent the rest (USK-1409 T2). The
// fixture is RFC 9112 §7.1 chunked coding with a chunk-ext (§7.1.1) and a
// trailer section (§7.1.2).
func TestRawTap_ChunkedIncremental(t *testing.T) {
	const (
		head   = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Digest\r\n\r\n"
		chunk1 = "5;ext=1\r\nhello\r\n"
		rest   = "6;name=\"v\"\r\n world\r\n0\r\nX-Digest: abc\r\n\r\n"
	)
	pr, pw := io.Pipe()
	defer pr.Close()
	gate := make(chan struct{})
	go func() {
		_, _ = pw.Write([]byte(head + chunk1))
		<-gate
		_, _ = pw.Write([]byte(rest))
		_ = pw.Close()
	}()

	resp, err := ParseResponseWithOptions(bufio.NewReader(pr), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseResponseWithOptions: %v", err)
	}
	setter, ok := resp.Body.(RawTapSetter)
	if !ok {
		t.Fatalf("chunked body reader %T does not implement RawTapSetter", resp.Body)
	}
	var got rawTapResult
	setter.SetRawTap(got.tap)

	p := make([]byte, 64)
	n, err := readWithin(t, resp.Body, p)
	if err != nil || string(p[:n]) != "hello" {
		t.Fatalf("first Read = %q, %v; want \"hello\", nil", p[:n], err)
	}
	if got.buf.String() != chunk1 {
		t.Fatalf("raw tap before the rest was sent = %q, want %q", got.buf.String(), chunk1)
	}

	close(gate)
	var semantic bytes.Buffer
	semantic.Write(p[:n])
	for {
		n, err := readWithin(t, resp.Body, p)
		semantic.Write(p[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if semantic.String() != "hello world" {
		t.Errorf("semantic body = %q, want %q", semantic.String(), "hello world")
	}
	if want := chunk1 + rest; got.buf.String() != want {
		t.Errorf("raw tap = %q, want byte-identical %q", got.buf.String(), want)
	}
}

// TestRawTap_ContentLengthIncremental: identity bodies tap the same bytes
// Read returns, as they arrive.
func TestRawTap_ContentLengthIncremental(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	gate := make(chan struct{})
	go func() {
		_, _ = pw.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst"))
		<-gate
		_, _ = pw.Write([]byte("-last"))
	}()

	resp, err := ParseResponseWithOptions(bufio.NewReader(pr), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseResponseWithOptions: %v", err)
	}
	setter, ok := resp.Body.(RawTapSetter)
	if !ok {
		t.Fatalf("identity body reader %T does not implement RawTapSetter", resp.Body)
	}
	var got rawTapResult
	setter.SetRawTap(got.tap)

	p := make([]byte, 64)
	n, err := readWithin(t, resp.Body, p)
	if err != nil || string(p[:n]) != "first" {
		t.Fatalf("first Read = %q, %v; want \"first\", nil", p[:n], err)
	}
	if got.buf.String() != "first" {
		t.Fatalf("raw tap before the rest was sent = %q, want %q", got.buf.String(), "first")
	}
	close(gate)
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got.buf.String() != "first-last" {
		t.Errorf("raw tap = %q, want %q", got.buf.String(), "first-last")
	}
}

// TestRawTap_StopsCapture: bytes read after the tap is installed are not
// accumulated in RawBody (the tap owns them); bytes captured before stay.
func TestRawTap_StopsCapture(t *testing.T) {
	resp, err := ParseResponseWithOptions(bufio.NewReader(bytes.NewReader([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef"))), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseResponseWithOptions: %v", err)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(resp.Body, p); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	var got rawTapResult
	resp.Body.(RawTapSetter).SetRawTap(got.tap)
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(resp.Body.(RawBodyProvider).RawBody()) != "ab" {
		t.Errorf("RawBody = %q, want the pre-tap prefix %q", resp.Body.(RawBodyProvider).RawBody(), "ab")
	}
	if got.buf.String() != "cdef" {
		t.Errorf("raw tap = %q, want %q", got.buf.String(), "cdef")
	}
}
