package parser

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// USK-769: tests covering RawBody capture for chunked Transfer-Encoding,
// identity (Content-Length / EOF) bodies, and bodyless messages.

// rawBodyOf reads the body fully and returns the on-wire RawBody bytes via
// the RawBodyProvider interface. Any TrailerProvider and io.Reader EOFs are
// surfaced as test failures.
func rawBodyOf(t *testing.T, body io.Reader) (raw []byte, truncated bool) {
	t.Helper()
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("ReadAll(body) error: %v", err)
	}
	rp, ok := body.(RawBodyProvider)
	if !ok {
		t.Fatalf("body does not implement RawBodyProvider: %T", body)
	}
	return rp.RawBody(), rp.RawBodyTruncated()
}

func assertBytesEqual(t *testing.T, got, want []byte, name string) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s: bytes mismatch\n got=\n%swant=\n%s", name, hex.Dump(got), hex.Dump(want))
	}
}

func TestParseResponse_RawBody_Chunked(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		bodyOnWire string
	}{
		{
			name:       "two chunks",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
		},
		{
			name:       "uppercase hex chunk size",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "A\r\n0123456789\r\nB\r\nABCDEFGHIJK\r\n0\r\n\r\n",
		},
		{
			name:       "lowercase hex chunk size",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "a\r\n0123456789\r\nb\r\nabcdefghijk\r\n0\r\n\r\n",
		},
		{
			name:       "chunk extension preserved",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "5;name=value\r\nhello\r\n0\r\n\r\n",
		},
		{
			name:       "chunked with trailers",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "5\r\nhello\r\n0\r\nX-Trailer: yes\r\n\r\n",
		},
		{
			name:       "single zero chunk only",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "0\r\n\r\n",
		},
		{
			name:       "multiple chunk extensions",
			header:     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			bodyOnWire: "3;a=1;b=2\r\nfoo\r\n4;c=3\r\nbar!\r\n0\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.header + tt.bodyOnWire
			resp, err := ParseResponse(newReader(raw))
			if err != nil {
				t.Fatalf("ParseResponse() error: %v", err)
			}
			gotRaw, truncated := rawBodyOf(t, resp.Body)
			if truncated {
				t.Fatalf("unexpected RawBodyTruncated for body of len %d", len(tt.bodyOnWire))
			}
			assertBytesEqual(t, gotRaw, []byte(tt.bodyOnWire), "RawBody")
		})
	}
}

func TestParseResponse_RawBody_Identity(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "Content-Length 11",
			raw:  "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world",
			want: "hello world",
		},
		{
			name: "Content-Length 0",
			raw:  "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			want: "",
		},
		{
			name: "Content-Length with binary bytes",
			raw:  "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n\x00\x01\x02\x03\x04",
			want: "\x00\x01\x02\x03\x04",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(newReader(tt.raw))
			if err != nil {
				t.Fatalf("ParseResponse() error: %v", err)
			}
			gotRaw, truncated := rawBodyOf(t, resp.Body)
			if truncated {
				t.Fatalf("unexpected RawBodyTruncated")
			}
			assertBytesEqual(t, gotRaw, []byte(tt.want), "RawBody")
		})
	}
}

func TestParseResponse_RawBody_NoBody(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "204 No Content",
			raw:  "HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n",
		},
		{
			name: "304 Not Modified",
			raw:  "HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n",
		},
		{
			name: "100 Continue",
			raw:  "HTTP/1.1 100 Continue\r\n\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(newReader(tt.raw))
			if err != nil {
				t.Fatalf("ParseResponse() error: %v", err)
			}
			gotRaw, truncated := rawBodyOf(t, resp.Body)
			if truncated {
				t.Fatalf("unexpected RawBodyTruncated")
			}
			if len(gotRaw) != 0 {
				t.Errorf("RawBody = %q, want empty", string(gotRaw))
			}
		})
	}
}

func TestParseRequest_RawBody_Chunked(t *testing.T) {
	body := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	raw := "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	gotRaw, truncated := rawBodyOf(t, req.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	assertBytesEqual(t, gotRaw, []byte(body), "RawBody")
}

func TestParseRequest_RawBody_Identity(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	gotRaw, truncated := rawBodyOf(t, req.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	assertBytesEqual(t, gotRaw, []byte("hello"), "RawBody")
}

func TestParseResponse_RawBody_ChunkedWithTrailerPreserved(t *testing.T) {
	// USK-769 + USK-627 interaction: chunk framing + trailers must round-trip.
	body := "5\r\nhello\r\n0\r\nX-Trailer-A: alpha\r\nx-trailer-b: beta\r\n\r\n"
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	gotRaw, truncated := rawBodyOf(t, resp.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	assertBytesEqual(t, gotRaw, []byte(body), "RawBody")
	// Trailers must still be exposed via TrailerProvider.
	tp, ok := resp.Body.(TrailerProvider)
	if !ok {
		t.Fatalf("resp.Body does not implement TrailerProvider: %T", resp.Body)
	}
	trailers := tp.Trailers()
	if len(trailers) != 2 {
		t.Fatalf("trailer count = %d, want 2", len(trailers))
	}
	if trailers[0].Name != "X-Trailer-A" || trailers[0].Value != "alpha" {
		t.Errorf("trailer[0] = %+v, want {X-Trailer-A, alpha}", trailers[0])
	}
	if trailers[1].Name != "x-trailer-b" || trailers[1].Value != "beta" {
		t.Errorf("trailer[1] = %+v, want {x-trailer-b, beta}", trailers[1])
	}
}

func TestParseResponse_RawBody_MaxBodySize_Truncated(t *testing.T) {
	// Build an identity-encoded body just over MaxRawCaptureSize so the
	// captureWriter trips its truncation flag. We use a Content-Length
	// declaration matching the actual payload length so the LimitReader
	// permits the full read.
	const overflow = 1024
	bodyLen := MaxRawCaptureSize + overflow
	header := "HTTP/1.1 200 OK\r\nContent-Length: " +
		// inline strconv.Itoa to avoid importing strconv just for this.
		formatInt(bodyLen) + "\r\n\r\n"
	body := strings.Repeat("X", bodyLen)
	resp, err := ParseResponse(newReader(header + body))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	gotRaw, truncated := rawBodyOf(t, resp.Body)
	if !truncated {
		t.Fatalf("expected RawBodyTruncated=true for body of len %d", bodyLen)
	}
	if len(gotRaw) != MaxRawCaptureSize {
		t.Errorf("RawBody len = %d, want %d", len(gotRaw), MaxRawCaptureSize)
	}
	if !bytes.Equal(gotRaw, []byte(strings.Repeat("X", MaxRawCaptureSize))) {
		t.Errorf("RawBody prefix mismatch (truncation must preserve the leading bytes)")
	}
}

func TestParseResponse_RawBody_ChunkedTruncation(t *testing.T) {
	// One large chunk whose data exceeds MaxRawCaptureSize. RawBody must
	// surface RawBodyTruncated=true; the dechunked semantic body remains
	// the full payload (independent of capture cap).
	const overflow = 1024
	dataLen := MaxRawCaptureSize + overflow
	body := formatHex(dataLen) + "\r\n" + strings.Repeat("Y", dataLen) + "\r\n0\r\n\r\n"
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	semantic, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if len(semantic) != dataLen {
		t.Errorf("semantic body len = %d, want %d", len(semantic), dataLen)
	}
	rp, ok := resp.Body.(RawBodyProvider)
	if !ok {
		t.Fatalf("resp.Body does not implement RawBodyProvider: %T", resp.Body)
	}
	if !rp.RawBodyTruncated() {
		t.Fatal("expected RawBodyTruncated=true for chunked body exceeding MaxRawCaptureSize")
	}
	if len(rp.RawBody()) != MaxRawCaptureSize {
		t.Errorf("RawBody len = %d, want %d", len(rp.RawBody()), MaxRawCaptureSize)
	}
}

// formatInt is a minimal strconv.Itoa replacement to avoid touching
// imports in this file (the rest of parser_test.go already covers strconv
// indirectly).
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// formatHex returns the lowercase hex string for n (used to emit chunk-size
// lines).
func formatHex(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789abcdef"
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n&0xf]
		n >>= 4
	}
	return string(buf[i:])
}
