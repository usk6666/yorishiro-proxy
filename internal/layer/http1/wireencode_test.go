package http1

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// parseReqFixture parses a request from raw and returns both the parsed
// RawRequest and an Envelope populated with HTTPMessage + opaqueHTTP1.
func parseReqFixture(t *testing.T, raw string) *envelope.Envelope {
	t.Helper()
	rawReq, err := parser.ParseRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	bb, body, err := readBodyWithThreshold(rawReq.Body, "", 10<<20, 254<<20)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bb != nil {
		t.Cleanup(func() { _ = bb.Release() })
	}
	// USK-769: populate RawBody after drain so the opaque encoder branch
	// behaves identically to the channel.go production path. USK-772 added
	// RawBodyBuffer to the return tuple; tests below stay in the memory
	// path because no fixture exercises body sizes above DefaultBodySpillThreshold.
	rawReq.RawBody, rawReq.RawBodyBuffer, rawReq.RawBodyTruncated = extractRawBody(rawReq.Body)
	path, rawQuery, authority := parseRequestURI(rawReq.RequestURI, rawReq.Headers)
	msg := &envelope.HTTPMessage{
		Method:     rawReq.Method,
		Scheme:     "http",
		Authority:  authority,
		Path:       path,
		RawQuery:   rawQuery,
		Headers:    rawHeadersToKV(rawReq.Headers),
		Body:       body,
		BodyBuffer: bb,
	}
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawReq:         rawReq,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}
}

func parseRespFixture(t *testing.T, raw string) *envelope.Envelope {
	t.Helper()
	rawResp, err := parser.ParseResponse(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	bb, body, err := readBodyWithThreshold(rawResp.Body, "", 10<<20, 254<<20)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bb != nil {
		t.Cleanup(func() { _ = bb.Release() })
	}
	// USK-769: populate RawBody after drain. USK-772 added RawBodyBuffer.
	rawResp.RawBody, rawResp.RawBodyBuffer, rawResp.RawBodyTruncated = extractRawBody(rawResp.Body)
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: extractStatusReason(rawResp.Status),
		Headers:      rawHeadersToKV(rawResp.Headers),
		Body:         body,
		BodyBuffer:   bb,
	}
	return &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawResp:        rawResp,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}
}

// TestEncodeWireBytes_OpaqueRequest_HeaderAdd verifies that adding a header
// to the HTTPMessage results in that header appearing in the encoded bytes
// while the unchanged headers retain their original OWS / casing.
func TestEncodeWireBytes_OpaqueRequest_HeaderAdd(t *testing.T) {
	env := parseReqFixture(t,
		"GET /a HTTP/1.1\r\nHost:    example.com\r\nAccept: */*\r\n\r\n")
	msg := env.Message.(*envelope.HTTPMessage)
	msg.Headers = append(msg.Headers, envelope.KeyValue{
		Name: "X-Injected", Value: "by-proxy",
	})

	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Contains(out, []byte("X-Injected: by-proxy\r\n")) {
		t.Errorf("output missing injected header:\n%s", out)
	}
	// OWS on unchanged "Host:    example.com" must be preserved.
	if !bytes.Contains(out, []byte("Host:    example.com\r\n")) {
		t.Errorf("unchanged header lost OWS preservation:\n%s", out)
	}
	if !bytes.HasPrefix(out, []byte("GET /a HTTP/1.1\r\n")) {
		t.Errorf("request-line mismatch:\n%s", out)
	}
}

// TestEncodeWireBytes_OpaqueResponse_BodyChange verifies that a body change
// causes Content-Length to be re-stamped and the new body to be appended.
func TestEncodeWireBytes_OpaqueResponse_BodyChange(t *testing.T) {
	env := parseRespFixture(t,
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello")
	msg := env.Message.(*envelope.HTTPMessage)
	msg.Body = []byte("goodbye")

	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Contains(out, []byte("Content-Length: 7\r\n")) {
		t.Errorf("Content-Length not re-stamped:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("goodbye")) {
		t.Errorf("body not appended:\n%s", out)
	}
}

// TestEncodeWireBytes_Synthetic_Request covers the opaque-less fallback.
func TestEncodeWireBytes_Synthetic_Request(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Path:   "/submit",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Flag", Value: "1"},
			},
			Body: []byte("payload"),
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("POST /submit HTTP/1.1\r\n")) {
		t.Errorf("synthetic request-line wrong:\n%s", out)
	}
	if !bytes.Contains(out, []byte("Content-Length: 7\r\n")) {
		t.Errorf("synthetic path missing Content-Length stamp:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("payload")) {
		t.Errorf("synthetic body missing:\n%s", out)
	}
}

// TestEncodeWireBytes_Synthetic_Response covers the opaque-less response
// fallback with both a reason phrase and a non-empty body.
func TestEncodeWireBytes_Synthetic_Response(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       404,
			StatusReason: "Nope",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/plain"},
			},
			Body: []byte("missing"),
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("HTTP/1.1 404 Nope\r\n")) {
		t.Errorf("synthetic status-line wrong:\n%s", out)
	}
	if !bytes.Contains(out, []byte("Content-Length: 7\r\n")) {
		t.Errorf("synthetic path missing Content-Length stamp:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("missing")) {
		t.Errorf("synthetic body missing:\n%s", out)
	}
}

// TestEncodeWireBytes_BufferBackedBodyMaterialized verifies that when the
// opaque path has msg.Body==nil but msg.BodyBuffer holds a materialized
// large body, the encoder returns the full header+body bytes with no
// partial marker. Replaces the pre-USK-631 passthrough path.
func TestEncodeWireBytes_BufferBackedBodyMaterialized(t *testing.T) {
	// 15 MiB body; exceeds the default 10 MiB spill threshold but fits
	// within 254 MiB maxBody.
	largeBody := bytes.Repeat([]byte("X"), 15<<20)
	bb := bodybuf.NewMemory(largeBody)
	defer func() { _ = bb.Release() }()

	rawReq, err := parser.ParseRequest(bufio.NewReader(strings.NewReader(
		"POST /large HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	msg := &envelope.HTTPMessage{
		Method:     "POST",
		Path:       "/large",
		Headers:    rawHeadersToKV(rawReq.Headers),
		BodyBuffer: bb, // buffer-backed body; Body intentionally nil.
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawReq:         rawReq,
			origKV:         cloneKV(msg.Headers),
			origBody:       nil,
			origBodyBuffer: bb,
		},
	}
	// Mutate headers to force the opaque encode path (would otherwise take
	// the zero-copy fast path and return rawReq.RawBytes unchanged).
	msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "X-Injected", Value: "y"})

	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Contains(out, []byte("X-Injected: y\r\n")) {
		t.Errorf("output missing injected header")
	}
	// The full 15 MiB body must be present in the encoded output.
	if !bytes.HasSuffix(out, largeBody) {
		t.Errorf("encoded output does not end with the full body (len=%d, got tail %d bytes)",
			len(out), len(out)-bytes.Index(out, []byte("\r\n\r\n"))-4)
	}
}

// USK-769: end-to-end round-trip — chunked Transfer-Encoding response goes
// through parser then encoder unchanged, and the wire output is byte-for-byte
// identical to the upstream wire input.
func TestEncodeWireBytes_OpaqueResponse_TEChunkedPassthrough(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "two chunks no extension",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
		},
		{
			name: "uppercase hex with extension",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA;name=val\r\n0123456789\r\n0\r\n\r\n",
		},
		{
			name: "with trailers",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Sig: abc\r\n\r\n",
		},
		{
			name: "single zero chunk",
			raw:  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := parseRespFixture(t, tt.raw)
			out, err := EncodeWireBytes(env)
			if err != nil {
				t.Fatalf("EncodeWireBytes: %v", err)
			}
			if !bytes.Equal(out, []byte(tt.raw)) {
				t.Errorf("wire round-trip mismatch:\n got=%q\nwant=%q", out, tt.raw)
			}
		})
	}
}

// USK-769: when only headers change but body stays unchanged, RawBody must
// be re-emitted verbatim (chunk framing intact) alongside the patched
// header section.
func TestEncodeWireBytes_OpaqueResponse_HeaderModified_BodyUnchanged(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: orig\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	env := parseRespFixture(t, raw)
	msg := env.Message.(*envelope.HTTPMessage)
	// Mutate the Server header value (do not alter Transfer-Encoding).
	for i := range msg.Headers {
		if msg.Headers[i].Name == "Server" {
			msg.Headers[i].Value = "patched"
		}
	}

	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	want := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: patched\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	if !bytes.Equal(out, []byte(want)) {
		t.Errorf("header-modified body-unchanged mismatch:\n got=%q\nwant=%q", out, want)
	}
}

// USK-769: regression guard — when the body is mutated, the existing TE→CL
// rewrite must still take effect (wire structure cannot be preserved once
// the body is rewritten).
func TestEncodeWireBytes_OpaqueResponse_BodyModified(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	env := parseRespFixture(t, raw)
	msg := env.Message.(*envelope.HTTPMessage)
	msg.Body = []byte("new-body")

	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if bytes.Contains(out, []byte("Transfer-Encoding")) {
		t.Errorf("TE not removed after body modify:\n%s", out)
	}
	if !bytes.Contains(out, []byte("Content-Length: 8\r\n")) {
		t.Errorf("Content-Length not re-stamped to 8:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("new-body")) {
		t.Errorf("new body not appended:\n%s", out)
	}
}

// USK-769: identity-encoded (Content-Length) responses are also re-emitted
// verbatim under the unchanged-body opaque path.
func TestEncodeWireBytes_OpaqueResponse_IdentityPassthrough(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nhello world"
	env := parseRespFixture(t, raw)
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Equal(out, []byte(raw)) {
		t.Errorf("identity round-trip mismatch:\n got=%q\nwant=%q", out, raw)
	}
}

// TestEncodeWireBytes_NoMutationToOpaque verifies that EncodeWireBytes does
// not modify env.Opaque — especially opaque.rawReq.Headers, which is shared
// with the real channel.Send path.
func TestEncodeWireBytes_NoMutationToOpaque(t *testing.T) {
	env := parseReqFixture(t,
		"GET / HTTP/1.1\r\nHost: example.com\r\nX-Orig: keep\r\n\r\n")
	opaque := env.Opaque.(*opaqueHTTP1)
	beforeLen := len(opaque.rawReq.Headers)
	beforeCL := opaque.rawReq.Headers.Get("Content-Length")

	msg := env.Message.(*envelope.HTTPMessage)
	msg.Body = []byte("some-body-appended-by-plugin")

	if _, err := EncodeWireBytes(env); err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if got := len(opaque.rawReq.Headers); got != beforeLen {
		t.Errorf("opaque.rawReq.Headers len changed: got %d, want %d", got, beforeLen)
	}
	if got := opaque.rawReq.Headers.Get("Content-Length"); got != beforeCL {
		t.Errorf("opaque.rawReq.Headers.Content-Length changed: got %q, want %q", got, beforeCL)
	}
}
