package http1

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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
	body, _, err := readBodyWithThreshold(rawReq.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	path, rawQuery, authority := parseRequestURI(rawReq.RequestURI, rawReq.Headers)
	msg := &envelope.HTTPMessage{
		Method:    rawReq.Method,
		Scheme:    "http",
		Authority: authority,
		Path:      path,
		RawQuery:  rawQuery,
		Headers:   rawHeadersToKV(rawReq.Headers),
		Body:      body,
	}
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawReq:   rawReq,
			origKV:   cloneKV(msg.Headers),
			origBody: cloneBytes(body),
		},
	}
}

func parseRespFixture(t *testing.T, raw string) *envelope.Envelope {
	t.Helper()
	rawResp, err := parser.ParseResponse(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	body, _, err := readBodyWithThreshold(rawResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: extractStatusReason(rawResp.Status),
		Headers:      rawHeadersToKV(rawResp.Headers),
		Body:         body,
	}
	return &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawResp:  rawResp,
			origKV:   cloneKV(msg.Headers),
			origBody: cloneBytes(body),
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

// TestEncodeWireBytes_PassthroughBodyReturnsPartial verifies that when the
// opaque path has a live passthrough bodyReader and msg.Body is nil, the
// encoder returns header-only bytes together with ErrPartialWireBytes.
func TestEncodeWireBytes_PassthroughBodyReturnsPartial(t *testing.T) {
	rawReq, err := parser.ParseRequest(bufio.NewReader(strings.NewReader(
		"POST /large HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	msg := &envelope.HTTPMessage{
		Method:  "POST",
		Path:    "/large",
		Headers: rawHeadersToKV(rawReq.Headers),
		// Body intentionally nil — passthrough mode.
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Opaque: &opaqueHTTP1{
			rawReq:     rawReq,
			origKV:     cloneKV(msg.Headers),
			origBody:   nil, // passthrough
			bodyReader: io.NopCloser(bytes.NewReader([]byte("streamed-body"))),
		},
	}
	// Mutate headers to force the opaque encode path.
	msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "X-Injected", Value: "y"})

	out, err := EncodeWireBytes(env)
	if !errors.Is(err, envelope.ErrPartialWireBytes) {
		t.Fatalf("err = %v, want ErrPartialWireBytes", err)
	}
	if !bytes.Contains(out, []byte("X-Injected: y\r\n")) {
		t.Errorf("partial output missing injected header:\n%s", out)
	}
	// Header-only — must not contain the upstream-delivered streamed body.
	if bytes.Contains(out, []byte("streamed-body")) {
		t.Errorf("partial output must not include live passthrough body")
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
