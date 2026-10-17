package parser

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// USK-1181: ParseRequestWithOptions must hand back the request-head bytes it
// consumed before failing, so the proxy can record what a client sent when
// it closes the connection before an Envelope exists.

// parseOverPipeWithDeadline writes sent to a net.Pipe, stalls, and parses
// the server side with a read deadline of d.
func parseOverPipeWithDeadline(t *testing.T, sent string, d time.Duration, opts ParseOptions) (*RawRequest, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write([]byte(sent)) }()
	if err := server.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	return ParseRequestWithOptions(bufio.NewReader(server), opts)
}

func asPartial(t *testing.T, err error) *PartialRequestError {
	t.Helper()
	if err == nil {
		t.Fatal("ParseRequestWithOptions err = nil, want a parse error")
	}
	var perr *PartialRequestError
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v (%T), want *PartialRequestError", err, err)
	}
	return perr
}

func TestParseRequestWithOptions_PartialRequestError_HeaderDeadline(t *testing.T) {
	const sent = "GET /p?q=1 HTTP/1.1\r\nHost: example.com\r\nX-Pa"
	req, err := parseOverPipeWithDeadline(t, sent, 200*time.Millisecond, ParseOptions{})
	if req != nil {
		t.Fatalf("req = %+v, want nil on error", req)
	}
	perr := asPartial(t, err)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("errors.Is(err, os.ErrDeadlineExceeded) = false; err = %v", err)
	}
	if string(perr.Raw) != sent {
		t.Errorf("Raw = %q, want %q", perr.Raw, sent)
	}
	if perr.Truncated {
		t.Error("Truncated = true, want false")
	}
	if !perr.RequestLineComplete {
		t.Error("RequestLineComplete = false, want true")
	}
	if perr.Method != "GET" || perr.RequestURI != "/p?q=1" || perr.Proto != "HTTP/1.1" {
		t.Errorf("request line = %q %q %q, want GET /p?q=1 HTTP/1.1", perr.Method, perr.RequestURI, perr.Proto)
	}
	if len(perr.Headers) != 1 || perr.Headers[0].Name != "Host" || perr.Headers[0].Value != "example.com" {
		t.Errorf("Headers = %+v, want only Host: example.com (the cut fragment excluded)", perr.Headers)
	}
}

func TestParseRequestWithOptions_PartialRequestError_RequestLineDeadline(t *testing.T) {
	const sent = "GET /pa"
	_, err := parseOverPipeWithDeadline(t, sent, 200*time.Millisecond, ParseOptions{})
	perr := asPartial(t, err)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("errors.Is(err, os.ErrDeadlineExceeded) = false; err = %v", err)
	}
	if string(perr.Raw) != sent {
		t.Errorf("Raw = %q, want %q", perr.Raw, sent)
	}
	if perr.RequestLineComplete {
		t.Error("RequestLineComplete = true for a cut request line")
	}
	if perr.Method != "" || perr.RequestURI != "" || perr.Proto != "" {
		t.Errorf("request line fields = %q %q %q, want empty for an incomplete line", perr.Method, perr.RequestURI, perr.Proto)
	}
}

func TestParseRequestWithOptions_PartialRequestError_RequestLineTooLong(t *testing.T) {
	sent := "GET /" + strings.Repeat("x", maxRequestLineSize) + " HTTP/1.1\r\nHost: example.com\r\n\r\n"
	const capBytes = 1024
	_, err := ParseRequestWithOptions(newReader(sent), ParseOptions{MaxRawCapture: capBytes})
	perr := asPartial(t, err)
	if !errors.Is(err, ErrRequestLineTooLong) {
		t.Errorf("errors.Is(err, ErrRequestLineTooLong) = false; err = %v", err)
	}
	if string(perr.Raw) != sent[:capBytes] {
		t.Errorf("Raw = %d bytes (prefix ok=%v), want the first %d bytes sent",
			len(perr.Raw), strings.HasPrefix(sent, string(perr.Raw)), capBytes)
	}
	if !perr.Truncated {
		t.Error("Truncated = false, want true (request line exceeds the capture cap)")
	}
	if perr.RequestLineComplete {
		t.Error("RequestLineComplete = true for an over-limit request line")
	}
}

func TestParseRequestWithOptions_HeaderSectionTooLarge(t *testing.T) {
	const line = "GET / HTTP/1.1\r\n"
	var count strings.Builder
	count.WriteString(line)
	for i := 0; i <= maxHeaderCount; i++ {
		count.WriteString("X: y\r\n")
	}
	count.WriteString("\r\n")

	cases := []struct {
		name string
		sent string
	}{
		{name: "count", sent: count.String()},
		{name: "line", sent: line + "X-Big: " + strings.Repeat("b", maxHeaderSize) + "\r\n\r\n"},
		{name: "total", sent: line +
			"X-A: " + strings.Repeat("a", maxHeaderSize/2) + "\r\n" +
			"X-B: " + strings.Repeat("b", maxHeaderSize/2) + "\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const capBytes = 4096
			_, err := ParseRequestWithOptions(newReader(tc.sent), ParseOptions{MaxRawCapture: capBytes})
			perr := asPartial(t, err)
			if !errors.Is(err, ErrHeaderSectionTooLarge) {
				t.Errorf("errors.Is(err, ErrHeaderSectionTooLarge) = false; err = %v", err)
			}
			if errors.Is(err, ErrRequestLineTooLong) {
				t.Errorf("header-section error also matches ErrRequestLineTooLong: %v", err)
			}
			if string(perr.Raw) != tc.sent[:capBytes] {
				t.Errorf("Raw = %d bytes, want the first %d bytes sent", len(perr.Raw), capBytes)
			}
			if !perr.Truncated {
				t.Error("Truncated = false, want true")
			}
			if !perr.RequestLineComplete || perr.Method != "GET" || perr.RequestURI != "/" {
				t.Errorf("request line = complete:%v %q %q, want complete GET /", perr.RequestLineComplete, perr.Method, perr.RequestURI)
			}
		})
	}
}

// The response side keeps its own error taxonomy: an over-limit response
// header section is an upstream fault, not a 431 condition.
func TestParseResponse_HeaderSectionTooLarge_NotRequestSentinel(t *testing.T) {
	sent := "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("b", maxHeaderSize) + "\r\n\r\n"
	_, err := ParseResponse(newReader(sent))
	if err == nil {
		t.Fatal("ParseResponse err = nil, want an error")
	}
	if errors.Is(err, ErrHeaderSectionTooLarge) {
		t.Errorf("response error matches ErrHeaderSectionTooLarge: %v", err)
	}
}

func TestParseRequestWithOptions_PartialRequestError_EOF(t *testing.T) {
	cases := []struct {
		name    string
		sent    string
		wantRaw string
	}{
		{name: "empty", sent: "", wantRaw: ""},
		{name: "mid headers", sent: "GET / HTTP/1.1\r\nHost", wantRaw: "GET / HTTP/1.1\r\nHost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest(newReader(tc.sent))
			perr := asPartial(t, err)
			if !errors.Is(err, io.EOF) {
				t.Errorf("errors.Is(err, io.EOF) = false; err = %v", err)
			}
			if string(perr.Raw) != tc.wantRaw {
				t.Errorf("Raw = %q, want %q", perr.Raw, tc.wantRaw)
			}
		})
	}
}
