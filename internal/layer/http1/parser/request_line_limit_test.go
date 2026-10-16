package parser

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// USK-1137 (defect D): browsers send request lines far longer than 8 KiB
// (Chromium url/url_constants.h kMaxURLChars = 2 MiB; Firefox
// network.standard-url.max-length = 1 MiB, both reachable in absolute-form
// through a forward proxy). The request-line cap is 4 MiB — the same budget
// as the header section — and an over-cap request line surfaces as the typed
// ErrRequestLineTooLong so the client-facing Layer can answer 414.

// TestParseRequest_LongRequestLine covers Test Plan #11: request lines of
// 9 KiB (Issue repro D) and of 2 MiB + 64 bytes (Chromium's URL cap) parse
// with RequestURI intact.
func TestParseRequest_LongRequestLine(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{name: "9 KiB origin-form (repro D)", uri: "/?q=" + strings.Repeat("x", 9000)},
		{name: "2 MiB + 64 absolute-form", uri: "https://example.com/?q=" + strings.Repeat("x", 2<<20+64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "GET " + tt.uri + " HTTP/1.1\r\nHost: example.com\r\n\r\n"
			req, err := ParseRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if req.RequestURI != tt.uri {
				t.Errorf("RequestURI is %d bytes, want %d", len(req.RequestURI), len(tt.uri))
			}
			if req.Method != "GET" || req.Proto != "HTTP/1.1" {
				t.Errorf("Method/Proto = %q/%q, want GET/HTTP/1.1", req.Method, req.Proto)
			}
			if got := req.Headers.Get("Host"); got != "example.com" {
				t.Errorf("Host = %q, want example.com", got)
			}
		})
	}
}

// TestParseRequest_RequestLineOverCap_TypedError pins the over-cap request
// line to ErrRequestLineTooLong while an over-cap status line keeps the
// generic error (only the client-facing request side answers 414).
func TestParseRequest_RequestLineOverCap_TypedError(t *testing.T) {
	line := strings.Repeat("x", 4<<20+1)

	_, err := ParseRequest(bufio.NewReader(strings.NewReader("GET /" + line + " HTTP/1.1\r\nHost: x\r\n\r\n")))
	if !errors.Is(err, ErrRequestLineTooLong) {
		t.Errorf("ParseRequest over-cap error = %v, want ErrRequestLineTooLong", err)
	}

	_, err = ParseResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 200 " + line + "\r\n\r\n")))
	if err == nil {
		t.Fatal("ParseResponse over-cap status line: want error, got nil")
	}
	if errors.Is(err, ErrRequestLineTooLong) {
		t.Errorf("ParseResponse over-cap error = %v, must not be ErrRequestLineTooLong", err)
	}
}
