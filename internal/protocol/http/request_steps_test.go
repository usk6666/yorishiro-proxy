package http

import (
	"bufio"
	"bytes"
	"io"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestNormalizeRequestURL(t *testing.T) {
	tests := []struct {
		name       string
		reqURL     string
		reqHost    string
		wantHost   string
		wantScheme string
	}{
		{
			name:       "missing host is set from req.Host",
			reqURL:     "/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "missing scheme defaults to http",
			reqURL:     "//example.com/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "absolute URL preserved",
			reqURL:     "http://example.com/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "https scheme preserved",
			reqURL:     "https://secure.example.com/path",
			reqHost:    "secure.example.com",
			wantHost:   "secure.example.com",
			wantScheme: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.reqURL)
			req := &gohttp.Request{
				URL:  u,
				Host: tt.reqHost,
			}

			normalizeRequestURL(req)

			if req.URL.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", req.URL.Host, tt.wantHost)
			}
			if req.URL.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", req.URL.Scheme, tt.wantScheme)
			}
		})
	}
}

func TestReadAndCaptureRequestBody(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantBody      string
		wantTruncated bool
	}{
		{
			name:          "nil body returns empty result",
			body:          "",
			wantBody:      "",
			wantTruncated: false,
		},
		{
			name:          "small body captured fully",
			body:          "hello world",
			wantBody:      "hello world",
			wantTruncated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *gohttp.Request
			if tt.body == "" {
				req, _ = gohttp.NewRequest("GET", "http://example.com", nil)
			} else {
				req, _ = gohttp.NewRequest("POST", "http://example.com", strings.NewReader(tt.body))
			}

			logger := testutil.DiscardLogger()
			result := readAndCaptureRequestBody(req, logger)

			if tt.body == "" {
				if len(result.recordBody) != 0 {
					t.Errorf("recordBody = %q, want empty", result.recordBody)
				}
			} else {
				if string(result.recordBody) != tt.wantBody {
					t.Errorf("recordBody = %q, want %q", result.recordBody, tt.wantBody)
				}
			}

			if result.truncated != tt.wantTruncated {
				t.Errorf("truncated = %v, want %v", result.truncated, tt.wantTruncated)
			}

			// Verify the request body is re-readable after capture.
			if tt.body != "" {
				rereadBody, _ := io.ReadAll(req.Body)
				if string(rereadBody) != tt.body {
					t.Errorf("re-read body = %q, want %q", rereadBody, tt.body)
				}
			}
		})
	}
}

func TestReadAndCaptureRequestBody_Truncation(t *testing.T) {
	// Create a body larger than MaxBodySize to test truncation.
	bigBody := strings.Repeat("x", int(config.MaxBodySize)+100)
	req, _ := gohttp.NewRequest("POST", "http://example.com", strings.NewReader(bigBody))

	logger := testutil.DiscardLogger()
	result := readAndCaptureRequestBody(req, logger)

	if !result.truncated {
		t.Error("truncated = false, want true for body exceeding MaxBodySize")
	}
	if len(result.recordBody) != int(config.MaxBodySize) {
		t.Errorf("recordBody len = %d, want %d", len(result.recordBody), int(config.MaxBodySize))
	}

	// The req.Body should still contain the full body (not truncated).
	rereadBody, _ := io.ReadAll(req.Body)
	if len(rereadBody) != len(bigBody) {
		t.Errorf("re-read body len = %d, want %d", len(rereadBody), len(bigBody))
	}
}

func TestExtractRawRequest(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		captureStart int
		wantNil      bool
		wantLen      int
	}{
		{
			name:    "nil capture returns nil",
			wantNil: true,
		},
		{
			name:         "captures raw bytes correctly",
			input:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			captureStart: 0,
			wantNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantNil {
				result := extractRawRequest(nil, 0, nil)
				if result != nil {
					t.Errorf("extractRawRequest(nil, 0, nil) = %v, want nil", result)
				}
				return
			}

			capture := &captureReader{r: strings.NewReader(tt.input)}
			reader := bufio.NewReader(capture)

			// Read through the reader to populate the capture buffer.
			buf := make([]byte, len(tt.input))
			io.ReadFull(reader, buf)

			result := extractRawRequest(capture, tt.captureStart, reader)
			if result == nil {
				t.Fatal("extractRawRequest returned nil, want non-nil")
			}
			if string(result) != tt.input {
				t.Errorf("raw request = %q, want %q", result, tt.input)
			}
		})
	}
}

func TestExtractRawRequest_WithOffset(t *testing.T) {
	// Simulate reading two requests from the same connection: the captureStart
	// for the second request is at the end of the first.
	firstReq := "GET /first HTTP/1.1\r\nHost: a.com\r\n\r\n"
	secondReq := "GET /second HTTP/1.1\r\nHost: b.com\r\n\r\n"
	combined := firstReq + secondReq

	capture := &captureReader{r: strings.NewReader(combined)}
	reader := bufio.NewReader(capture)

	// Read the first request.
	buf := make([]byte, len(combined))
	io.ReadFull(reader, buf)

	captureStart := len(firstReq)
	result := extractRawRequest(capture, captureStart, reader)
	if result == nil {
		t.Fatal("extractRawRequest returned nil")
	}
	if string(result) != secondReq {
		t.Errorf("raw second request = %q, want %q", result, secondReq)
	}
}

func TestApplyTransform_NilPipeline(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	originalBody := []byte("original body")

	result := handler.applyTransform(req, originalBody)
	if !bytes.Equal(result, originalBody) {
		t.Errorf("applyTransform with nil pipeline changed body: got %q, want %q", result, originalBody)
	}
}

func TestLogHTTPRequest(t *testing.T) {
	// This is a smoke test to ensure logHTTPRequest doesn't panic.
	logger := testutil.DiscardLogger()
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logHTTPRequest(logger, req, 200, 42)
}
