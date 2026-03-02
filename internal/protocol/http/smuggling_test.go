package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestCheckRequestSmuggling_CLTEConflict(t *testing.T) {
	tests := []struct {
		name           string
		rawRequest     string
		wantCLTE       bool
		wantAmbiguous  bool
		wantWarnings   bool
		warnSubstrings []string
	}{
		{
			name:         "normal GET without body headers",
			rawRequest:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantCLTE:     false,
			wantWarnings: false,
		},
		{
			name:         "normal POST with Content-Length only",
			rawRequest:   "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
			wantCLTE:     false,
			wantWarnings: false,
		},
		{
			name:         "normal POST with Transfer-Encoding chunked only",
			rawRequest:   "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantCLTE:     false,
			wantWarnings: false,
		},
		{
			name:           "CL/TE conflict - both headers present",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantCLTE:       true,
			wantWarnings:   true,
			warnSubstrings: []string{"Content-Length", "Transfer-Encoding", "CL/TE"},
		},
		{
			name:           "CL/TE conflict - TE before CL",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantCLTE:       true,
			wantWarnings:   true,
			warnSubstrings: []string{"CL/TE"},
		},
		{
			name:           "CL/TE conflict - case insensitive",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantCLTE:       true,
			wantWarnings:   true,
			warnSubstrings: []string{"CL/TE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.rawRequest))
			logger := testutil.DiscardLogger()

			flags := checkRequestSmuggling(reader, logger)

			if flags.CLTEConflict != tt.wantCLTE {
				t.Errorf("CLTEConflict = %v, want %v", flags.CLTEConflict, tt.wantCLTE)
			}
			if flags.AmbiguousTE != tt.wantAmbiguous {
				t.Errorf("AmbiguousTE = %v, want %v", flags.AmbiguousTE, tt.wantAmbiguous)
			}
			if flags.hasWarnings() != tt.wantWarnings {
				t.Errorf("hasWarnings() = %v, want %v (warnings: %v)", flags.hasWarnings(), tt.wantWarnings, flags.Warnings)
			}

			for _, substr := range tt.warnSubstrings {
				found := false
				for _, w := range flags.Warnings {
					if strings.Contains(w, substr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no warning containing %q found in %v", substr, flags.Warnings)
				}
			}

			// Verify that ReadRequest still works after peek-based detection.
			reader2 := bufio.NewReader(strings.NewReader(tt.rawRequest))
			checkRequestSmuggling(reader2, logger)
			req, err := gohttp.ReadRequest(reader2)
			if err != nil {
				// Some smuggling payloads may cause ReadRequest to fail.
				// The important thing is checkRequestSmuggling doesn't consume bytes.
				return
			}
			if req.Method == "" {
				t.Error("ReadRequest returned empty method after smuggling check")
			}
		})
	}
}

func TestCheckRequestSmuggling_AmbiguousTE(t *testing.T) {
	tests := []struct {
		name           string
		rawRequest     string
		wantAmbiguous  bool
		warnSubstrings []string
	}{
		{
			name:          "standard chunked TE",
			rawRequest:    "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantAmbiguous: false,
		},
		{
			name:           "non-standard TE value",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: xchunked\r\n\r\n",
			wantAmbiguous:  true,
			warnSubstrings: []string{"non-standard value"},
		},
		{
			name:           "TE with trailing whitespace",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked \r\n\r\n",
			wantAmbiguous:  true,
			warnSubstrings: []string{"trailing whitespace"},
		},
		{
			name:           "TE with space before colon",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\n\r\n",
			wantAmbiguous:  true,
			warnSubstrings: []string{"unexpected character before colon"},
		},
		{
			name:           "multiple TE headers",
			rawRequest:     "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
			wantAmbiguous:  true,
			warnSubstrings: []string{"multiple Transfer-Encoding"},
		},
		{
			name:          "TE identity (standard)",
			rawRequest:    "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: identity\r\n\r\n",
			wantAmbiguous: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.rawRequest))
			logger := testutil.DiscardLogger()

			flags := checkRequestSmuggling(reader, logger)

			if flags.AmbiguousTE != tt.wantAmbiguous {
				t.Errorf("AmbiguousTE = %v, want %v (warnings: %v)", flags.AmbiguousTE, tt.wantAmbiguous, flags.Warnings)
			}

			for _, substr := range tt.warnSubstrings {
				found := false
				for _, w := range flags.Warnings {
					if strings.Contains(w, substr) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no warning containing %q found in %v", substr, flags.Warnings)
				}
			}
		})
	}
}

func TestPeekHeaders(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantNil    bool
		wantPrefix string
	}{
		{
			name:       "normal request with headers",
			input:      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody",
			wantPrefix: "GET / HTTP/1.1\r\nHost: example.com",
		},
		{
			name:       "request with multiple headers",
			input:      "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
			wantPrefix: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5",
		},
		{
			name:    "empty input",
			input:   "",
			wantNil: true,
		},
		{
			name:       "no header terminator - returns partial data",
			input:      "GET / HTTP/1.1\r\nHost: example.com",
			wantPrefix: "GET / HTTP/1.1\r\nHost: example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			result := peekHeaders(reader)

			if tt.wantNil {
				if result != nil {
					t.Errorf("peekHeaders() = %q, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("peekHeaders() returned nil, want non-nil")
			}

			if !strings.HasPrefix(string(result), tt.wantPrefix) {
				t.Errorf("peekHeaders() = %q, want prefix %q", result, tt.wantPrefix)
			}
		})
	}
}

func TestContainsHeader(t *testing.T) {
	tests := []struct {
		name       string
		headers    string
		headerName string
		want       bool
	}{
		{
			name:       "header present",
			headers:    "GET / HTTP/1.1\r\ncontent-length: 5\r\n",
			headerName: "content-length",
			want:       true,
		},
		{
			name:       "header not present",
			headers:    "GET / HTTP/1.1\r\nhost: example.com\r\n",
			headerName: "content-length",
			want:       false,
		},
		{
			name:       "header name in value should not match",
			headers:    "GET / HTTP/1.1\r\nx-info: content-length is 5\r\n",
			headerName: "content-length",
			want:       false,
		},
		{
			name:       "multiple headers present",
			headers:    "GET / HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n",
			headerName: "transfer-encoding",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsHeader([]byte(tt.headers), tt.headerName)
			if got != tt.want {
				t.Errorf("containsHeader(%q) = %v, want %v", tt.headerName, got, tt.want)
			}
		})
	}
}

func TestSmugglingFlags_HasWarnings(t *testing.T) {
	tests := []struct {
		name  string
		flags smugglingFlags
		want  bool
	}{
		{
			name:  "no warnings",
			flags: smugglingFlags{},
			want:  false,
		},
		{
			name:  "with warnings",
			flags: smugglingFlags{Warnings: []string{"test warning"}},
			want:  true,
		},
		{
			name:  "empty warnings slice",
			flags: smugglingFlags{Warnings: []string{}},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.hasWarnings()
			if got != tt.want {
				t.Errorf("hasWarnings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSmugglingTags(t *testing.T) {
	tests := []struct {
		name  string
		flags *smugglingFlags
		want  map[string]string
	}{
		{
			name:  "nil flags",
			flags: nil,
			want:  nil,
		},
		{
			name:  "no warnings",
			flags: &smugglingFlags{},
			want:  nil,
		},
		{
			name: "CL/TE conflict",
			flags: &smugglingFlags{
				CLTEConflict: true,
				Warnings:     []string{"CL/TE conflict detected"},
			},
			want: map[string]string{
				"smuggling:cl_te_conflict": "true",
				"smuggling:warnings":       "CL/TE conflict detected",
			},
		},
		{
			name: "ambiguous TE",
			flags: &smugglingFlags{
				AmbiguousTE: true,
				Warnings:    []string{"ambiguous TE value"},
			},
			want: map[string]string{
				"smuggling:ambiguous_te": "true",
				"smuggling:warnings":     "ambiguous TE value",
			},
		},
		{
			name: "both flags",
			flags: &smugglingFlags{
				CLTEConflict: true,
				AmbiguousTE:  true,
				Warnings:     []string{"warning 1", "warning 2"},
			},
			want: map[string]string{
				"smuggling:cl_te_conflict": "true",
				"smuggling:ambiguous_te":   "true",
				"smuggling:warnings":       "warning 1; warning 2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smugglingTags(tt.flags)

			if tt.want == nil {
				if got != nil {
					t.Errorf("smugglingTags() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("smugglingTags() returned nil, want non-nil")
			}

			for key, wantVal := range tt.want {
				gotVal, ok := got[key]
				if !ok {
					t.Errorf("missing key %q", key)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("tag[%q] = %q, want %q", key, gotVal, wantVal)
				}
			}

			if len(got) != len(tt.want) {
				t.Errorf("got %d tags, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestLogSmugglingWarnings(t *testing.T) {
	t.Run("no warnings does not log", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		flags := &smugglingFlags{}
		logSmugglingWarnings(logger, flags, nil)

		if buf.Len() > 0 {
			t.Errorf("expected no log output, got: %s", buf.String())
		}
	})

	t.Run("warnings are logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		flags := &smugglingFlags{
			CLTEConflict: true,
			Warnings:     []string{"CL/TE conflict detected"},
		}
		req := &gohttp.Request{
			Method: "POST",
		}
		logSmugglingWarnings(logger, flags, req)

		output := buf.String()
		if !strings.Contains(output, "smuggling") {
			t.Errorf("log output does not contain 'smuggling': %s", output)
		}
		if !strings.Contains(output, "CL/TE conflict") {
			t.Errorf("log output does not contain warning message: %s", output)
		}
	})

	t.Run("nil request is handled gracefully", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		flags := &smugglingFlags{
			Warnings: []string{"test warning"},
		}
		logSmugglingWarnings(logger, flags, nil)

		if buf.Len() == 0 {
			t.Error("expected log output for warning")
		}
	})
}

func TestCheckAmbiguousTE(t *testing.T) {
	tests := []struct {
		name          string
		headerBytes   string
		wantAmbiguous bool
		wantCount     int // minimum expected number of warnings
	}{
		{
			name:          "standard chunked",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n",
			wantAmbiguous: false,
			wantCount:     0,
		},
		{
			name:          "non-standard value xchunked",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding: xchunked\r\n",
			wantAmbiguous: true,
			wantCount:     1,
		},
		{
			name:          "trailing tab in value",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\t\r\n",
			wantAmbiguous: true,
			wantCount:     1,
		},
		{
			name:          "space before colon",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n",
			wantAmbiguous: true,
			wantCount:     1,
		},
		{
			name:          "duplicate TE headers",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
			wantAmbiguous: true,
			wantCount:     1,
		},
		{
			name:          "empty TE value",
			headerBytes:   "GET / HTTP/1.1\r\nTransfer-Encoding:\r\n",
			wantAmbiguous: false,
			wantCount:     0,
		},
		{
			name:          "transfer-encoding in header value should not match",
			headerBytes:   "GET / HTTP/1.1\r\nX-Transfer-Encoding: chunked\r\n",
			wantAmbiguous: false,
			wantCount:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &smugglingFlags{}
			checkAmbiguousTE([]byte(tt.headerBytes), flags)

			if flags.AmbiguousTE != tt.wantAmbiguous {
				t.Errorf("AmbiguousTE = %v, want %v (warnings: %v)", flags.AmbiguousTE, tt.wantAmbiguous, flags.Warnings)
			}

			if len(flags.Warnings) < tt.wantCount {
				t.Errorf("got %d warnings, want at least %d: %v", len(flags.Warnings), tt.wantCount, flags.Warnings)
			}
		})
	}
}

// TestReadRequestAfterSmugglingCheck verifies that ReadRequest can still
// correctly parse requests after checkRequestSmuggling has peeked at the
// raw header bytes. This ensures no data is consumed by the detection.
func TestReadRequestAfterSmugglingCheck(t *testing.T) {
	tests := []struct {
		name       string
		rawRequest string
		wantMethod string
		wantPath   string
		wantHost   string
	}{
		{
			name:       "simple GET",
			rawRequest: "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "GET",
			wantPath:   "/test",
			wantHost:   "example.com",
		},
		{
			name:       "POST with CL",
			rawRequest: "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
			wantMethod: "POST",
			wantPath:   "/api",
			wantHost:   "example.com",
		},
		{
			name:       "request with CL/TE conflict",
			rawRequest: "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantMethod: "POST",
			wantPath:   "/",
			wantHost:   "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.rawRequest))
			logger := testutil.DiscardLogger()

			// Run smuggling check first.
			checkRequestSmuggling(reader, logger)

			// Now ReadRequest should still work.
			req, err := gohttp.ReadRequest(reader)
			if err != nil {
				t.Fatalf("ReadRequest after smuggling check: %v", err)
			}

			if req.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", req.Method, tt.wantMethod)
			}
			if req.URL.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", req.URL.Path, tt.wantPath)
			}
			if req.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", req.Host, tt.wantHost)
			}
		})
	}
}

// TestSmugglingDetection_EndToEnd_HTTP tests the full HTTP proxy flow with
// smuggling detection, verifying that normal requests are forwarded correctly
// and sessions are recorded without smuggling tags.
func TestSmugglingDetection_EndToEnd_HTTP(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Send a normal request (no smuggling).
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}

	// Wait for session recording.
	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}

	// Normal request should have no tags.
	if entries[0].Session.Tags != nil {
		t.Errorf("expected nil tags for normal request, got %v", entries[0].Session.Tags)
	}
}

// TestSmugglingDetection_DuplicateCL_DifferentValues tests that Go's
// ReadRequest rejects requests with multiple Content-Length headers containing
// different values (RFC 7230 Section 3.3.2).
func TestSmugglingDetection_DuplicateCL_DifferentValues(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n"

	reader := bufio.NewReader(strings.NewReader(raw))
	logger := testutil.DiscardLogger()

	// Smuggling check runs first.
	checkRequestSmuggling(reader, logger)

	// Go's ReadRequest should reject this.
	_, err := gohttp.ReadRequest(reader)
	if err == nil {
		t.Fatal("expected ReadRequest to reject duplicate CL with different values")
	}

	if !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("error = %q, expected to mention Content-Length", err.Error())
	}
}

// TestSmugglingDetection_DuplicateCL_SameValues tests that Go's ReadRequest
// accepts requests with multiple Content-Length headers when all values match.
func TestSmugglingDetection_DuplicateCL_SameValues(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"

	reader := bufio.NewReader(strings.NewReader(raw))
	logger := testutil.DiscardLogger()

	checkRequestSmuggling(reader, logger)

	req, err := gohttp.ReadRequest(reader)
	if err != nil {
		t.Fatalf("ReadRequest should accept duplicate CL with same values: %v", err)
	}

	if req.ContentLength != 5 {
		t.Errorf("ContentLength = %d, want 5", req.ContentLength)
	}
}

// TestSmugglingDetection_GoStdlib_CLTE_Handling verifies Go's behavior when
// both CL and TE are present: TE takes precedence, CL is removed from headers.
func TestSmugglingDetection_GoStdlib_CLTE_Handling(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

	reader := bufio.NewReader(strings.NewReader(raw))
	logger := testutil.DiscardLogger()

	flags := checkRequestSmuggling(reader, logger)

	// Should detect the CL/TE conflict.
	if !flags.CLTEConflict {
		t.Error("expected CLTEConflict = true")
	}

	// ReadRequest should still succeed (Go handles this).
	req, err := gohttp.ReadRequest(reader)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	// Go should prioritize TE and remove CL.
	if req.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1 (TE takes priority)", req.ContentLength)
	}

	// Content-Length header should be removed by Go.
	if cl := req.Header.Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length header = %q, want empty (removed by Go)", cl)
	}

	// TransferEncoding should be set to chunked.
	if len(req.TransferEncoding) != 1 || req.TransferEncoding[0] != "chunked" {
		t.Errorf("TransferEncoding = %v, want [chunked]", req.TransferEncoding)
	}

	// Body should be readable (de-chunked by Go).
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}
