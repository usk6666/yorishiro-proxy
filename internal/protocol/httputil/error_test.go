package httputil

import (
	"fmt"
	"net"
	gohttp "net/http"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestWriteHTTPError_KnownStatusCodes(t *testing.T) {
	tests := []struct {
		code int
		text string
	}{
		{gohttp.StatusBadRequest, "Bad Request"},
		{gohttp.StatusForbidden, "Forbidden"},
		{gohttp.StatusBadGateway, "Bad Gateway"},
		{gohttp.StatusInternalServerError, "Internal Server Error"},
		{gohttp.StatusServiceUnavailable, "Service Unavailable"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_%s", tt.code, tt.text), func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			logger := testutil.DiscardLogger()

			go WriteHTTPError(client, tt.code, logger)

			buf := make([]byte, 1024)
			n, err := server.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			resp := string(buf[:n])

			expected := fmt.Sprintf("HTTP/1.1 %d %s", tt.code, tt.text)
			if !strings.HasPrefix(resp, expected) {
				t.Errorf("response = %q, want prefix %q", resp, expected)
			}
			if !strings.Contains(resp, "Content-Length: 0") {
				t.Error("response should contain Content-Length: 0")
			}
			if !strings.Contains(resp, "Connection: close") {
				t.Error("response should contain Connection: close")
			}
			if !strings.HasSuffix(resp, "\r\n\r\n") {
				t.Error("response should end with blank line (\\r\\n\\r\\n)")
			}
		})
	}
}

func TestWriteHTTPError_UnknownStatusCode(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	logger := testutil.DiscardLogger()

	go WriteHTTPError(client, 999, logger)

	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	resp := string(buf[:n])

	if !strings.HasPrefix(resp, "HTTP/1.1 999 Unknown") {
		t.Errorf("response = %q, want prefix %q", resp, "HTTP/1.1 999 Unknown")
	}
}

func TestWriteHTTPError_WriteFails_NoError(t *testing.T) {
	// Use a closed pipe to force a write error. WriteHTTPError should
	// log the error at debug level but not panic or return an error.
	server, client := net.Pipe()
	server.Close() // close read end
	defer client.Close()

	logger := testutil.DiscardLogger()

	// This should not panic.
	WriteHTTPError(client, gohttp.StatusBadGateway, logger)
}
