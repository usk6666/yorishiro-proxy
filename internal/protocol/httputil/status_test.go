package httputil

import "testing"

func TestStatusText_KnownCodes(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{StatusContinue, "Continue"},
		{StatusSwitchingProtocols, "Switching Protocols"},
		{StatusOK, "OK"},
		{StatusCreated, "Created"},
		{StatusAccepted, "Accepted"},
		{StatusNoContent, "No Content"},
		{StatusMovedPermanently, "Moved Permanently"},
		{StatusFound, "Found"},
		{StatusNotModified, "Not Modified"},
		{StatusTemporaryRedirect, "Temporary Redirect"},
		{StatusPermanentRedirect, "Permanent Redirect"},
		{StatusBadRequest, "Bad Request"},
		{StatusUnauthorized, "Unauthorized"},
		{StatusForbidden, "Forbidden"},
		{StatusNotFound, "Not Found"},
		{StatusMethodNotAllowed, "Method Not Allowed"},
		{StatusRequestTimeout, "Request Timeout"},
		{StatusRequestEntityTooLarge, "Request Entity Too Large"},
		{StatusTooManyRequests, "Too Many Requests"},
		{StatusInternalServerError, "Internal Server Error"},
		{StatusNotImplemented, "Not Implemented"},
		{StatusBadGateway, "Bad Gateway"},
		{StatusServiceUnavailable, "Service Unavailable"},
		{StatusGatewayTimeout, "Gateway Timeout"},
	}
	for _, tt := range tests {
		if got := StatusText(tt.code); got != tt.want {
			t.Errorf("StatusText(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestStatusText_UnknownCode(t *testing.T) {
	if got := StatusText(999); got != "" {
		t.Errorf("StatusText(999) = %q, want empty string", got)
	}
}

func TestStatusConstants(t *testing.T) {
	// Verify a selection of constants match their expected integer values.
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"StatusOK", StatusOK, 200},
		{"StatusBadRequest", StatusBadRequest, 400},
		{"StatusForbidden", StatusForbidden, 403},
		{"StatusNotFound", StatusNotFound, 404},
		{"StatusInternalServerError", StatusInternalServerError, 500},
		{"StatusBadGateway", StatusBadGateway, 502},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}
