package httputil

import (
	gohttp "net/http"
	"testing"
)

func TestStatusText_KnownCodes(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{StatusContinue, "Continue"},
		{StatusSwitchingProtocols, "Switching Protocols"},
		{StatusProcessing, "Processing"},
		{StatusEarlyHints, "Early Hints"},
		{StatusOK, "OK"},
		{StatusCreated, "Created"},
		{StatusAccepted, "Accepted"},
		{StatusNonAuthoritativeInfo, "Non-Authoritative Information"},
		{StatusNoContent, "No Content"},
		{StatusResetContent, "Reset Content"},
		{StatusPartialContent, "Partial Content"},
		{StatusMultiStatus, "Multi-Status"},
		{StatusAlreadyReported, "Already Reported"},
		{StatusIMUsed, "IM Used"},
		{StatusMultipleChoices, "Multiple Choices"},
		{StatusMovedPermanently, "Moved Permanently"},
		{StatusFound, "Found"},
		{StatusSeeOther, "See Other"},
		{StatusNotModified, "Not Modified"},
		{StatusUseProxy, "Use Proxy"},
		{StatusTemporaryRedirect, "Temporary Redirect"},
		{StatusPermanentRedirect, "Permanent Redirect"},
		{StatusBadRequest, "Bad Request"},
		{StatusUnauthorized, "Unauthorized"},
		{StatusPaymentRequired, "Payment Required"},
		{StatusForbidden, "Forbidden"},
		{StatusNotFound, "Not Found"},
		{StatusMethodNotAllowed, "Method Not Allowed"},
		{StatusNotAcceptable, "Not Acceptable"},
		{StatusProxyAuthRequired, "Proxy Authentication Required"},
		{StatusRequestTimeout, "Request Timeout"},
		{StatusConflict, "Conflict"},
		{StatusGone, "Gone"},
		{StatusLengthRequired, "Length Required"},
		{StatusPreconditionFailed, "Precondition Failed"},
		{StatusRequestEntityTooLarge, "Request Entity Too Large"},
		{StatusRequestURITooLong, "Request URI Too Long"},
		{StatusUnsupportedMediaType, "Unsupported Media Type"},
		{StatusRequestedRangeNotSatisfiable, "Requested Range Not Satisfiable"},
		{StatusExpectationFailed, "Expectation Failed"},
		{StatusTeapot, "I'm a teapot"},
		{StatusMisdirectedRequest, "Misdirected Request"},
		{StatusUnprocessableEntity, "Unprocessable Entity"},
		{StatusLocked, "Locked"},
		{StatusFailedDependency, "Failed Dependency"},
		{StatusTooEarly, "Too Early"},
		{StatusUpgradeRequired, "Upgrade Required"},
		{StatusPreconditionRequired, "Precondition Required"},
		{StatusTooManyRequests, "Too Many Requests"},
		{StatusRequestHeaderFieldsTooLarge, "Request Header Fields Too Large"},
		{StatusUnavailableForLegalReasons, "Unavailable For Legal Reasons"},
		{StatusInternalServerError, "Internal Server Error"},
		{StatusNotImplemented, "Not Implemented"},
		{StatusBadGateway, "Bad Gateway"},
		{StatusServiceUnavailable, "Service Unavailable"},
		{StatusGatewayTimeout, "Gateway Timeout"},
		{StatusHTTPVersionNotSupported, "HTTP Version Not Supported"},
		{StatusVariantAlsoNegotiates, "Variant Also Negotiates"},
		{StatusInsufficientStorage, "Insufficient Storage"},
		{StatusLoopDetected, "Loop Detected"},
		{StatusNotExtended, "Not Extended"},
		{StatusNetworkAuthenticationRequired, "Network Authentication Required"},
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

// TestStatusText_MatchesNetHTTP verifies that StatusText returns the same
// reason phrase as net/http.StatusText for all standard HTTP status codes.
// This ensures our local table stays in sync with Go's standard library.
func TestStatusText_MatchesNetHTTP(t *testing.T) {
	// All status codes defined in net/http.
	codes := []int{
		100, 101, 102, 103,
		200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
		300, 301, 302, 303, 304, 305, 307, 308,
		400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
		410, 411, 412, 413, 414, 415, 416, 417, 418, 421,
		422, 423, 424, 425, 426, 428, 429, 431, 451,
		500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511,
	}

	for _, code := range codes {
		got := StatusText(code)
		want := gohttp.StatusText(code)
		if got != want {
			t.Errorf("StatusText(%d) = %q, net/http.StatusText(%d) = %q", code, got, code, want)
		}
	}
}

func TestFormatStatus(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "200 OK"},
		{404, "404 Not Found"},
		{500, "500 Internal Server Error"},
		{999, "999"}, // unknown code: no trailing space
		{599, "599"}, // unknown code: no trailing space
		{206, "206 Partial Content"},
		{422, "422 Unprocessable Entity"},
	}
	for _, tt := range tests {
		if got := FormatStatus(tt.code); got != tt.want {
			t.Errorf("FormatStatus(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}
