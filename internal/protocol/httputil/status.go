package httputil

// HTTP status code constants. These replace net/http status constants on the
// data path to minimise net/http dependency per the project's L7-first policy.
// See CLAUDE.md net/http usage policy (USK-522).
const (
	StatusContinue           = 100
	StatusSwitchingProtocols = 101

	StatusOK        = 200
	StatusCreated   = 201
	StatusAccepted  = 202
	StatusNoContent = 204

	StatusMovedPermanently  = 301
	StatusFound             = 302
	StatusNotModified       = 304
	StatusTemporaryRedirect = 307
	StatusPermanentRedirect = 308

	StatusBadRequest            = 400
	StatusUnauthorized          = 401
	StatusForbidden             = 403
	StatusNotFound              = 404
	StatusMethodNotAllowed      = 405
	StatusRequestTimeout        = 408
	StatusRequestEntityTooLarge = 413
	StatusTooManyRequests       = 429

	StatusInternalServerError = 500
	StatusNotImplemented      = 501
	StatusBadGateway          = 502
	StatusServiceUnavailable  = 503
	StatusGatewayTimeout      = 504
)

// statusTexts maps HTTP status codes to their reason phrases.
var statusTexts = map[int]string{
	StatusContinue:           "Continue",
	StatusSwitchingProtocols: "Switching Protocols",

	StatusOK:        "OK",
	StatusCreated:   "Created",
	StatusAccepted:  "Accepted",
	StatusNoContent: "No Content",

	StatusMovedPermanently:  "Moved Permanently",
	StatusFound:             "Found",
	StatusNotModified:       "Not Modified",
	StatusTemporaryRedirect: "Temporary Redirect",
	StatusPermanentRedirect: "Permanent Redirect",

	StatusBadRequest:            "Bad Request",
	StatusUnauthorized:          "Unauthorized",
	StatusForbidden:             "Forbidden",
	StatusNotFound:              "Not Found",
	StatusMethodNotAllowed:      "Method Not Allowed",
	StatusRequestTimeout:        "Request Timeout",
	StatusRequestEntityTooLarge: "Request Entity Too Large",
	StatusTooManyRequests:       "Too Many Requests",

	StatusInternalServerError: "Internal Server Error",
	StatusNotImplemented:      "Not Implemented",
	StatusBadGateway:          "Bad Gateway",
	StatusServiceUnavailable:  "Service Unavailable",
	StatusGatewayTimeout:      "Gateway Timeout",
}

// StatusText returns the text for the HTTP status code. It returns the empty
// string if the code is unknown.
func StatusText(code int) string {
	return statusTexts[code]
}
