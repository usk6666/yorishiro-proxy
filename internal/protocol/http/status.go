package http

// HTTP status codes used by the handler. Defined as package-level constants
// to avoid importing net/http in production code.
const (
	statusOK                  = 200
	statusSwitchingProtocols  = 101
	statusBadRequest          = 400
	statusForbidden           = 403
	statusNotFound            = 404
	statusMethodNotAllowed    = 405
	statusTooManyRequests     = 429
	statusInternalServerError = 500
	statusNotImplemented      = 501
	statusBadGateway          = 502
)

// statusTexts maps HTTP status codes to their reason phrases.
var statusTexts = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	413: "Request Entity Too Large",
	429: "Too Many Requests",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

// statusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
func statusText(code int) string {
	return statusTexts[code]
}
