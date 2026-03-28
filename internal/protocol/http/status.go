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

// statusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
func statusText(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 413:
		return "Request Entity Too Large"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return ""
	}
}
