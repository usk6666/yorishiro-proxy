package http

import "github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"

// HTTP status code constants — aliases to the shared httputil package.
// These remain unexported to preserve the existing API within this package.
const (
	statusOK                  = httputil.StatusOK
	statusSwitchingProtocols  = httputil.StatusSwitchingProtocols
	statusBadRequest          = httputil.StatusBadRequest
	statusForbidden           = httputil.StatusForbidden
	statusNotFound            = httputil.StatusNotFound
	statusMethodNotAllowed    = httputil.StatusMethodNotAllowed
	statusTooManyRequests     = httputil.StatusTooManyRequests
	statusInternalServerError = httputil.StatusInternalServerError
	statusNotImplemented      = httputil.StatusNotImplemented
	statusBadGateway          = httputil.StatusBadGateway
)

// statusText returns the text for the HTTP status code. It delegates to the
// shared httputil.StatusText function.
func statusText(code int) string {
	return httputil.StatusText(code)
}
