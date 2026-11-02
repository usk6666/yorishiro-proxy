package connector

import (
	"errors"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// resolveForwardTarget returns the upstream host:port an explicit
// plain-HTTP forward-proxy request names (USK-1410).
func resolveForwardTarget(method, requestURI string, headers parser.RawHeaders) (string, error) {
	return "", errors.New("not implemented")
}
