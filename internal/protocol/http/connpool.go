package http

import "github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"

// ConnPool is an alias for httputil.ConnPool, re-exported for backward
// compatibility within the protocol/http package. New code should import
// httputil.ConnPool directly.
type ConnPool = httputil.ConnPool

// ConnResult is an alias for httputil.ConnResult, re-exported for backward
// compatibility within the protocol/http package. New code should import
// httputil.ConnResult directly.
type ConnResult = httputil.ConnResult
