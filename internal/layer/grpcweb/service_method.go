package grpcweb

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// parseServiceMethod splits a gRPC-Web :path / HTTP path of the form
// "/pkg.Service/Method" into Service ("pkg.Service") and Method ("Method").
// Empty / malformed paths return ("", "", false); callers log at the call
// site rather than failing the stream.
//
// Strict like internal/layer/grpc.parseGRPCPath (USK-1069): the path must
// start with "/", and the split is at the LAST "/" with both halves
// non-empty. Strictness matters because pathForStart forwards an
// unparseable observed :path verbatim — a tolerant parse would rebuild
// "svc/M" into "/svc/M" and normalize what the wire did not normalize.
//
// This helper is duplicated in internal/layer/grpc per RFC-001 N7
// implementation discipline (no premature cross-package abstraction during
// parallel layer implementation — see USK-641 / USK-640 user-approved
// guidance).
func parseServiceMethod(path string) (service, method string, ok bool) {
	if !strings.HasPrefix(path, "/") {
		return "", "", false
	}
	p := path[1:]
	idx := strings.LastIndex(p, "/")
	// Reject paths with no "/" separator, an empty service, or trailing "/".
	if idx <= 0 || idx == len(p)-1 {
		return "", "", false
	}
	return p[:idx], p[idx+1:], true
}

// buildGRPCWebPath is the inverse of parseServiceMethod. Empty
// service+method yields "/" so the request-target remains valid.
func buildGRPCWebPath(service, method string) string {
	if service == "" && method == "" {
		return "/"
	}
	return "/" + service + "/" + method
}

// pathForStart resolves the request path for a Send-side Start, with the
// same precedence rule as internal/layer/grpc.pathForStart (USK-1053;
// adopted here by USK-1069).
//
// Service / Method are the derived L7 view; Path is the wire overlay
// projected by applyRequestOverlay. The derived view wins whenever the
// observed path was parseable into it — that keeps the intercept / plugin
// service+method override working. When parseServiceMethod could not
// represent the observed path (no inner slash, empty service, trailing
// "/", no leading "/"), rebuilding would normalize it, so the overlay wins
// instead (MITM Principle 1). An empty Path falls through to the rebuild,
// so synthetic producers that never set it are unaffected.
//
// The query component is not part of the result: it rides on
// GRPCStartMessage.RawQuery → HTTPMessage.RawQuery and the inner HTTP
// Layer rejoins it.
func pathForStart(m *envelope.GRPCStartMessage) string {
	if m.Path != "" {
		if _, _, ok := parseServiceMethod(m.Path); !ok {
			return m.Path
		}
	}
	return buildGRPCWebPath(m.Service, m.Method)
}
