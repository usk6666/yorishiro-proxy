package grpcweb

import "strings"

// parseServiceMethod splits a gRPC-Web :path / HTTP path of the form
// "/pkg.Service/Method" into Service ("pkg.Service") and Method ("Method").
// Tolerant policy (matches USK-640 and the legacy grpc.ParseServiceMethod):
// empty / malformed paths return ("", "", false). Callers are expected to
// log a slog.Warn at the call site rather than failing the stream.
//
// This helper is duplicated in internal/layer/grpc per RFC-001 N7
// implementation discipline (no premature cross-package abstraction during
// parallel layer implementation — see USK-641 / USK-640 user-approved
// guidance).
func parseServiceMethod(path string) (service, method string, ok bool) {
	p := strings.TrimPrefix(path, "/")
	if p == "" {
		return "", "", false
	}
	idx := strings.LastIndex(p, "/")
	// Reject paths with no "/" separator, leading "/" only, or trailing "/".
	if idx <= 0 || idx == len(p)-1 {
		return "", "", false
	}
	return p[:idx], p[idx+1:], true
}
