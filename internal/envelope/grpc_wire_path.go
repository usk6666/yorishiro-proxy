package envelope

import "strings"

// GRPCStartWirePath returns the request path a Send-side GRPCStartMessage
// is written to the wire with — the HTTP/2 :path of native gRPC and the
// HTTP request-target path of gRPC-Web — without the query component,
// which rides on RawQuery (the same split HTTPMessage.Path / RawQuery
// uses).
//
// Service / Method are the derived L7 view and Path is the wire overlay
// (USK-920). The derived view wins whenever Path parses as
// "/<service>/<method>" — split at the last "/", both halves non-empty —
// which keeps the intercept / plugin service+method override working.
// When Path does not parse (no inner slash, empty service, trailing "/",
// no leading "/"), rebuilding would normalize what the wire did not
// normalize, so Path is returned verbatim (MITM Principle 1, USK-1053 /
// USK-1069). An empty Path falls through to the rebuild, so synthetic
// producers (resend / fuzz) that never set it are unaffected; empty
// Service and Method rebuild as "/".
//
// It is the single source of that precedence rule: the native gRPC and
// gRPC-Web Layers serialize with it, and the TargetScope request check
// judges the same path (USK-1236), so the policy decision reads the path
// the upstream actually receives. m is only read; a nil m yields "".
func GRPCStartWirePath(m *GRPCStartMessage) string {
	if m == nil {
		return ""
	}
	if m.Path != "" && !grpcPathParses(m.Path) {
		return m.Path
	}
	if m.Service == "" && m.Method == "" {
		return "/"
	}
	return "/" + m.Service + "/" + m.Method
}

// grpcPathParses reports whether path has the strict "/<service>/<method>"
// shape both gRPC Layers parse Service / Method from: a leading "/", and a
// last "/" with a non-empty service before it and a non-empty method
// after it.
func grpcPathParses(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	rest := path[1:]
	idx := strings.LastIndex(rest, "/")
	return idx > 0 && idx != len(rest)-1
}
