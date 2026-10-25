package envelope

import "testing"

// GRPCStartWirePath is the precedence rule both gRPC Layers serialize a
// Send Start's path with (formerly duplicated as pathForStart in
// internal/layer/grpc and internal/layer/grpcweb).
func TestGRPCStartWirePath(t *testing.T) {
	tests := []struct {
		name string
		msg  *GRPCStartMessage
		want string
	}{
		{"nil", nil, ""},
		{"empty path rebuilds", &GRPCStartMessage{Service: "pkg.Svc", Method: "Do"}, "/pkg.Svc/Do"},
		{"empty everything is root", &GRPCStartMessage{}, "/"},
		{"parseable path: derived view wins", &GRPCStartMessage{Path: "/ok.Svc/M", Service: "admin.AdminService", Method: "Delete"}, "/admin.AdminService/Delete"},
		{"parseable path unchanged", &GRPCStartMessage{Path: "/pkg.Svc/Do", Service: "pkg.Svc", Method: "Do"}, "/pkg.Svc/Do"},
		{"multi-segment service splits at last slash", &GRPCStartMessage{Path: "/a/b/C", Service: "a/b", Method: "C"}, "/a/b/C"},
		{"no inner slash verbatim", &GRPCStartMessage{Path: "/noslash"}, "/noslash"},
		{"trailing slash verbatim", &GRPCStartMessage{Path: "/svc/", Service: "x", Method: "y"}, "/svc/"},
		{"leading double slash verbatim", &GRPCStartMessage{Path: "//M"}, "//M"},
		{"no leading slash verbatim", &GRPCStartMessage{Path: "svc/M", Service: "x", Method: "y"}, "svc/M"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := GRPCStartWirePath(tc.msg); got != tc.want {
				t.Errorf("GRPCStartWirePath = %q, want %q", got, tc.want)
			}
		})
	}
}
