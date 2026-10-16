package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// usk1139WirePaths are request paths exactly as a client writes them on the
// wire. The first is the reported ad cookie-sync shape (GitHub issue 137);
// the rest are pentest shapes (invented) chosen because net/url's
// RawPath/EscapedPath machinery cannot carry them verbatim.
var usk1139WirePaths = []struct {
	name string
	wire string
}{
	{"reported cookie-sync", "/check_uuid/https%3A%2F%2Fsync.example%2Fsetuid%3Fa%3D1"},
	{"encoded question mark", "/a%3Fb"},
	{"encoded slash", "/a%2Fb"},
	{"encoded unreserved", "/%61dmin"},
	{"encoded space", "/a%20b"},
	{"invalid escape", "/a%zz"},
	{"template braces", "/{{7*7}}"},
	{"pipe", "/a|b"},
	{"raw utf-8", "/caf\xc3\xa9"},
}

// TestRecordStep_FlowURLKeepsWirePath_HTTP1 drives the real HTTP/1.x parser
// and RecordStep: the persisted Flow.URL's string form must carry the
// request-target bytes the client wrote, not a decoded or re-escaped copy.
func TestRecordStep_FlowURLKeepsWirePath_HTTP1(t *testing.T) {
	for _, p := range usk1139WirePaths {
		t.Run(p.name, func(t *testing.T) {
			env := realH1RequestEnvelope(t, "http",
				"GET "+p.wire+"?q=x%3Ay HTTP/1.1\r\nHost: example.com\r\n\r\n")
			w := &mockWriter{}
			NewRecordStep(w, nil).Process(context.Background(), env)
			if len(w.flows) != 1 {
				t.Fatalf("flows = %d, want 1", len(w.flows))
			}
			fl := w.flows[0]
			want := "http://example.com" + p.wire + "?q=x%3Ay"
			if got := envelope.WireURLString(fl.URL); got != want {
				t.Errorf("Flow.URL = %q, want %q", got, want)
			}
			if got := envelope.WirePath(fl.URL); got != p.wire {
				t.Errorf("WirePath(Flow.URL) = %q, want %q", got, p.wire)
			}
		})
	}
}

// TestRecordStep_FlowURLKeepsWirePath_HTTP2 is the HTTP/2 sibling: the
// :path pseudo-header is already wire form, and today's &url.URL{Path: ...}
// projection re-escapes it (%3A -> %253A).
func TestRecordStep_FlowURLKeepsWirePath_HTTP2(t *testing.T) {
	for _, p := range usk1139WirePaths {
		t.Run(p.name, func(t *testing.T) {
			env := realH2RequestEnvelope(t, "https", "example.com", p.wire, "q=x%3Ay")
			w := &mockWriter{}
			NewRecordStep(w, nil).Process(context.Background(), env)
			if len(w.flows) != 1 {
				t.Fatalf("flows = %d, want 1", len(w.flows))
			}
			want := "https://example.com" + p.wire + "?q=x%3Ay"
			if got := envelope.WireURLString(w.flows[0].URL); got != want {
				t.Errorf("Flow.URL = %q, want %q", got, want)
			}
		})
	}
}

// TestRecordStep_FlowURLKeepsWirePath_GRPCStart covers the gRPC projection.
// The fixture mirrors layer/grpc buildStartMessage, which copies the HTTP/2
// :path (wire form) into GRPCStartMessage.Path verbatim.
func TestRecordStep_FlowURLKeepsWirePath_GRPCStart(t *testing.T) {
	for _, p := range usk1139WirePaths {
		t.Run(p.name, func(t *testing.T) {
			w := &mockWriter{}
			env := &envelope.Envelope{
				StreamID:  "s-grpc",
				FlowID:    "f-grpc",
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolGRPC,
				Message: &envelope.GRPCStartMessage{
					Scheme:    "https",
					Authority: "grpc.example",
					Path:      p.wire,
					RawQuery:  "v=1",
					Service:   "svc",
					Method:    "M",
				},
			}
			NewRecordStep(w, nil).Process(context.Background(), env)
			if len(w.flows) != 1 {
				t.Fatalf("flows = %d, want 1", len(w.flows))
			}
			want := "https://grpc.example" + p.wire + "?v=1"
			if got := envelope.WireURLString(w.flows[0].URL); got != want {
				t.Errorf("Flow.URL = %q, want %q", got, want)
			}
		})
	}
}

// TestHTTPScopeStep_PathPrefixMatchesEitherForm pins the USK-1139 gate
// contract: a path_prefix matches when either the wire form or its
// percent-decoded form starts with the prefix, identically for HTTP/1.x and
// HTTP/2. Without it, moving HTTP/1.x Path to wire form would let
// "/%61dmin" past a "/admin" deny (it already does on HTTP/2 today).
// Shapes from USK-1131.
func TestHTTPScopeStep_PathPrefixMatchesEitherForm(t *testing.T) {
	denyScope := connector.NewTargetScope()
	denyScope.SetPolicyRules(nil, []connector.TargetRule{
		{PathPrefix: "/admin"},
		{PathPrefix: "/a%20b"},
	})
	allowScope := connector.NewTargetScope()
	allowScope.SetPolicyRules([]connector.TargetRule{
		{PathPrefix: "/public"},
	}, nil)

	tests := []struct {
		name  string
		scope *connector.TargetScope
		wire  string
		want  Action
	}{
		{"deny plain", denyScope, "/admin/users", Respond},
		{"deny encoded unreserved", denyScope, "/%61dmin/users", Respond},
		{"deny lowercase hex", denyScope, "/%61%64min", Respond},
		{"deny raw-form prefix matches wire", denyScope, "/a%20b/x", Respond},
		{"deny unrelated passes", denyScope, "/public/x", Continue},
		{"allow plain", allowScope, "/public/x", Continue},
		{"allow encoded", allowScope, "/%70ublic/x", Continue},
		{"allow other blocked", allowScope, "/private", Respond},
	}
	for _, tt := range tests {
		t.Run("h1/"+tt.name, func(t *testing.T) {
			env := realH1RequestEnvelope(t, "http",
				"GET "+tt.wire+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
			if got := NewHTTPScopeStep(tt.scope).Process(context.Background(), env).Action; got != tt.want {
				t.Errorf("HTTP/1.x %s: action = %v, want %v", tt.wire, got, tt.want)
			}
		})
		t.Run("h2/"+tt.name, func(t *testing.T) {
			env := realH2RequestEnvelope(t, "https", "example.com", tt.wire, "")
			if got := NewHTTPScopeStep(tt.scope).Process(context.Background(), env).Action; got != tt.want {
				t.Errorf("HTTP/2 %s: action = %v, want %v", tt.wire, got, tt.want)
			}
		})
	}
}

// TestHTTPScopeStep_RequestTargetForms_Characterization pins the
// absolute-form and asterisk-form behavior USK-1129 relies on; green before
// and after USK-1139.
func TestHTTPScopeStep_RequestTargetForms_Characterization(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{PathPrefix: "/admin"}})
	step := NewHTTPScopeStep(scope)

	abs := realH1RequestEnvelope(t, "http",
		"GET http://example.com/admin HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if got := abs.Message.(*envelope.HTTPMessage).Path; got != "/admin" {
		t.Errorf("absolute-form Path = %q, want /admin", got)
	}
	if got := step.Process(context.Background(), abs).Action; got != Respond {
		t.Errorf("absolute-form /admin: action = %v, want Respond", got)
	}

	star := realH1RequestEnvelope(t, "http",
		"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if got := star.Message.(*envelope.HTTPMessage).Path; got != "*" {
		t.Errorf("asterisk-form Path = %q, want *", got)
	}
	if got := step.Process(context.Background(), star).Action; got != Continue {
		t.Errorf("OPTIONS *: action = %v, want Continue", got)
	}
}

// TestSafetyStep_URLTargetMatchesDecodedPath pins that the Input Filter's
// url target sees the percent-decoded path as well as the wire path, on
// both HTTP/1.x and HTTP/2. destructive-sql is deny-only, so matching
// either form fails closed.
func TestSafetyStep_URLTargetMatchesDecodedPath(t *testing.T) {
	step := NewSafetyStep(newTestSafetyEngine(t), nil, nil, nil)
	const wire = "/x/DROP%20TABLE%20t"

	h1 := realH1RequestEnvelope(t, "http", "GET "+wire+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if got := step.Process(context.Background(), h1).Action; got != Respond {
		t.Errorf("HTTP/1.x %s: action = %v, want Respond", wire, got)
	}
	h2 := realH2RequestEnvelope(t, "https", "example.com", wire, "")
	if got := step.Process(context.Background(), h2).Action; got != Respond {
		t.Errorf("HTTP/2 %s: action = %v, want Respond", wire, got)
	}

	// The literal form keeps matching (HTTP/2 allows a raw space in :path
	// bytes; HTTP/1.x cannot carry one in the request line).
	lit := realH2RequestEnvelope(t, "https", "example.com", "/x/DROP TABLE t", "")
	if got := step.Process(context.Background(), lit).Action; got != Respond {
		t.Errorf("HTTP/2 literal: action = %v, want Respond", got)
	}
}
