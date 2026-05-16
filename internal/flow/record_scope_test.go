package flow

import (
	"net"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func httpEnv(method, authority, path string) *envelope.Envelope {
	return &envelope.Envelope{
		Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    method,
			Authority: authority,
			Path:      path,
		},
	}
}

// grpcStartEnv builds a Direction=Send GRPCStartMessage envelope shaped
// like what the gRPC / gRPC-Web Layers emit. The proto argument selects
// envelope.ProtocolGRPC or envelope.ProtocolGRPCWeb — both layers produce
// the same Message type, so a single capture_scope arm must cover both.
func grpcStartEnv(t *testing.T, proto envelope.Protocol, authority, service, method string) *envelope.Envelope {
	t.Helper()
	return &envelope.Envelope{
		Protocol:  proto,
		Direction: envelope.Send,
		Message: &envelope.GRPCStartMessage{
			Service: service,
			Method:  method,
		},
		Context: envelope.EnvelopeContext{
			TargetHost: authority,
		},
	}
}

func nonHTTPEnvWithCtx(targetHost string, sni string) *envelope.Envelope {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolWebSocket,
		Message:  &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hi")},
		Context: envelope.EnvelopeContext{
			ClientAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
			TargetHost: targetHost,
		},
	}
	if sni != "" {
		env.Context.TLS = &envelope.TLSSnapshot{SNI: sni}
	}
	return env
}

func TestNewRecordScope_EmptyAllowsAll(t *testing.T) {
	rs := NewRecordScope()
	if !rs.IsEmpty() {
		t.Fatal("new RecordScope should be empty")
	}
	if !rs.ShouldRecord(httpEnv("GET", "api.example.com", "/")) {
		t.Error("empty scope must capture all flows")
	}
}

func TestRecordScope_NilSafe(t *testing.T) {
	var rs *RecordScope
	if !rs.IsEmpty() {
		t.Error("nil RecordScope.IsEmpty should be true")
	}
	if !rs.ShouldRecord(httpEnv("GET", "api.example.com", "/")) {
		t.Error("nil RecordScope.ShouldRecord should record everything")
	}
}

func TestRecordScope_ScopeRule_IsEmpty(t *testing.T) {
	if !(ScopeRule{}).IsEmpty() {
		t.Error("zero-value ScopeRule must report empty")
	}
	if (ScopeRule{Hostname: "x"}).IsEmpty() {
		t.Error("rule with hostname must not be empty")
	}
	if (ScopeRule{Method: "GET"}).IsEmpty() {
		t.Error("rule with method must not be empty")
	}
	if (ScopeRule{URLPrefix: "/x"}).IsEmpty() {
		t.Error("rule with url_prefix must not be empty")
	}
}

func TestRecordScope_IncludeOnly(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com"}}, nil)

	cases := []struct {
		env  *envelope.Envelope
		want bool
		why  string
	}{
		{httpEnv("GET", "api.target.com", "/"), true, "in-scope hostname"},
		{httpEnv("GET", "API.Target.COM", "/"), true, "case-insensitive hostname"},
		{httpEnv("GET", "static.target.com", "/"), false, "different hostname"},
		{httpEnv("GET", "api.target.com:8443", "/"), true, "port stripped"},
	}
	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if got := rs.ShouldRecord(tc.env); got != tc.want {
				t.Errorf("ShouldRecord = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRecordScope_ExcludeBeatsInclude(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules(
		[]ScopeRule{{Hostname: "*.target.com"}},
		[]ScopeRule{{Hostname: "static.target.com"}},
	)
	if rs.ShouldRecord(httpEnv("GET", "static.target.com", "/")) {
		t.Error("exclude must override include")
	}
	if !rs.ShouldRecord(httpEnv("GET", "api.target.com", "/")) {
		t.Error("non-excluded include match must record")
	}
}

func TestRecordScope_WildcardHostnameApex(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "*.target.com"}}, nil)
	if rs.ShouldRecord(httpEnv("GET", "target.com", "/")) {
		t.Error("'*.target.com' must NOT match the apex 'target.com'")
	}
	if !rs.ShouldRecord(httpEnv("GET", "sub.target.com", "/")) {
		t.Error("'*.target.com' must match 'sub.target.com'")
	}
	if !rs.ShouldRecord(httpEnv("GET", "deep.sub.target.com", "/")) {
		t.Error("'*.target.com' must match 'deep.sub.target.com'")
	}
}

func TestRecordScope_URLPrefix(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com", URLPrefix: "/api/"}}, nil)
	if !rs.ShouldRecord(httpEnv("GET", "api.target.com", "/api/v1/widgets")) {
		t.Error("matching prefix must record")
	}
	if rs.ShouldRecord(httpEnv("GET", "api.target.com", "/healthz")) {
		t.Error("non-matching prefix must filter")
	}
	if rs.ShouldRecord(httpEnv("GET", "api.target.com", "")) {
		t.Error("empty path must filter when prefix required")
	}
}

func TestRecordScope_Method(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com", Method: "post"}}, nil)
	if !rs.ShouldRecord(httpEnv("POST", "api.target.com", "/x")) {
		t.Error("method should match case-insensitively")
	}
	if rs.ShouldRecord(httpEnv("GET", "api.target.com", "/x")) {
		t.Error("non-matching method must filter")
	}
}

// TestRecordScope_URLPrefix_GRPC verifies that capture_scope url_prefix
// rules apply to native gRPC envelopes (USK-909). The matcher synthesizes
// the wire-equivalent `:path = /<Service>/<Method>` from
// *envelope.GRPCStartMessage so rules like `/hello.HelloService/` work as
// operators expect.
func TestRecordScope_URLPrefix_GRPC(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "grpcb.in", URLPrefix: "/hello.HelloService/"}}, nil)
	if !rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "hello.HelloService", "SayHello")) {
		t.Error("matching service prefix must record")
	}
	if rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "other.Service", "X")) {
		t.Error("non-matching service must filter")
	}
	// Guard: empty Service or empty Method must suppress synthesis so a
	// partial path like "/Service/" cannot spuriously prefix-match.
	if rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "", "SayHello")) {
		t.Error("empty Service must suppress path synthesis (no spurious match)")
	}
	if rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "hello.HelloService", "")) {
		t.Error("empty Method must suppress path synthesis (no spurious match)")
	}
}

// TestRecordScope_Method_GRPC verifies that capture_scope method rules
// apply to gRPC envelopes by treating them as wire-literal POST (USK-909).
func TestRecordScope_Method_GRPC(t *testing.T) {
	rsPost := NewRecordScope()
	rsPost.SetRules([]ScopeRule{{Hostname: "grpcb.in", Method: "POST"}}, nil)
	if !rsPost.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "hello.HelloService", "SayHello")) {
		t.Error("method=POST rule must match gRPC envelope (wire-literal POST)")
	}

	rsGet := NewRecordScope()
	rsGet.SetRules([]ScopeRule{{Hostname: "grpcb.in", Method: "GET"}}, nil)
	if rsGet.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "hello.HelloService", "SayHello")) {
		t.Error("method=GET rule must not match gRPC envelope")
	}

	// Guard: when synthesis is suppressed (empty Service/Method), the
	// method field is also empty so a method rule cannot match.
	if rsPost.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "", "SayHello")) {
		t.Error("empty Service must suppress method projection")
	}
	if rsPost.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPC, "grpcb.in:443", "hello.HelloService", "")) {
		t.Error("empty Method must suppress method projection")
	}
}

// TestRecordScope_URLPrefix_GRPCWeb verifies that gRPC-Web envelopes —
// which share the *envelope.GRPCStartMessage type with native gRPC — are
// covered by the same arm (USK-909).
func TestRecordScope_URLPrefix_GRPCWeb(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "grpcb.in", URLPrefix: "/hello.HelloService/"}}, nil)
	if !rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPCWeb, "grpcb.in:443", "hello.HelloService", "SayHello")) {
		t.Error("matching service prefix must record for gRPC-Web")
	}
	if rs.ShouldRecord(grpcStartEnv(t, envelope.ProtocolGRPCWeb, "grpcb.in:443", "other.Service", "X")) {
		t.Error("non-matching service must filter for gRPC-Web")
	}
}

func TestRecordScope_NonHTTPHostname_FromTargetHost(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com"}}, nil)
	env := nonHTTPEnvWithCtx("api.target.com:443", "")
	if !rs.ShouldRecord(env) {
		t.Error("WS frame: hostname should resolve from Context.TargetHost")
	}
}

func TestRecordScope_NonHTTPHostname_FromSNI(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com"}}, nil)
	env := nonHTTPEnvWithCtx("", "api.target.com")
	if !rs.ShouldRecord(env) {
		t.Error("WS frame without TargetHost: hostname should resolve from TLS SNI")
	}
}

// TestRecordScope_TLSHandshakeHostname_FromContext exercises the
// TargetHost → SNI fallback chain that the USK-845 footgun fix relies on
// for protocol="tls-handshake" audit envelopes. The matcher must remain
// protocol-agnostic: it consults Context.TargetHost (preferred) then
// Context.TLS.SNI (fallback) — no type-switch on TLSHandshakeMessage.
func TestRecordScope_TLSHandshakeHostname_FromContext(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "httpbin.org"}}, nil)

	// USK-845 happy path: TargetHost set from CONNECT authority — matcher
	// must use it and ignore the absent SNI.
	envTargetHost := &envelope.Envelope{
		Protocol: envelope.ProtocolTLSHandshake,
		Message: &envelope.TLSHandshakeMessage{
			SNI:          "",
			UpstreamAddr: "1.2.3.4:443",
		},
		Context: envelope.EnvelopeContext{TargetHost: "httpbin.org"},
	}
	if !rs.ShouldRecord(envTargetHost) {
		t.Error("tls-handshake with TargetHost=httpbin.org: hostname must match via TargetHost")
	}

	// USK-845 defence-in-depth path: TargetHost empty — matcher must fall
	// back to Context.TLS.SNI.
	envSNIFallback := &envelope.Envelope{
		Protocol: envelope.ProtocolTLSHandshake,
		Message: &envelope.TLSHandshakeMessage{
			SNI:          "httpbin.org",
			UpstreamAddr: "1.2.3.4:443",
		},
		Context: envelope.EnvelopeContext{
			TargetHost: "",
			TLS:        &envelope.TLSSnapshot{SNI: "httpbin.org"},
		},
	}
	if !rs.ShouldRecord(envSNIFallback) {
		t.Error("tls-handshake without TargetHost: hostname must fall back to TLS.SNI")
	}

	// Regression guard: if TargetHost is the resolved IP (the pre-fix bug)
	// and SNI is empty, no rule should match — the matcher must NOT
	// accidentally interpret the IP as the include rule's hostname.
	envIPOnly := &envelope.Envelope{
		Protocol: envelope.ProtocolTLSHandshake,
		Message: &envelope.TLSHandshakeMessage{
			SNI:          "",
			UpstreamAddr: "1.2.3.4:443",
		},
		Context: envelope.EnvelopeContext{TargetHost: "1.2.3.4"},
	}
	if rs.ShouldRecord(envIPOnly) {
		t.Error("tls-handshake with only an IP TargetHost must not match a hostname include rule")
	}
}

func TestRecordScope_NonHTTP_URLPrefixRule_DoesNotMatch(t *testing.T) {
	// Per the design, rules that require url_prefix or method do not match
	// non-HTTP envelopes (they have no path / method). The recording
	// decision is made at the stream's first Send (HTTP upgrade) and
	// cached at the RecordStep level — see record_step.go.
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com", URLPrefix: "/api/"}}, nil)
	env := nonHTTPEnvWithCtx("api.target.com:443", "")
	if rs.ShouldRecord(env) {
		t.Error("rule requiring url_prefix must not match non-HTTP envelope on its own")
	}
}

func TestRecordScope_MergeRules(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "a.com"}}, []ScopeRule{{Hostname: "b.com"}})
	rs.MergeRules(
		[]ScopeRule{{Hostname: "c.com"}, {Hostname: "a.com"}},
		[]ScopeRule{{Hostname: "a.com"}},
		[]ScopeRule{{Hostname: "d.com"}},
		[]ScopeRule{{Hostname: "b.com"}},
	)
	includes, excludes := rs.Rules()
	if len(includes) != 1 || includes[0].Hostname != "c.com" {
		t.Errorf("includes after merge = %v, want [c.com]", includes)
	}
	if len(excludes) != 1 || excludes[0].Hostname != "d.com" {
		t.Errorf("excludes after merge = %v, want [d.com]", excludes)
	}
}

func TestRecordScope_Clear(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "a"}}, []ScopeRule{{Hostname: "b"}})
	rs.Clear()
	if !rs.IsEmpty() {
		t.Error("Clear should empty the scope")
	}
}

func TestRecordScope_RulesReturnsCopy(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "a"}}, []ScopeRule{{Hostname: "b"}})
	includes, excludes := rs.Rules()
	includes[0].Hostname = "MUTATED"
	excludes[0].Hostname = "MUTATED"
	gotInc, gotExc := rs.Rules()
	if gotInc[0].Hostname != "a" || gotExc[0].Hostname != "b" {
		t.Error("Rules must return independent copies")
	}
}

// Round-trip a minimal HTTPMessage through the matcher to catch regressions
// in field extraction. The auxiliary url.URL is here to surface accidental
// reuse in extractScopeFields.
func TestRecordScope_HTTPMessage_AuthorityWins(t *testing.T) {
	rs := NewRecordScope()
	rs.SetRules([]ScopeRule{{Hostname: "api.target.com"}}, nil)
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{
			TargetHost: "different.example.com",
		},
		Message: &envelope.HTTPMessage{Method: "GET", Authority: "api.target.com", Path: "/"},
	}
	if !rs.ShouldRecord(env) {
		t.Error("HTTPMessage.Authority should override Context.TargetHost for hostname resolution")
	}
	_ = url.URL{}
}
