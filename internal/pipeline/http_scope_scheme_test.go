package pipeline

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1086: HTTPScopeStep must hand TargetScope.CheckTarget the transport
// confidentiality of the client's connection (derived from
// Envelope.Context.TLS), never the request's declared scheme. The declared
// scheme is client-controlled: HTTP/2 records `:scheme` verbatim (an absent
// one leaves HTTPMessage.Scheme empty) and an intercept modify_and_forward
// may set it to anything. Because matchTargetRule is AND logic, a blank or
// mismatched scheme silently stopped every Schemes-bearing rule from
// matching — a deny bypass and an allow false-block — and broke default
// port inference for Ports-bearing rules.

// scopeSchemeRequest builds a Send-direction HTTPMessage envelope whose
// declared scheme is scheme, on a connection that is TLS iff tls is true.
// The Context mirrors the client-facing Layer's EnvelopeContext
// (connector/stack_builder.go clientEnvCtx: TLS is the client-leg snapshot).
func scopeSchemeRequest(scheme, authority, path string, tls bool) *envelope.Envelope {
	env := &envelope.Envelope{
		StreamID:  "usk1086",
		FlowID:    "usk1086-flow",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    scheme,
			Authority: authority,
			Path:      path,
		},
	}
	if tls {
		env.Context.TLS = &envelope.TLSSnapshot{}
	}
	return env
}

// TestHTTPScopeStep_BlankSchemeDerivesFromTLS covers the blank-scheme
// quadrants (TLS on/off × deny/allow) plus two negative controls proving the
// fix is "match the transport", not "block anything blank".
func TestHTTPScopeStep_BlankSchemeDerivesFromTLS(t *testing.T) {
	tests := []struct {
		name   string
		allows []connector.TargetRule
		denies []connector.TargetRule
		tls    bool
		want   Action
	}{
		{
			name:   "deny https on TLS connection blocks",
			denies: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"https"}}},
			tls:    true,
			want:   Respond,
		},
		{
			name:   "deny http on plaintext connection blocks",
			denies: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"http"}}},
			tls:    false,
			want:   Respond,
		},
		{
			name:   "allow https on TLS connection passes",
			allows: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"https"}}},
			tls:    true,
			want:   Continue,
		},
		{
			name:   "allow http on plaintext connection passes",
			allows: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"http"}}},
			tls:    false,
			want:   Continue,
		},
		// Negative controls: green before and after the fix.
		{
			name:   "control: deny https on plaintext connection passes",
			denies: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"https"}}},
			tls:    false,
			want:   Continue,
		},
		{
			name:   "control: deny http on TLS connection passes",
			denies: []connector.TargetRule{{Hostname: "api.target.com", Schemes: []string{"http"}}},
			tls:    true,
			want:   Continue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(tt.allows, tt.denies)
			env := scopeSchemeRequest("", "api.target.com:443", "/x", tt.tls)

			r := NewHTTPScopeStep(scope).Process(context.Background(), env)
			if r.Action != tt.want {
				t.Errorf("Scheme \"\", TLS=%v: action = %v, want %v", tt.tls, r.Action, tt.want)
			}
			if tt.want == Respond && r.BlockedBy != BlockedByTargetScope {
				t.Errorf("BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
			}
		})
	}
}

// TestHTTPScopeStep_PortInferenceUsesTransportScheme pins that a port-less
// authority resolves its default port from the derived transport scheme, so
// Ports-bearing rules do not degrade to port 0 when the declared scheme is
// blank or out of vocabulary.
func TestHTTPScopeStep_PortInferenceUsesTransportScheme(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		tls    bool
		ports  []int
		want   Action
	}{
		{"blank scheme on TLS resolves 443", "", true, []int{443}, Respond},
		{"blank scheme on plaintext resolves 80", "", false, []int{80}, Respond},
		{"uppercase HTTPS on TLS resolves 443", "HTTPS", true, []int{443}, Respond},
		{"foreign scheme on TLS resolves 443", "ftp", true, []int{443}, Respond},
		// Control: the derived port is the transport default, not "any".
		{"control: blank scheme on TLS does not resolve 80", "", true, []int{80}, Continue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{
				{Hostname: "api.target.com", Ports: tt.ports, PathPrefix: "/admin"},
			})
			env := scopeSchemeRequest(tt.scheme, "api.target.com", "/admin/x", tt.tls)

			r := NewHTTPScopeStep(scope).Process(context.Background(), env)
			if r.Action != tt.want {
				t.Errorf("Scheme %q, TLS=%v, deny ports %v: action = %v, want %v",
					tt.scheme, tt.tls, tt.ports, r.Action, tt.want)
			}
		})
	}
}

// TestHTTPScopeStep_DeclaredSchemeIgnored pins the always-derive decision:
// a declared scheme that disagrees with the transport does not steer the
// policy decision in either direction.
func TestHTTPScopeStep_DeclaredSchemeIgnored(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		tls    bool
		deny   connector.TargetRule
		want   Action
	}{
		{
			name:   "declared http over TLS still hits an https deny",
			scheme: "http",
			tls:    true,
			deny:   connector.TargetRule{Hostname: "api.target.com", Schemes: []string{"https"}},
			want:   Respond,
		},
		{
			name:   "declared https over plaintext does not hit an https deny",
			scheme: "https",
			tls:    false,
			deny:   connector.TargetRule{Hostname: "api.target.com", Schemes: []string{"https"}},
			want:   Continue,
		},
		{
			name:   "declared https over plaintext hits an http deny",
			scheme: "https",
			tls:    false,
			deny:   connector.TargetRule{Hostname: "api.target.com", Schemes: []string{"http"}},
			want:   Respond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{tt.deny})
			env := scopeSchemeRequest(tt.scheme, "api.target.com:443", "/x", tt.tls)

			r := NewHTTPScopeStep(scope).Process(context.Background(), env)
			if r.Action != tt.want {
				t.Errorf("Scheme %q, TLS=%v: action = %v, want %v", tt.scheme, tt.tls, r.Action, tt.want)
			}
			if got := env.Message.(*envelope.HTTPMessage).Scheme; got != tt.scheme {
				t.Errorf("HTTPMessage.Scheme = %q after Process, want %q untouched (MITM Principle 1)", got, tt.scheme)
			}
		})
	}
}

// rawH2RequestEnvelope writes a client preface, SETTINGS and one HEADERS
// frame carrying exactly fields (so a test can omit or forge `:scheme`) to a
// ServerRole HTTP/2 Layer over net.Pipe, aggregates the stream with
// httpaggregator and returns the Send envelope. The Layer is configured as
// the client-facing leg of a TLS MITM is in production
// (connector/stack_builder.go: WithScheme("https") + clientEnvCtx whose TLS
// is the client-leg snapshot). The peer mirrors h2Peer in
// internal/layer/http2/layer_test.go.
func rawH2RequestEnvelope(t *testing.T, fields []hpack.HeaderField) *envelope.Envelope {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	// net.Pipe is synchronous: drain whatever the server Layer writes
	// (SETTINGS, SETTINGS ACK, WINDOW_UPDATE) so it never blocks.
	go func() { _, _ = io.Copy(io.Discard, cliConn) }()

	type srvResult struct {
		l   *http2.Layer
		err error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		l, err := http2.New(srvConn, "usk1086-h2-srv", http2.ServerRole,
			http2.WithScheme("https"),
			http2.WithEnvelopeContext(envelope.EnvelopeContext{
				TargetHost: "api.target.com:443",
				TLS:        &envelope.TLSSnapshot{SNI: "api.target.com", ALPN: "h2"},
			}))
		srvCh <- srvResult{l, err}
	}()
	if _, err := cliConn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("server http2.New: %v", sr.err)
	}
	t.Cleanup(func() {
		_ = sr.l.Close()
		_ = cliConn.Close()
		_ = srvConn.Close()
	})

	wr := frame.NewWriter(cliConn)
	if err := wr.WriteSettings(nil); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	block := hpack.NewEncoder(4096, true).Encode(fields)
	if err := wr.WriteHeaders(1, true, true, block); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var agg interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case sch := <-sr.l.Channels():
		agg = httpaggregator.WrapWithDefaults(sch, httpaggregator.RoleServer, nil)
	case <-ctx.Done():
		t.Fatalf("server http2 Layer yielded no stream")
	}
	env, err := agg.Next(ctx)
	if err != nil {
		t.Fatalf("aggregator Next: %v", err)
	}
	if _, ok := env.Message.(*envelope.HTTPMessage); !ok {
		t.Fatalf("aggregator Next: Message = %T, want *HTTPMessage", env.Message)
	}
	return env
}

// TestHTTPScopeStep_H2RequestSchemeFromWire is the live-path repro: an
// HTTP/2 client on a TLS MITM connection omits (or forges) `:scheme` on a
// request into a denied path. The envelope comes from the real ServerRole
// HTTP/2 Layer + httpaggregator; the declared scheme must be recorded
// verbatim and must not steer the scope decision.
func TestHTTPScopeStep_H2RequestSchemeFromWire(t *testing.T) {
	tests := []struct {
		name       string
		fields     []hpack.HeaderField
		wantScheme string
	}{
		{
			name: "no :scheme",
			fields: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":authority", Value: "api.target.com"},
				{Name: ":path", Value: "/admin/x"},
			},
			wantScheme: "",
		},
		{
			name: ":scheme http over TLS",
			fields: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "api.target.com"},
				{Name: ":path", Value: "/admin/x"},
			},
			wantScheme: "http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, deny := range []connector.TargetRule{
				{Hostname: "api.target.com", PathPrefix: "/admin", Schemes: []string{"https"}},
				{Hostname: "api.target.com", PathPrefix: "/admin", Ports: []int{443}},
			} {
				scope := connector.NewTargetScope()
				scope.SetPolicyRules(nil, []connector.TargetRule{deny})
				env := rawH2RequestEnvelope(t, tt.fields)
				msg := env.Message.(*envelope.HTTPMessage)
				if msg.Scheme != tt.wantScheme {
					t.Fatalf("precondition: aggregated Scheme = %q, want %q (recorded verbatim)", msg.Scheme, tt.wantScheme)
				}

				r := NewHTTPScopeStep(scope).Process(context.Background(), env)
				if r.Action != Respond || r.BlockedBy != BlockedByTargetScope {
					t.Errorf("deny %+v: action = %v blockedBy %q, want Respond/%q",
						deny, r.Action, r.BlockedBy, BlockedByTargetScope)
				}
				if msg.Scheme != tt.wantScheme {
					t.Errorf("HTTPMessage.Scheme = %q after Process, want %q untouched (MITM Principle 1)", msg.Scheme, tt.wantScheme)
				}
			}
		})
	}
}

// TestInterceptStep_ScopeRecheck_ModifyAndForwardSchemeIgnored: an agent
// rewriting the held request's scheme via modify_and_forward cannot carry a
// denied path past a Schemes-bearing deny at release. The release re-check
// reuses HTTPScopeStep on a clone that keeps the client-leg Context.TLS.
func TestInterceptStep_ScopeRecheck_ModifyAndForwardSchemeIgnored(t *testing.T) {
	for _, scheme := range []string{"", "http"} {
		t.Run("scheme "+strconv.Quote(scheme), func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{
				{Hostname: "127.0.0.1", PathPrefix: "/admin", Schemes: []string{"https"}},
			})
			queue := common.NewHoldQueue()
			step := newRecheckStep(t, scope, queue, nil)

			held := recheckHTTPRequest("/public")
			held.Context.TLS = &envelope.TLSSnapshot{}
			held.Message.(*envelope.HTTPMessage).Scheme = "https"
			modified := held.Clone()
			mm := modified.Message.(*envelope.HTTPMessage)
			mm.Scheme = scheme
			mm.Path = "/admin/users"

			whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

			assertTargetScope403(t, step.Process(context.Background(), held))
		})
	}
}

// TestHTTPScopeStep_HTTP1SchemeCharacterization pins that HTTP/1.x, whose
// Scheme is always the Layer's configured scheme and agrees with the
// client-leg TLS state on every live constructor, is unaffected. Green
// before and after USK-1086.
func TestHTTPScopeStep_HTTP1SchemeCharacterization(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		tls    bool
		deny   connector.TargetRule
		want   Action
	}{
		{"https MITM hits https deny", "https", true,
			connector.TargetRule{Hostname: "example.com", Schemes: []string{"https"}}, Respond},
		{"https MITM misses http deny", "https", true,
			connector.TargetRule{Hostname: "example.com", Schemes: []string{"http"}}, Continue},
		{"https MITM default port 443", "https", true,
			connector.TargetRule{Hostname: "example.com", Ports: []int{443}}, Respond},
		{"plain http hits http deny", "http", false,
			connector.TargetRule{Hostname: "example.com", Schemes: []string{"http"}}, Respond},
		{"plain http default port 80", "http", false,
			connector.TargetRule{Hostname: "example.com", Ports: []int{80}}, Respond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{tt.deny})
			var envCtx envelope.EnvelopeContext
			if tt.tls {
				envCtx.TLS = &envelope.TLSSnapshot{}
			}
			env := realH1RequestEnvelopeWithContext(t, tt.scheme, envCtx,
				"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
			if got := env.Message.(*envelope.HTTPMessage).Scheme; got != tt.scheme {
				t.Fatalf("precondition: Scheme = %q, want %q", got, tt.scheme)
			}
			if got := NewHTTPScopeStep(scope).Process(context.Background(), env).Action; got != tt.want {
				t.Errorf("action = %v, want %v", got, tt.want)
			}
		})
	}
}
