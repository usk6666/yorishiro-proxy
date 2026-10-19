package flow

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1199: a body-bearing HTTP/2 (or gRPC-Web) stream's first Send
// envelope is a Message-less wire_level overlay (h2-frame /
// grpcweb-base64). RecordStep caches the capture_scope decision on that
// envelope, so ShouldRecord must evaluate method / url_prefix / hostname
// rules against the overlay's wire-observed request-head fields on
// EnvelopeContext (RequestMethod / RequestPath / RequestAuthority), as the
// producing Layer stamps them from the stream's HEADERS / request line.

// overlayEnv builds the overlay shape the aggregator / grpcweb Layer hands
// to RecordStep: Message=nil, WireLevel stamped by the session record
// helper, connection-level TargetHost / SNI, and request-head fields.
func overlayEnv(wireLevel, targetHost, sni, method, path, authority string) *envelope.Envelope {
	ctx := envelope.EnvelopeContext{
		TargetHost:       targetHost,
		WireLevel:        wireLevel,
		RequestMethod:    method,
		RequestPath:      path,
		RequestAuthority: authority,
	}
	if sni != "" {
		ctx.TLS = &envelope.TLSSnapshot{SNI: sni}
	}
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("a=1"),
		Context:   ctx,
	}
}

func TestRecordScope_ShouldRecord_WireLevelOverlay(t *testing.T) {
	tests := []struct {
		name     string
		includes []ScopeRule
		excludes []ScopeRule
		env      *envelope.Envelope
		want     bool
	}{
		{
			name:     "h2-frame overlay matches include method=POST",
			includes: []ScopeRule{{Method: "POST"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "", "POST", "/api/x", "a.example.com:443"),
			want:     true,
		},
		{
			name:     "h2-frame overlay matches include url_prefix",
			includes: []ScopeRule{{URLPrefix: "/api/"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "", "POST", "/api/x", ""),
			want:     true,
		},
		{
			name:     "h2-frame overlay does not match include method=GET",
			includes: []ScopeRule{{Method: "GET"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "", "POST", "/api/x", ""),
			want:     false,
		},
		{
			name:     "h2-frame overlay matches exclude method=POST",
			excludes: []ScopeRule{{Method: "POST"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "", "POST", "/api/x", ""),
			want:     false,
		},
		{
			name:     "grpcweb-base64 overlay matches include url_prefix service",
			includes: []ScopeRule{{URLPrefix: "/yorishiro.test.WebSafety/"}},
			env:      overlayEnv(WireLevelGRPCWebBase64, "a.example.com:443", "", "POST", "/yorishiro.test.WebSafety/Echo", ""),
			want:     true,
		},
		{
			name:     "grpcweb-base64 overlay matches exclude method=POST",
			excludes: []ScopeRule{{Method: "POST"}},
			env:      overlayEnv(WireLevelGRPCWebBase64, "a.example.com:443", "", "POST", "/yorishiro.test.WebSafety/Echo", ""),
			want:     false,
		},
		{
			// T11: HTTP/2 connection coalescing — the connection was
			// opened for a.example.com but this stream's :authority is
			// b.example.com. The semantic envelope matches on
			// :authority, so the overlay must too.
			name:     "coalesced overlay include hostname matches :authority not TargetHost",
			includes: []ScopeRule{{Hostname: "b.example.com"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "a.example.com", "GET", "/", "b.example.com"),
			want:     true,
		},
		{
			name:     "coalesced overlay exclude hostname matches :authority with port",
			excludes: []ScopeRule{{Hostname: "b.example.com"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "a.example.com", "GET", "/", "b.example.com:443"),
			want:     false,
		},
		{
			name:     "coalesced overlay include connection host no longer matches",
			includes: []ScopeRule{{Hostname: "a.example.com"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "a.example.com", "GET", "/", "b.example.com"),
			want:     false,
		},
		{
			name:     "overlay without RequestAuthority falls back to TargetHost",
			includes: []ScopeRule{{Hostname: "a.example.com"}},
			env:      overlayEnv(WireLevelH2Frame, "a.example.com:443", "", "POST", "/", ""),
			want:     true,
		},
		{
			name:     "overlay without RequestAuthority or TargetHost falls back to SNI",
			includes: []ScopeRule{{Hostname: "a.example.com"}},
			env:      overlayEnv(WireLevelH2Frame, "", "a.example.com", "POST", "/", ""),
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRecordScope()
			rs.SetRules(tt.includes, tt.excludes)
			if got := rs.ShouldRecord(tt.env); got != tt.want {
				t.Errorf("ShouldRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRecordScope_ShouldRecord_RequestFieldsGate pins that the
// EnvelopeContext request-head fallback is confined to Message-less
// non-semantic overlays: a WS frame or a Message-less envelope without an
// overlay WireLevel keeps today's behaviour (method/path rules inert).
func TestRecordScope_ShouldRecord_RequestFieldsGate(t *testing.T) {
	ctx := envelope.EnvelopeContext{
		TargetHost:       "a.example.com:443",
		RequestMethod:    "POST",
		RequestPath:      "/api/x",
		RequestAuthority: "b.example.com",
	}
	withWL := func(wl string) envelope.EnvelopeContext {
		c := ctx
		c.WireLevel = wl
		return c
	}
	tests := []struct {
		name string
		env  *envelope.Envelope
	}{
		{
			name: "WS frame with request-head context",
			env: &envelope.Envelope{
				Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
				Message: &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("x")},
				Context: withWL(WireLevelH2Frame),
			},
		},
		{
			name: "Message-less envelope with empty WireLevel",
			env: &envelope.Envelope{
				Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
				Context: withWL(""),
			},
		},
		{
			name: "Message-less envelope with semantic WireLevel",
			env: &envelope.Envelope{
				Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
				Context: withWL(WireLevelSemantic),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, rule := range []ScopeRule{{Method: "POST"}, {URLPrefix: "/api/"}, {Hostname: "b.example.com"}} {
				rs := NewRecordScope()
				rs.SetRules([]ScopeRule{rule}, nil)
				if rs.ShouldRecord(tt.env) {
					t.Errorf("include %+v: ShouldRecord() = true, want false (request-head fallback must not apply)", rule)
				}
			}
		})
	}
}
