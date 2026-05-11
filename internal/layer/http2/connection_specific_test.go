package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestIsConnectionSpecificHeader covers the RFC 7540 §8.1.2.2 / RFC 9113
// §8.2.2 forbidden header set. `te` is intentionally NOT in the predicate
// — its handling requires value inspection via TEAllowedValue. (USK-840)
func TestIsConnectionSpecificHeader(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Forbidden names.
		{"connection", true},
		{"Connection", true},
		{"CONNECTION", true},
		{"keep-alive", true},
		{"Keep-Alive", true},
		{"proxy-connection", true},
		{"Proxy-Connection", true},
		{"transfer-encoding", true},
		{"Transfer-Encoding", true},
		{"upgrade", true},
		{"Upgrade", true},

		// Not forbidden.
		{"te", false},
		{"TE", false},
		{"server", false},
		{"content-type", false},
		{"content-length", false},
		{"host", false},
		{"", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := IsConnectionSpecificHeader(c.name); got != c.want {
				t.Errorf("IsConnectionSpecificHeader(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestTEAllowedValue locks down the only RFC-permitted te value
// ("trailers", case-insensitive with whitespace tolerance). Any other
// value triggers a strip / anomaly. (USK-840)
func TestTEAllowedValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"trailers", true},
		{"Trailers", true},
		{"TRAILERS", true},
		{" trailers ", true},
		{"trailers, deflate", false},
		{"gzip", false},
		{"", false},
		{"chunked", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.value, func(t *testing.T) {
			if got := TEAllowedValue(c.value); got != c.want {
				t.Errorf("TEAllowedValue(%q) = %v, want %v", c.value, got, c.want)
			}
		})
	}
}

// TestBuildHeaderFieldsFromEventWithDiag_StripsConnectionSpecific drives
// BuildHeaderFieldsFromEventWithDiag through the policy-drop terminator
// header set and asserts that:
//
//   - All five forbidden names are absent from the encoded HPACK field
//     list (they would yield a PROTOCOL_ERROR on the wire).
//   - The stripped slice records the verbatim wire-name of every stripped
//     header in order.
//   - Other headers (Content-Type, Server) survive.
//
// USK-840 — this is the encoder-level proof that the strip runs;
// policy_drop_integration_test.go is the end-to-end proof that the strip
// reaches the client.
func TestBuildHeaderFieldsFromEventWithDiag_StripsConnectionSpecific(t *testing.T) {
	env := &envelope.Envelope{Direction: envelope.Receive}
	evt := &H2HeadersEvent{
		Status: 403,
		Headers: []envelope.KeyValue{
			{Name: "Content-Type", Value: "application/json; charset=utf-8"},
			{Name: "Connection", Value: "close"},
			{Name: "Server", Value: "yorishiro-proxy"},
			{Name: "Keep-Alive", Value: "timeout=5"},
			{Name: "Transfer-Encoding", Value: "chunked"},
			{Name: "Upgrade", Value: "h2c"},
			{Name: "Proxy-Connection", Value: "close"},
		},
	}

	fields, stripped := BuildHeaderFieldsFromEventWithDiag(env, evt)

	// Pseudo + Content-Type + Server should survive; nothing else.
	wantNames := map[string]string{
		":status":      "403",
		"content-type": "application/json; charset=utf-8",
		"server":       "yorishiro-proxy",
	}
	if got, want := len(fields), len(wantNames); got != want {
		t.Errorf("len(fields) = %d, want %d (fields=%v)", got, want, fields)
	}
	for _, f := range fields {
		want, ok := wantNames[f.Name]
		if !ok {
			t.Errorf("unexpected field on the wire: %q = %q", f.Name, f.Value)
			continue
		}
		if f.Value != want {
			t.Errorf("field %q value = %q, want %q", f.Name, f.Value, want)
		}
	}

	// Verbatim wire-names of stripped headers, preserved in input order.
	wantStripped := []string{
		"Connection",
		"Keep-Alive",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection",
	}
	if len(stripped) != len(wantStripped) {
		t.Fatalf("stripped = %v, want %v", stripped, wantStripped)
	}
	for i, name := range wantStripped {
		if stripped[i] != name {
			t.Errorf("stripped[%d] = %q, want %q", i, stripped[i], name)
		}
	}
}

// TestBuildHeaderFieldsFromEventWithDiag_TEValueGate verifies that `te`
// is only permitted with the exact value "trailers"; any other value is
// stripped and reported as `te: <value>` to mirror the receive-side
// H2ConnectionSpecificHeader anomaly Detail shape (USK-840).
func TestBuildHeaderFieldsFromEventWithDiag_TEValueGate(t *testing.T) {
	cases := []struct {
		name      string
		teValue   string
		wantKept  bool
		wantStrip string
	}{
		{name: "trailers_only_kept", teValue: "trailers", wantKept: true},
		{name: "uppercase_trailers_kept", teValue: "TRAILERS", wantKept: true},
		{name: "gzip_stripped", teValue: "gzip", wantKept: false, wantStrip: "te: gzip"},
		{name: "mixed_value_stripped", teValue: "trailers, deflate", wantKept: false, wantStrip: "te: trailers, deflate"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			env := &envelope.Envelope{Direction: envelope.Send}
			evt := &H2HeadersEvent{
				Method:    "GET",
				Scheme:    "https",
				Authority: "example.com",
				Path:      "/",
				Headers: []envelope.KeyValue{
					{Name: "TE", Value: c.teValue},
				},
			}
			fields, stripped := BuildHeaderFieldsFromEventWithDiag(env, evt)

			var hasTE bool
			for _, f := range fields {
				if f.Name == "te" {
					hasTE = true
					if f.Value != c.teValue {
						t.Errorf("te value lowercased? got %q want %q", f.Value, c.teValue)
					}
				}
			}
			if c.wantKept && !hasTE {
				t.Errorf("expected te kept; fields=%v stripped=%v", fields, stripped)
			}
			if !c.wantKept {
				if hasTE {
					t.Errorf("expected te stripped; fields=%v", fields)
				}
				if len(stripped) != 1 || stripped[0] != c.wantStrip {
					t.Errorf("stripped = %v, want [%q]", stripped, c.wantStrip)
				}
			}
		})
	}
}
