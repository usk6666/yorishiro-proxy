package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1239: RFC §9.3 D4 last-writer-wins for an SSE intercept modify. A
// held event whose envelope carries a plugin msg["raw"] write
// (RawAuthoritative) must hand the wire back to the Message path when
// the operator changes a field; otherwise the session would write the
// plugin bytes and silently drop the operator's edit. A release that
// changes nothing keeps the marker so the plugin bytes still go out.
// Raw is never cleared on the SSE path (USK-892).
func TestApplySSEModify_RawWinsMarker(t *testing.T) {
	str := func(s string) *string { return &s }
	u32 := func(v uint32) *uint32 { return &v }
	cases := []struct {
		name       string
		params     *sseMessageModify
		wantMarker bool
	}{
		{name: "nil params keeps marker", params: nil, wantMarker: true},
		{name: "all-nil fields keeps marker", params: &sseMessageModify{}, wantMarker: true},
		{name: "data set clears marker", params: &sseMessageModify{Data: str("operator")}, wantMarker: false},
		{name: "event set clears marker", params: &sseMessageModify{Event: str("op")}, wantMarker: false},
		{name: "id set clears marker", params: &sseMessageModify{ID: str("9")}, wantMarker: false},
		{name: "retry set clears marker", params: &sseMessageModify{RetryMs: u32(1500)}, wantMarker: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("event: injected\ndata:x\n\n")
			msg := &envelope.SSEMessage{Event: "tick", Data: "v1"}
			env := &envelope.Envelope{
				Direction:        envelope.Receive,
				Protocol:         envelope.ProtocolSSE,
				Raw:              raw,
				RawAuthoritative: true,
				Message:          msg,
			}
			out, err := applySSEModify(env, msg, tc.params)
			if err != nil {
				t.Fatalf("applySSEModify: %v", err)
			}
			if out.RawAuthoritative != tc.wantMarker {
				t.Errorf("RawAuthoritative = %v, want %v", out.RawAuthoritative, tc.wantMarker)
			}
			if string(out.Raw) != string(raw) {
				t.Errorf("Raw = %q, want kept %q", out.Raw, raw)
			}
			if !env.RawAuthoritative {
				t.Error("input envelope marker mutated; applySSEModify must work on a clone")
			}
		})
	}
}
