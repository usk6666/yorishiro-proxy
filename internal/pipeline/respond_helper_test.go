package pipeline

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestBuildGRPCPolicyDropResponse_MatchedRulesValueIsValidH2Field pins the
// USK-1202 review finding S-1: rule IDs are operator / AI-agent authored
// and only required to be non-empty, so the synthesized
// x-yorishiro-matched-rules value must stay a valid HTTP/2 field value
// (RFC 9113 §8.2.1: no NUL / CR / LF, no leading or trailing whitespace)
// whatever the IDs contain. Visible-ASCII IDs keep their exact spelling.
func TestBuildGRPCPolicyDropResponse_MatchedRulesValueIsValidH2Field(t *testing.T) {
	env := &envelope.Envelope{
		StreamID:  "s",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Payload: []byte("x")},
	}
	for _, tc := range []struct {
		name  string
		rules []string
		want  string
	}{
		{name: "visible ascii unchanged", rules: []string{"custom:method", "grpc-catch-all"}, want: "custom:method,grpc-catch-all"},
		{name: "crlf", rules: []string{"evil\r\nx-injected: 1"}, want: "evil%0D%0Ax-injected:%201"},
		{name: "nul", rules: []string{"a\x00b"}, want: "a%00b"},
		{name: "edge whitespace", rules: []string{" pad\t"}, want: "%20pad%09"},
		{name: "separator and percent", rules: []string{"a,b", "100%"}, want: "a%2Cb,100%25"},
		{name: "non-ascii", rules: []string{"ルール"}, want: "%E3%83%AB%E3%83%BC%E3%83%AB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := buildGRPCPolicyDropResponse(env, "safety_filter", tc.rules)
			end, ok := resp.Message.(*envelope.GRPCEndMessage)
			if !ok {
				t.Fatalf("Message = %T, want *GRPCEndMessage", resp.Message)
			}
			got, ok := kvValue(end.Trailers, "x-yorishiro-matched-rules")
			if !ok {
				t.Fatalf("x-yorishiro-matched-rules missing: %v", end.Trailers)
			}
			if got != tc.want {
				t.Errorf("x-yorishiro-matched-rules = %q, want %q", got, tc.want)
			}
			for i := 0; i < len(got); i++ {
				if c := got[i]; c < 0x21 || c > 0x7e {
					t.Errorf("value %q has byte 0x%02x outside visible ASCII", got, c)
				}
			}
		})
	}
}
