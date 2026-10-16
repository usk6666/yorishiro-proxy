package job

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

// TestFuzzHTTPSource_PathPayloadSentVerbatim pins USK-1139 F-3: a path
// position payload is wire bytes and must reach the envelope unchanged —
// "%2e%2e" must not be re-escaped to "%252e%252e" — and the untouched part
// of a recorded wire path keeps its original encoding.
func TestFuzzHTTPSource_PathPayloadSentVerbatim(t *testing.T) {
	tests := []struct {
		name  string
		match string
		want  string
	}{
		{name: "whole path", match: "", want: "/%2e%2e/etc/passwd"},
		{name: "regex segment", match: "^/api", want: "/%2e%2e/etc/passwd/%61dmin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := makeHTTPFuzzFlow()
			f.URL = envelope.URLFromWirePath("https", "example.com", "/api/%61dmin", "q=test")
			reader := &mockFlowReader{flows: map[string][]*flow.Flow{"stream-1": {f}}}
			src, err := NewFuzzHTTPSource(FuzzHTTPConfig{
				Reader:     reader,
				StreamID:   "stream-1",
				AttackType: "sequential",
				Positions: []fuzzer.Position{
					{ID: "pos-0", Location: "path", Match: tt.match, PayloadSet: "p"},
				},
				ResolvedPayloads: map[string][]string{"p": {"/%2e%2e/etc/passwd"}},
			})
			if err != nil {
				t.Fatalf("NewFuzzHTTPSource: %v", err)
			}
			env, err := src.Next(context.Background())
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.Path != tt.want {
				t.Errorf("Path = %q, want %q (payload must be sent verbatim)", msg.Path, tt.want)
			}
			if msg.RawQuery != "q=test" {
				t.Errorf("RawQuery = %q, want q=test", msg.RawQuery)
			}
		})
	}
}
