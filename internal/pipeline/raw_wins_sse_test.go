package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
)

// USK-1239: the SSE arm of TransformStep follows the same RFC §9.3 D4
// last-writer-wins rule as HTTP — a firing Transform rule clears the
// raw-wins marker an earlier pre_pipeline plugin set; a non-firing rule
// leaves it alone. env.Raw itself is never cleared (USK-892).

func sseRawWinsEnv() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:         "stream-1",
		FlowID:           "flow-1",
		Direction:        envelope.Receive,
		Protocol:         envelope.ProtocolSSE,
		Raw:              []byte("event: injected\ndata:x\n\n"),
		RawAuthoritative: true,
		Message:          &envelope.SSEMessage{Event: "tick", Data: "v1"},
	}
}

func sseSetDataEngine(t *testing.T, eventPattern string) *sserules.TransformEngine {
	t.Helper()
	r, err := sserules.CompileTransformRule("set", 0, "", eventPattern, "", "", nil, nil, nil,
		sserules.TransformSetData, "", "", "TRANSFORMED", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	te := sserules.NewTransformEngine()
	te.AddRule(*r)
	return te
}

func TestTransformStep_SSE_RawWinsMarker(t *testing.T) {
	cases := []struct {
		name         string
		eventPattern string
		wantMarker   bool
	}{
		{name: "firing rule clears marker", eventPattern: "^tick$", wantMarker: false},
		{name: "non-matching rule keeps marker", eventPattern: "^never$", wantMarker: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sseRawWinsEnv()
			raw := string(env.Raw)
			r := NewTransformStep(nil, nil, nil, sseSetDataEngine(t, tc.eventPattern)).Process(context.Background(), env)
			if r.Action == Drop {
				t.Fatal("unexpected Drop")
			}
			if env.RawAuthoritative != tc.wantMarker {
				t.Errorf("RawAuthoritative = %v, want %v", env.RawAuthoritative, tc.wantMarker)
			}
			if string(env.Raw) != raw {
				t.Errorf("env.Raw = %q, want untouched %q (SSE engines never clear Raw)", env.Raw, raw)
			}
		})
	}
}
