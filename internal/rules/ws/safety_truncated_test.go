package ws

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1321 (U2): a payload the WS Layer truncated at its decompression cap
// cannot be fully scanned, so an engine that has any payload/body rule
// blocks it (fail closed) even when the scanned prefix does not match.
func TestSafetyEngine_TruncatedPayload_FailsClosed(t *testing.T) {
	truncated := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte("harmless prefix"),
		Anomalies: []envelope.Anomaly{{
			Type:   envelope.AnomalyWSDecompressedTooLarge,
			Detail: "decompressed payload exceeds 16777216 bytes",
		}},
	}
	whole := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("harmless prefix")}

	t.Run("preset blocks truncated payload", func(t *testing.T) {
		e := NewSafetyEngine()
		if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
			t.Fatal(err)
		}
		v := e.CheckInput(context.Background(), truncated)
		if v == nil {
			t.Fatal("CheckInput(truncated) = nil, want a fail-closed violation")
		}
		if v.Target != string(TargetPayload) {
			t.Errorf("violation Target = %q, want %q", v.Target, TargetPayload)
		}
		if all := e.CheckInputAll(context.Background(), truncated); len(all) == 0 {
			t.Error("CheckInputAll(truncated) = empty, want a fail-closed violation")
		}
		if v := e.CheckInput(context.Background(), whole); v != nil {
			t.Errorf("CheckInput(untruncated harmless) = %+v, want nil", v)
		}
	})

	t.Run("no rules forwards", func(t *testing.T) {
		e := NewSafetyEngine()
		if v := e.CheckInput(context.Background(), truncated); v != nil {
			t.Errorf("CheckInput with no rules = %+v, want nil", v)
		}
	})

	t.Run("opcode-only rule does not fail closed", func(t *testing.T) {
		e := NewSafetyEngine()
		pat, err := common.CompilePattern(`^0x9$`)
		if err != nil {
			t.Fatal(err)
		}
		e.AddRule(common.CompiledRule{ID: "ping", Name: "ping", Pattern: pat, Targets: []common.Target{TargetOpcode}})
		if v := e.CheckInput(context.Background(), truncated); v != nil {
			t.Errorf("CheckInput with opcode-only rule = %+v, want nil", v)
		}
	})
}
