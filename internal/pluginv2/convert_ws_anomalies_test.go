package pluginv2

import (
	"reflect"
	"strings"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1321: the WS dict exposes the Layer's anomalies read-only, and a
// MessageOnly rebuild carries them forward. Dropping them would let a
// plugin that touched any field turn the Layer's fail-closed refusal of a
// modified truncated message into a silent truncated forward.
func TestWSDict_AnomaliesReadOnlyAndKeptOnRebuild(t *testing.T) {
	anoms := []envelope.Anomaly{{
		Type:   envelope.AnomalyWSDecompressedTooLarge,
		Detail: "decompressed payload exceeds 16777216 bytes",
	}}
	m := &envelope.WSMessage{
		Opcode: envelope.WSText, Fin: true, Compressed: true,
		Payload: []byte("prefix"), Anomalies: anoms,
	}
	env := &envelope.Envelope{Message: m, Raw: []byte("WS")}

	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	v, found, err := d.Get(starlark.String("anomalies"))
	if err != nil || !found {
		t.Fatalf("msg[\"anomalies\"] found=%v err=%v, want present", found, err)
	}
	if l, ok := v.(*starlark.List); !ok || l.Len() != 1 {
		t.Fatalf("msg[\"anomalies\"] = %v, want a 1-element list", v)
	}

	_, err = runHook(t, &envelope.Envelope{Message: m}, `
def hook(msg):
    msg["anomalies"] = []
`)
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("anomalies write err = %v, want read-only", err)
	}

	d, err = runHook(t, env, `
def hook(msg):
    msg["payload"] = b"changed"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationMessageOnly {
		t.Fatalf("kind = %s, want MessageOnly", kind)
	}
	ws := got.(*envelope.WSMessage)
	if !reflect.DeepEqual(ws.Anomalies, anoms) {
		t.Errorf("rebuilt Anomalies = %+v, want %+v", ws.Anomalies, anoms)
	}
}
