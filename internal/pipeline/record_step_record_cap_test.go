package pipeline

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// USK-1408: the RecordStep cap (max_record_body_size) cuts only the
// recorded copy. Whenever it cuts the raw bytes it keeps their leading
// bytes and marks the flow with http_anomaly_raw_body_truncated; whenever
// it cuts the L7 body it keeps the prefix and sets Flow.BodyTruncated.

const rawTruncatedKey = "http_anomaly_raw_body_truncated"

// recordCapResponse builds a Receive HTTP/1.x response envelope the shape
// internal/layer/http1 produces: Raw = header section (+ body when not
// spilled), RawBuffer = spilled body bytes, Body = decoded body.
func recordCapResponse(bodyLen int, spilled bool) (*envelope.Envelope, []byte) {
	header := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(bodyLen) + "\r\n\r\n")
	body := bytes.Repeat([]byte("R"), bodyLen)
	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Status: 200, StatusReason: "OK", Body: body},
	}
	if spilled {
		env.Raw = header
		env.RawBuffer = bodybuf.NewMemory(body)
	} else {
		env.Raw = append(append([]byte{}, header...), body...)
	}
	return env, append(append([]byte{}, header...), body...)
}

func TestRecordStep_RecordCap_RawTruncationMarked(t *testing.T) {
	cases := []struct {
		name    string
		cap     int64
		bodyLen int
		spilled bool
		wantCut bool
	}{
		{name: "spilled raw over cap", cap: 32, bodyLen: 100, spilled: true, wantCut: true},
		{name: "in-memory raw over cap", cap: 1024, bodyLen: 4096, wantCut: true},
		{name: "spilled raw under cap", cap: 64 << 10, bodyLen: 100, spilled: true},
		{name: "in-memory raw under cap", cap: 64 << 10, bodyLen: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil, WithMaxBodySize(tc.cap))
			env, wire := recordCapResponse(tc.bodyLen, tc.spilled)
			if env.RawBuffer != nil {
				t.Cleanup(func() { _ = env.RawBuffer.Release() })
			}

			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			_, marked := fl.Metadata[rawTruncatedKey]
			if !tc.wantCut {
				if !bytes.Equal(fl.RawBytes, wire) {
					t.Errorf("RawBytes len = %d, want the full %d wire bytes", len(fl.RawBytes), len(wire))
				}
				if marked {
					t.Errorf("metadata %s = %q, want absent when nothing was cut", rawTruncatedKey, fl.Metadata[rawTruncatedKey])
				}
				return
			}
			if int64(len(fl.RawBytes)) != tc.cap {
				t.Errorf("RawBytes len = %d, want cap %d", len(fl.RawBytes), tc.cap)
			}
			if !bytes.Equal(fl.RawBytes, wire[:min(int64(len(wire)), tc.cap)]) {
				t.Errorf("RawBytes is not the leading %d wire bytes", tc.cap)
			}
			if !marked {
				t.Errorf("metadata %s absent, want it set when RawBytes was cut (metadata=%v)", rawTruncatedKey, fl.Metadata)
			}
		})
	}
}

func TestRecordStep_RecordCap_InMemoryBodyTruncated(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithMaxBodySize(1024))
	env, _ := recordCapResponse(4096, false)

	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if len(fl.Body) != 1024 {
		t.Errorf("Body len = %d, want 1024", len(fl.Body))
	}
	if !fl.BodyTruncated {
		t.Error("BodyTruncated = false, want true for a 4 KiB body over a 1 KiB record cap")
	}
	// The live message is untouched — only the recorded copy is cut.
	if got := len(env.Message.(*envelope.HTTPMessage).Body); got != 4096 {
		t.Errorf("envelope Body len = %d after Process, want 4096 (record must not mutate the wire copy)", got)
	}
	if got := len(env.Raw); got <= 4096 {
		t.Errorf("envelope Raw len = %d after Process, want the full wire bytes", got)
	}
}

// TestRecordStep_RecordCap_ParserTruncationMerged pins that a record-cap cut
// keeps a parser-side http_anomaly_raw_body_truncated detail already carried
// by the message and appends the record-cap note after it.
func TestRecordStep_RecordCap_ParserTruncationMerged(t *testing.T) {
	const parserDetail = "raw body capture truncated at 4096 bytes"
	cases := []struct {
		name    string
		cap     int64
		wantCut bool
	}{
		{name: "parser cut plus record cut", cap: 1024, wantCut: true},
		{name: "parser cut only", cap: 64 << 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil, WithMaxBodySize(tc.cap))
			env, _ := recordCapResponse(4096, false)
			m := env.Message.(*envelope.HTTPMessage)
			m.Anomalies = []envelope.Anomaly{{Type: envelope.AnomalyRawBodyTruncated, Detail: parserDetail}}

			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			got := w.flows[0].Metadata[rawTruncatedKey]
			if !strings.HasPrefix(got, parserDetail) {
				t.Errorf("metadata %s = %q, want it to keep the parser detail %q first", rawTruncatedKey, got, parserDetail)
			}
			hasRecordNote := strings.Contains(got, "max_record_body_size")
			if hasRecordNote != tc.wantCut {
				t.Errorf("metadata %s = %q, record-cap note present = %v, want %v", rawTruncatedKey, got, hasRecordNote, tc.wantCut)
			}
		})
	}
}

// TestRecordStep_RecordCap_SpilledFileBacked pins the disk-spill raw path:
// the recorded prefix is byte-identical to the wire prefix whether the cut
// falls inside the body or inside the header section.
func TestRecordStep_RecordCap_SpilledFileBacked(t *testing.T) {
	cases := []struct {
		name    string
		cap     int64 // 0 = exactly the full wire length
		bodyLen int
		wantCut bool
	}{
		{name: "cut inside body", cap: 100, bodyLen: 8 << 10, wantCut: true},
		{name: "cut inside header", cap: 10, bodyLen: 8 << 10, wantCut: true},
		{name: "exactly at cap", cap: 0, bodyLen: 512},
		{name: "under cap", cap: 64 << 10, bodyLen: 512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, wire := recordCapResponse(tc.bodyLen, true)
			_ = env.RawBuffer.Release()
			fb, err := bodybuf.NewFile(t.TempDir(), "rec", 0)
			if err != nil {
				t.Fatalf("NewFile: %v", err)
			}
			t.Cleanup(func() { _ = fb.Release() })
			if _, err := fb.Write(wire[len(env.Raw):]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			env.RawBuffer = fb
			limit := tc.cap
			if limit == 0 {
				limit = int64(len(wire))
			}
			w := &mockWriter{}
			step := NewRecordStep(w, nil, WithMaxBodySize(limit))

			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			want := wire
			if int64(len(want)) > limit {
				want = wire[:limit]
			}
			if !bytes.Equal(fl.RawBytes, want) {
				t.Errorf("RawBytes len = %d, want the leading %d wire bytes", len(fl.RawBytes), len(want))
			}
			if _, marked := fl.Metadata[rawTruncatedKey]; marked != tc.wantCut {
				t.Errorf("metadata %s present = %v, want %v (metadata=%v)", rawTruncatedKey, marked, tc.wantCut, fl.Metadata)
			}
		})
	}
}

// TestRecordStep_RecordCap_ModifiedVariant pins that the modified variant's
// RawBytes re-encoded by the WireEncoder is bounded by the record cap too,
// and that the truncation mark follows the stored bytes. The live envelope
// is never cut.
func TestRecordStep_RecordCap_ModifiedVariant(t *testing.T) {
	cases := []struct {
		name       string
		modBodyLen int
		wantCut    bool
	}{
		// Header-only edit on a 4 KiB response: the re-encoded image is
		// still over the 1 KiB cap.
		{name: "header edit over cap", modBodyLen: 4096, wantCut: true},
		// Body shrunk under the cap: the re-encoded image fits, so the
		// mark derived from the ingress Raw must not survive.
		{name: "body shrunk under cap", modBodyLen: 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const recCap = 1024
			snap, _ := recordCapResponse(4096, false)
			current, _ := recordCapResponse(4096, false)
			cm := current.Message.(*envelope.HTTPMessage)
			cm.Headers = []envelope.KeyValue{{Name: "X-Edited", Value: "1"}}
			cm.Body = bytes.Repeat([]byte("M"), tc.modBodyLen)
			encoded := append([]byte("HTTP/1.1 200 OK\r\nX-Edited: 1\r\nContent-Length: "+strconv.Itoa(tc.modBodyLen)+"\r\n\r\n"), cm.Body...)

			w := &mockWriter{}
			step := NewRecordStep(w, nil,
				WithMaxBodySize(recCap),
				WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
					return append([]byte(nil), encoded...), nil
				}),
			)

			step.Process(withSnapshot(context.Background(), snap), current)

			if len(w.flows) != 2 {
				t.Fatalf("expected 2 flows (variant pair), got %d", len(w.flows))
			}
			origFlow, modFlow := w.flows[0], w.flows[1]
			if int64(len(origFlow.RawBytes)) != recCap {
				t.Errorf("original RawBytes len = %d, want cap %d", len(origFlow.RawBytes), recCap)
			}
			want := encoded
			if len(want) > recCap {
				want = encoded[:recCap]
			}
			if !bytes.Equal(modFlow.RawBytes, want) {
				t.Errorf("modified RawBytes len = %d, want the leading %d encoded bytes", len(modFlow.RawBytes), len(want))
			}
			if _, marked := modFlow.Metadata[rawTruncatedKey]; marked != tc.wantCut {
				t.Errorf("modified metadata %s present = %v, want %v (value=%q)", rawTruncatedKey, marked, tc.wantCut, modFlow.Metadata[rawTruncatedKey])
			}
			if got := len(cm.Body); got != tc.modBodyLen {
				t.Errorf("live Body len = %d after Process, want %d (record must not mutate the wire copy)", got, tc.modBodyLen)
			}
		})
	}
}
