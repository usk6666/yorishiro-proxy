package pipeline

import (
	"bytes"
	"context"
	"strconv"
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
