package grpcweb

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestSend_StartRawIgnoredWithoutMalformedAnomaly — USK-1203 review F-3:
// only a Start emitted for a malformed body (AnomalyMalformedGRPCWeb*) has
// its Raw forwarded as a passthrough body. A (grpc-web, on_start) plugin
// assigning msg["raw"] on a normal Start must not become a body prefix in
// front of the re-assembled Data frames and trailer.
func TestSend_StartRawIgnoredWithoutMalformedAnomaly(t *testing.T) {
	dataFrame := EncodeFrame(false, false, []byte("ping"))
	trailerFrame := EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))
	tests := []struct {
		name     string
		role     Role
		dir      envelope.Direction
		wantBody []byte
	}{
		{"request", RoleClient, envelope.Send, dataFrame},
		{"response", RoleServer, envelope.Receive, append(append([]byte{}, dataFrame...), trailerFrame...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockChannel("s-nr")
			ch := Wrap(mock, tt.role)
			hm := sendAll(t, ch, mock,
				&envelope.Envelope{StreamID: "s-nr", Direction: tt.dir, Raw: []byte("PLUGIN-RAW"),
					Message: &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", ContentType: "application/grpc-web+proto"}},
				&envelope.Envelope{StreamID: "s-nr", Direction: tt.dir, Raw: dataFrame,
					Message: &envelope.GRPCDataMessage{Payload: []byte("ping")}},
				&envelope.Envelope{StreamID: "s-nr", Direction: tt.dir, Message: &envelope.GRPCEndMessage{}},
			)
			if !bytes.Equal(hm.Body, tt.wantBody) {
				t.Errorf("Body = %q, want %q (Start Raw must be ignored)", hm.Body, tt.wantBody)
			}
		})
	}
}

// TestSend_MalformedSentinelEndNeverFabricatesTrailer — USK-1203 review F-2:
// the Receive sentinel End carries a malformed-body anomaly. Even when the
// passthrough body has been lost (a Start without Raw), that End stands for
// "no trailer observed" and must not be re-encoded into a grpc-status: 0
// trailer frame.
func TestSend_MalformedSentinelEndNeverFabricatesTrailer(t *testing.T) {
	anom := []envelope.Anomaly{{Type: envelope.AnomalyMalformedGRPCWebLPM, Detail: "x"}}
	mock := newMockChannel("s-ms")
	ch := Wrap(mock, RoleServer)
	hm := sendAll(t, ch, mock,
		&envelope.Envelope{StreamID: "s-ms", Direction: envelope.Receive,
			Message: &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say",
				ContentType: "application/grpc-web+proto", Anomalies: anom}},
		&envelope.Envelope{StreamID: "s-ms", Direction: envelope.Receive,
			Message: &envelope.GRPCEndMessage{Anomalies: anom}},
	)
	if len(hm.Body) != 0 {
		t.Errorf("Body = %q, want empty (no trailer fabricated)", hm.Body)
	}
}
