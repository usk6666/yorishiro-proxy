package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-721. Verifies that the eventAssembler does NOT treat the HEADERS frame
// following a 1xx informational HEADERS as trailers. RFC 7540 §8.1.4 / RFC
// 9113 §8.1 / RFC 8297 (Early Hints): a 1xx informational response is
// followed by the actual final response on the same stream; the wire shape
// is HEADERS(1xx) → HEADERS(final) → DATA*, NOT HEADERS → DATA → HEADERS
// (the latter being the trailers shape).
//
// Bug: assembler.go's transition to phaseBodyOrTrailers on the first
// HEADERS, combined with the unconditional "HEADERS in phaseBodyOrTrailers
// is trailers" logic, causes the second HEADERS (with :status: 200) to be
// decoded as trailers — :status is dropped as an "invalid pseudo-header in
// trailers", the remaining headers are emitted as H2TrailersEvent, and the
// channel's recv side is closed. Subsequent DATA frames carrying the actual
// 200 OK body are silently lost (or panic on send-to-closed-channel if the
// channel never closes termDone in step).
func TestAssembler_EarlyHints_ThenFinalResponse(t *testing.T) {
	cases := []struct {
		name           string
		informational  int
		final          int
		finalEndStream bool
	}{
		{"103 then 200 with body", 103, 200, false},
		{"103 then 200 bodyless", 103, 200, true},
		{"100 then 200 with body", 100, 200, false},
		{"103 then 302 redirect", 103, 302, true},
		{"103 then 404", 103, 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asm, _ := newTestAssembler()
			asm.channel.layer.role = ClientRole // proxy reads responses
			dec := hpack.NewDecoder(4096)
			enc := hpack.NewEncoder(4096, true)

			// 1xx informational HEADERS (never carries END_STREAM per RFC).
			info := []hpack.HeaderField{
				{Name: ":status", Value: itoa3(tc.informational)},
				{Name: "link", Value: "</style.css>; rel=preload; as=style"},
			}
			env1, err := asm.handleHeadersFrame(enc.Encode(info), true, false, dec, envelope.Receive)
			if err != nil {
				t.Fatalf("first HEADERS: %v", err)
			}
			if env1 == nil {
				t.Fatal("expected envelope for informational HEADERS")
			}
			evt1, ok := env1.Message.(*H2HeadersEvent)
			if !ok {
				t.Fatalf("first Message = %T, want *H2HeadersEvent", env1.Message)
			}
			if evt1.Status != tc.informational {
				t.Errorf("first Status = %d, want %d", evt1.Status, tc.informational)
			}

			// Final response HEADERS.
			final := []hpack.HeaderField{
				{Name: ":status", Value: itoa3(tc.final)},
				{Name: "content-type", Value: "text/html"},
			}
			env2, err := asm.handleHeadersFrame(enc.Encode(final), true, tc.finalEndStream, dec, envelope.Receive)
			if err != nil {
				t.Fatalf("second HEADERS: %v", err)
			}
			if env2 == nil {
				t.Fatal("expected envelope for final response")
			}
			evt2, ok := env2.Message.(*H2HeadersEvent)
			if !ok {
				t.Fatalf("after 1xx, second HEADERS treated as %T (status=%d lost as :status pseudo dropped from trailers); should be *H2HeadersEvent",
					env2.Message, tc.final)
			}
			if evt2.Status != tc.final {
				t.Errorf("second Status = %d, want %d", evt2.Status, tc.final)
			}

			// After the final response the assembler's phase depends on
			// END_STREAM: phaseDone if endStream, else phaseBodyOrTrailers
			// to allow DATA frames carrying the body.
			if tc.finalEndStream {
				if asm.phase != phaseDone {
					t.Errorf("phase = %d, want phaseDone for endStream=true", asm.phase)
				}
			} else {
				if asm.phase != phaseBodyOrTrailers {
					t.Errorf("phase = %d, want phaseBodyOrTrailers (DATA must still be acceptable)", asm.phase)
				}
			}
		})
	}
}

// 1xx + DATA must still be processable: after a 1xx informational, a DATA
// frame for the eventual final response should be deliverable. Today the
// recv side has been closed by the bug above, so the test guards both the
// phase machine AND that DATA following the final HEADERS produces an
// H2DataEvent.
func TestAssembler_EarlyHints_ThenFinalResponse_WithDataFrame(t *testing.T) {
	asm, _ := newTestAssembler()
	asm.channel.layer.role = ClientRole
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	// 103 Early Hints.
	info := []hpack.HeaderField{
		{Name: ":status", Value: "103"},
		{Name: "link", Value: "</a.css>; rel=preload"},
	}
	if _, err := asm.handleHeadersFrame(enc.Encode(info), true, false, dec, envelope.Receive); err != nil {
		t.Fatalf("103 HEADERS: %v", err)
	}

	// 200 OK final response (no END_STREAM, body to follow).
	final := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/html"},
	}
	envFinal, err := asm.handleHeadersFrame(enc.Encode(final), true, false, dec, envelope.Receive)
	if err != nil {
		t.Fatalf("200 HEADERS: %v", err)
	}
	if _, ok := envFinal.Message.(*H2HeadersEvent); !ok {
		t.Fatalf("final Message = %T, want *H2HeadersEvent", envFinal.Message)
	}

	// DATA frame for the body.
	envData := asm.handleDataFrame([]byte("<html>hi</html>"), true)
	if envData == nil {
		t.Fatal("DATA produced no envelope")
	}
	dataEvt, ok := envData.Message.(*H2DataEvent)
	if !ok {
		t.Fatalf("DATA Message = %T, want *H2DataEvent", envData.Message)
	}
	if string(dataEvt.Payload) != "<html>hi</html>" {
		t.Errorf("DATA Payload = %q", dataEvt.Payload)
	}
	if !dataEvt.EndStream {
		t.Error("DATA EndStream = false, want true")
	}
	if asm.phase != phaseDone {
		t.Errorf("after END_STREAM DATA, phase = %d, want phaseDone", asm.phase)
	}
}

// Multiple 1xx in a row (e.g., 100 Continue then 103 Early Hints) before the
// final response. Permitted by RFC 9110 §15.2.
func TestAssembler_MultipleInformational_ThenFinal(t *testing.T) {
	asm, _ := newTestAssembler()
	asm.channel.layer.role = ClientRole
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	for i, status := range []string{"100", "103", "200"} {
		hdrs := []hpack.HeaderField{{Name: ":status", Value: status}}
		env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, status == "200", dec, envelope.Receive)
		if err != nil {
			t.Fatalf("HEADERS #%d (%s): %v", i, status, err)
		}
		evt, ok := env.Message.(*H2HeadersEvent)
		if !ok {
			t.Fatalf("HEADERS #%d (%s) Message = %T, want *H2HeadersEvent", i, status, env.Message)
		}
		want := 0
		switch status {
		case "100":
			want = 100
		case "103":
			want = 103
		case "200":
			want = 200
		}
		if evt.Status != want {
			t.Errorf("HEADERS #%d Status = %d, want %d", i, evt.Status, want)
		}
	}
}

// Genuine trailers (HEADERS-after-DATA) must still be detected as trailers,
// not as a second initial HEADERS. Regression guard for the fix.
func TestAssembler_GenuineTrailers_StillDetected(t *testing.T) {
	asm, _ := newTestAssembler()
	asm.channel.layer.role = ServerRole // request stream so we exercise the path most often used by gRPC
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	// Initial HEADERS (POST request, no END_STREAM, body+trailers to follow).
	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	env1, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("initial HEADERS: %v", err)
	}
	if _, ok := env1.Message.(*H2HeadersEvent); !ok {
		t.Fatalf("initial Message = %T, want *H2HeadersEvent", env1.Message)
	}

	// DATA (no END_STREAM, trailers to follow).
	if asm.handleDataFrame([]byte("body"), false) == nil {
		t.Fatal("DATA produced no envelope")
	}

	// Trailer HEADERS — END_STREAM, post-DATA, must decode as H2TrailersEvent.
	trailers := []hpack.HeaderField{{Name: "grpc-status", Value: "0"}}
	envT, err := asm.handleHeadersFrame(enc.Encode(trailers), true, true, dec, envelope.Send)
	if err != nil {
		t.Fatalf("trailer HEADERS: %v", err)
	}
	if _, ok := envT.Message.(*H2TrailersEvent); !ok {
		t.Fatalf("trailer Message = %T, want *H2TrailersEvent", envT.Message)
	}
	if asm.phase != phaseDone {
		t.Errorf("phase = %d, want phaseDone after trailers", asm.phase)
	}
}
