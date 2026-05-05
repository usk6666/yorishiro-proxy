package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// Test the event-producing eventAssembler: HEADERS + CONTINUATION fold
// into H2HeadersEvent, DATA folds into H2DataEvent, HEADERS-after-DATA
// folds into H2TrailersEvent.

func newTestAssembler() (*eventAssembler, *channel) {
	l := &Layer{role: ServerRole}
	ch := &channel{layer: l, streamID: "fake-ch-id", h2Stream: 1}
	asm := newEventAssembler(1, ch)
	return asm, ch
}

func TestAssembler_InitialHeadersEndStream(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/foo"},
	}
	enc := hpack.NewEncoder(4096, true)
	fragment := enc.Encode(hdrs)

	env, err := asm.handleHeadersFrame(fragment, true, true, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	if env == nil {
		t.Fatal("env = nil, want envelope")
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
	}
	if evt.Method != "GET" || evt.Path != "/foo" {
		t.Errorf("evt = %+v", evt)
	}
	if !evt.EndStream {
		t.Error("EndStream = false, want true")
	}
	if asm.phase != phaseDone {
		t.Errorf("phase = %d, want phaseDone", asm.phase)
	}
}

func TestAssembler_HeadersThenDataThenTrailers(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	// Initial HEADERS (no END_STREAM).
	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	if env == nil {
		t.Fatal("expected initial HeadersEvent envelope")
	}
	if _, ok := env.Message.(*H2HeadersEvent); !ok {
		t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
	}
	if asm.phase != phaseBodyOrTrailers {
		t.Errorf("phase = %d, want phaseBodyOrTrailers", asm.phase)
	}

	// DATA event.
	dataEnv := asm.handleDataFrame([]byte("abc"), false)
	if dataEnv == nil {
		t.Fatal("expected data envelope")
	}
	if _, ok := dataEnv.Message.(*H2DataEvent); !ok {
		t.Fatalf("Message = %T, want *H2DataEvent", dataEnv.Message)
	}

	// Trailer HEADERS (END_STREAM).
	trail := []hpack.HeaderField{{Name: "grpc-status", Value: "0"}}
	trailEnv, err := asm.handleHeadersFrame(enc.Encode(trail), true, true, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame (trailers): %v", err)
	}
	if trailEnv == nil {
		t.Fatal("expected trailers envelope")
	}
	tEvt, ok := trailEnv.Message.(*H2TrailersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2TrailersEvent", trailEnv.Message)
	}
	if len(tEvt.Trailers) != 1 || tEvt.Trailers[0].Name != "grpc-status" {
		t.Errorf("trailers = %+v", tEvt.Trailers)
	}
	if asm.phase != phaseDone {
		t.Errorf("phase = %d, want phaseDone", asm.phase)
	}
}

func TestAssembler_ContinuationFloodGuard(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)

	// Exceed maxHeaderFragmentBytes in one shot.
	big := make([]byte, maxHeaderFragmentBytes+1)
	_, err := asm.handleHeadersFrame(big, false, false, dec, envelope.Send)
	if err == nil {
		t.Fatal("expected ConnError for oversized fragment")
	}
}

func TestAssembler_TrailersWithPseudoHeaderFlagsAnomaly(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	// Initial HEADERS.
	init := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	_, _ = asm.handleHeadersFrame(enc.Encode(init), true, false, dec, envelope.Send)

	// DATA to transition into phaseBodyOrTrailers via HEADERS-after-DATA.
	_ = asm.handleDataFrame([]byte{}, false)

	// Trailer HEADERS with a pseudo-header in trailers (invalid).
	trail := []hpack.HeaderField{
		{Name: ":foo", Value: "bar"},
		{Name: "trailer-ok", Value: "v"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(trail), true, true, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	tEvt := env.Message.(*H2TrailersEvent)
	if len(tEvt.Trailers) != 1 || tEvt.Trailers[0].Name != "trailer-ok" {
		t.Errorf("trailers = %+v, want only 'trailer-ok' (pseudo dropped)", tEvt.Trailers)
	}
	foundAnomaly := false
	for _, a := range tEvt.Anomalies {
		if a.Type == envelope.H2InvalidPseudoHeader {
			foundAnomaly = true
		}
	}
	if !foundAnomaly {
		t.Errorf("anomalies = %+v, want H2InvalidPseudoHeader", tEvt.Anomalies)
	}
}

func TestAssembler_DataEndStreamTransitionsDone(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	init := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	_, _ = asm.handleHeadersFrame(enc.Encode(init), true, false, dec, envelope.Send)

	env := asm.handleDataFrame([]byte("done"), true)
	if env == nil {
		t.Fatal("nil envelope")
	}
	data := env.Message.(*H2DataEvent)
	if !data.EndStream {
		t.Error("EndStream = false, want true")
	}
	if asm.phase != phaseDone {
		t.Errorf("phase = %d, want phaseDone", asm.phase)
	}
}
