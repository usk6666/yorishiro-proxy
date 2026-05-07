package http2

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// hasAnomaly reports whether the slice contains an anomaly of the given
// type. Detail substring matching is left to callers via hasAnomalyDetail.
func hasAnomaly(in []envelope.Anomaly, t envelope.AnomalyType) bool {
	for _, a := range in {
		if a.Type == t {
			return true
		}
	}
	return false
}

// hasAnomalyDetail reports whether the slice contains an anomaly of the
// given type whose Detail contains substr (case-sensitive).
func hasAnomalyDetail(in []envelope.Anomaly, t envelope.AnomalyType, substr string) bool {
	for _, a := range in {
		if a.Type == t && strings.Contains(a.Detail, substr) {
			return true
		}
	}
	return false
}

// TestAssembler_ClassicCONNECT_NoProtocol verifies that a CONNECT request
// without :protocol (the pre-HTTP/2-extended-CONNECT shape, e.g. for
// proxy CONNECT tunnels) parses cleanly: Method == "CONNECT", Protocol
// stays empty, and no :protocol-related anomaly is raised. RFC 9113
// §8.5 says classic CONNECT also does not carry :scheme / :path; the
// USK-764 changes must not introduce false positives for that case.
func TestAssembler_ClassicCONNECT_NoProtocol(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "example.com:443"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	if env == nil {
		t.Fatal("env = nil, want envelope")
	}
	evt := env.Message.(*H2HeadersEvent)
	if evt.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", evt.Method)
	}
	if evt.ConnectProtocol != "" {
		t.Errorf("Protocol = %q, want empty (classic CONNECT)", evt.ConnectProtocol)
	}
	if hasAnomaly(evt.Anomalies, envelope.H2InvalidPseudoHeader) {
		t.Errorf("classic CONNECT raised H2InvalidPseudoHeader; anomalies=%+v", evt.Anomalies)
	}
}

// TestAssembler_ExtendedCONNECT_Websocket verifies the happy path for
// RFC 8441 §4 extended CONNECT: :method=CONNECT + :protocol=websocket +
// :scheme + :path + :authority parses, Protocol is propagated verbatim,
// and no anomaly is raised.
func TestAssembler_ExtendedCONNECT_Websocket(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "echo.example.com"},
		{Name: ":path", Value: "/chat"},
		{Name: ":protocol", Value: "websocket"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	evt := env.Message.(*H2HeadersEvent)
	if evt.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", evt.Method)
	}
	if evt.ConnectProtocol != "websocket" {
		t.Errorf("Protocol = %q, want websocket", evt.ConnectProtocol)
	}
	if evt.Path != "/chat" {
		t.Errorf("Path = %q, want /chat", evt.Path)
	}
	if evt.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", evt.Scheme)
	}
	if evt.Authority != "echo.example.com" {
		t.Errorf("Authority = %q, want echo.example.com", evt.Authority)
	}
	if hasAnomaly(evt.Anomalies, envelope.H2InvalidPseudoHeader) {
		t.Errorf("extended CONNECT raised H2InvalidPseudoHeader; anomalies=%+v", evt.Anomalies)
	}
}

// TestAssembler_ProtocolPseudo_OnNonCONNECT_FlagsAnomaly verifies that a
// :protocol pseudo-header with :method != CONNECT is rejected via an
// H2InvalidPseudoHeader anomaly. The Detail string carries the offending
// method so operators can correlate to the request.
func TestAssembler_ProtocolPseudo_OnNonCONNECT_FlagsAnomaly(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	evt := env.Message.(*H2HeadersEvent)

	if evt.ConnectProtocol != "" {
		t.Errorf("Protocol = %q, want empty (precondition not met)", evt.ConnectProtocol)
	}
	if !hasAnomalyDetail(evt.Anomalies, envelope.H2InvalidPseudoHeader, ":protocol with :method=GET") {
		t.Errorf("expected H2InvalidPseudoHeader detail :protocol with :method=GET; anomalies=%+v", evt.Anomalies)
	}
}

// TestAssembler_DuplicateProtocol_FlagsAnomaly verifies the
// duplicate-pseudo-header path still fires for :protocol via the existing
// recordOnce machinery (so the new field reuses the same dup detection
// the other pseudo-headers already enjoy).
func TestAssembler_DuplicateProtocol_FlagsAnomaly(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
		{Name: ":protocol", Value: "webtransport"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	evt := env.Message.(*H2HeadersEvent)

	if !hasAnomalyDetail(evt.Anomalies, envelope.H2DuplicatePseudoHeader, ":protocol") {
		t.Errorf("expected H2DuplicatePseudoHeader for :protocol; anomalies=%+v", evt.Anomalies)
	}
}

// TestAssembler_ExtendedCONNECT_MissingScheme_FlagsAnomaly verifies that
// an extended CONNECT (CONNECT + :protocol) without :scheme surfaces an
// H2InvalidPseudoHeader anomaly per RFC 8441 §4.
func TestAssembler_ExtendedCONNECT_MissingScheme_FlagsAnomaly(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/chat"},
		{Name: ":protocol", Value: "websocket"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	evt := env.Message.(*H2HeadersEvent)
	if !hasAnomalyDetail(evt.Anomalies, envelope.H2InvalidPseudoHeader, "extended CONNECT missing :scheme") {
		t.Errorf("expected missing :scheme anomaly; got %+v", evt.Anomalies)
	}
}

// TestAssembler_ExtendedCONNECT_MissingPath_FlagsAnomaly verifies that an
// extended CONNECT without :path surfaces an H2InvalidPseudoHeader anomaly
// per RFC 8441 §4.
func TestAssembler_ExtendedCONNECT_MissingPath_FlagsAnomaly(t *testing.T) {
	asm, _ := newTestAssembler()
	dec := hpack.NewDecoder(4096)
	enc := hpack.NewEncoder(4096, true)

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":protocol", Value: "websocket"},
	}
	env, err := asm.handleHeadersFrame(enc.Encode(hdrs), true, false, dec, envelope.Send)
	if err != nil {
		t.Fatalf("handleHeadersFrame: %v", err)
	}
	evt := env.Message.(*H2HeadersEvent)
	if !hasAnomalyDetail(evt.Anomalies, envelope.H2InvalidPseudoHeader, "extended CONNECT missing :path") {
		t.Errorf("expected missing :path anomaly; got %+v", evt.Anomalies)
	}
}
