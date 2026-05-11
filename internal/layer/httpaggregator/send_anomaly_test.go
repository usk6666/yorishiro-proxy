package httpaggregator

import (
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestSend_AttachesStripAnomalyForForbiddenH2Headers verifies that
// aggregatorChannel.Send attaches an H2ConnectionSpecificHeaderStrippedOnSend
// anomaly to the HTTPMessage when the message carries any of the
// RFC 7540 §8.1.2.2 / RFC 9113 §8.2.2 connection-specific names. The
// strip itself happens at the wire encoder (http2.BuildHeaderFieldsFromEvent);
// the aggregator is the natural attachment point for the diagnostic
// because the HTTPMessage envelope is the level at which anomalies are
// stored (RFC-001 §3.1) and the inner h2 channel sees event envelopes
// only. (USK-840)
func TestSend_AttachesStripAnomalyForForbiddenH2Headers(t *testing.T) {
	inner := newFakeChannel()
	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)

	msg := &envelope.HTTPMessage{
		Status:       403,
		StatusReason: "Forbidden",
		Headers: []envelope.KeyValue{
			{Name: "Content-Type", Value: "application/json; charset=utf-8"},
			{Name: "Connection", Value: "close"},
			{Name: "Server", Value: "yorishiro-proxy"},
		},
		Body: []byte(`{"error":"blocked"}`),
	}
	env := &envelope.Envelope{
		StreamID:  "fake-stream",
		FlowID:    "fake-flow",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	if err := agg.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify the anomaly is now on the HTTPMessage.
	var found *envelope.Anomaly
	for i := range msg.Anomalies {
		if msg.Anomalies[i].Type == envelope.H2ConnectionSpecificHeaderStrippedOnSend {
			found = &msg.Anomalies[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no H2ConnectionSpecificHeaderStrippedOnSend anomaly; msg.Anomalies = %v", msg.Anomalies)
	}
	if !strings.Contains(strings.ToLower(found.Detail), "connection") {
		t.Errorf("anomaly Detail = %q, want it to reference Connection", found.Detail)
	}
}

// TestSend_NoStripAnomalyForCleanHeaders verifies that the aggregator
// does NOT attach a spurious anomaly when the HTTPMessage carries only
// h2-permitted headers. Guards against false-positive diagnostics on
// forwarded traffic that is already RFC-conformant. (USK-840)
func TestSend_NoStripAnomalyForCleanHeaders(t *testing.T) {
	inner := newFakeChannel()
	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)

	msg := &envelope.HTTPMessage{
		Status:       200,
		StatusReason: "OK",
		Headers: []envelope.KeyValue{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Server", Value: "example"},
			// te: trailers is explicitly allowed by RFC 9113 §8.2.2.
			{Name: "TE", Value: "trailers"},
		},
		Body: []byte("ok"),
	}
	env := &envelope.Envelope{
		StreamID:  "fake-stream",
		FlowID:    "fake-flow",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	if err := agg.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for _, a := range msg.Anomalies {
		if a.Type == envelope.H2ConnectionSpecificHeaderStrippedOnSend {
			t.Errorf("unexpected strip anomaly attached: %v", a)
		}
	}
}

// TestSend_AttachesStripAnomalyForInvalidTE verifies that a `te` header
// carrying anything other than the exact value "trailers" surfaces a
// strip anomaly. The wire encoder drops the header; the aggregator
// records the diagnostic with the verbatim `te: <value>` Detail shape so
// it mirrors the receive-side H2ConnectionSpecificHeader anomaly.
// (USK-840)
func TestSend_AttachesStripAnomalyForInvalidTE(t *testing.T) {
	inner := newFakeChannel()
	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
		Headers: []envelope.KeyValue{
			{Name: "TE", Value: "gzip"},
		},
	}
	env := &envelope.Envelope{
		StreamID:  "fake-stream",
		FlowID:    "fake-flow",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	if err := agg.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var found *envelope.Anomaly
	for i := range msg.Anomalies {
		if msg.Anomalies[i].Type == envelope.H2ConnectionSpecificHeaderStrippedOnSend {
			found = &msg.Anomalies[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no strip anomaly for invalid TE; msg.Anomalies = %v", msg.Anomalies)
	}
	if !strings.Contains(found.Detail, "te: gzip") {
		t.Errorf("anomaly Detail = %q, want it to contain 'te: gzip'", found.Detail)
	}
}
