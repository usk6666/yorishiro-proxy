package httpaggregator

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-721. The aggregator must emit a 1xx informational HTTPMessage as a
// standalone bodyless envelope and stay in phaseIdle so the next HEADERS
// (which may be another 1xx, or the final response) is absorbed as a fresh
// initial HEADERS — not as trailers attached to the 1xx envelope.
func TestAggregator_EarlyHints_EmitsAsStandaloneEnvelope(t *testing.T) {
	inner := newFakeChannel()

	// 103 Early Hints (Receive direction; never carries END_STREAM).
	infoEvt := &http2.H2HeadersEvent{
		Status:       103,
		StatusReason: "Early Hints",
		Headers:      []envelope.KeyValue{{Name: "link", Value: "</a.css>; rel=preload"}},
		EndStream:    false,
	}
	infoEnv := &envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   infoEvt,
	}
	inner.queue(infoEnv)

	// Final 200 OK with body (no END_STREAM on HEADERS).
	finalEvt := &http2.H2HeadersEvent{
		Status:       200,
		StatusReason: "OK",
		Headers:      []envelope.KeyValue{{Name: "content-type", Value: "text/html"}},
		EndStream:    false,
	}
	finalEnv := &envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   finalEvt,
	}
	inner.queue(finalEnv)

	// DATA(body, END_STREAM).
	dataEvt := &http2.H2DataEvent{Payload: []byte("<html>hi</html>"), EndStream: true}
	dataEnv := &envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   dataEvt,
	}
	inner.queue(dataEnv)

	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)

	// First Next: 103 envelope.
	got1, err := agg.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1: %v", err)
	}
	msg1, ok := got1.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Next #1 Message = %T, want *HTTPMessage", got1.Message)
	}
	if msg1.Status != 103 {
		t.Errorf("Next #1 Status = %d, want 103", msg1.Status)
	}
	if len(msg1.Trailers) != 0 {
		t.Errorf("Next #1 Trailers = %v, want empty (200's headers must NOT leak in as trailers)", msg1.Trailers)
	}
	if msg1.Body != nil || msg1.BodyBuffer != nil {
		t.Errorf("Next #1 has body/buffer set; 1xx must be bodyless")
	}

	// Second Next: 200 OK envelope WITH body.
	got2, err := agg.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2: %v", err)
	}
	msg2, ok := got2.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Next #2 Message = %T, want *HTTPMessage", got2.Message)
	}
	if msg2.Status != 200 {
		t.Errorf("Next #2 Status = %d, want 200", msg2.Status)
	}
	if string(msg2.Body) != "<html>hi</html>" {
		t.Errorf("Next #2 Body = %q, want <html>hi</html>", msg2.Body)
	}
}

// 1xx must NOT count as the in-flight message when the aggregator is in
// phaseCollectingBody. Confirms the aggregator returns to phaseIdle after
// fast-emitting a 1xx so a subsequent HEADERS does not run into the
// "unexpected H2HeadersEvent in phaseCollectingBody" guard.
func TestAggregator_EarlyHints_PhaseResetsToIdle(t *testing.T) {
	inner := newFakeChannel()

	infoEvt := &http2.H2HeadersEvent{
		Status:    103,
		Headers:   []envelope.KeyValue{{Name: "link", Value: "</x.css>"}},
		EndStream: false,
	}
	inner.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   infoEvt,
	})

	agg := Wrap(inner, RoleClient, nil, WrapOptions{}).(*aggregatorChannel)
	if _, err := agg.Next(context.Background()); err != nil {
		t.Fatalf("Next: %v", err)
	}
	agg.mu.Lock()
	defer agg.mu.Unlock()
	if agg.phase != phaseIdle {
		t.Errorf("phase = %d, want phaseIdle after 1xx fast-emit", agg.phase)
	}
	if agg.inflight != nil || agg.inflightMsg != nil {
		t.Errorf("inflight not cleared after 1xx fast-emit: inflight=%v inflightMsg=%v", agg.inflight, agg.inflightMsg)
	}
}

// Send path: 1xx informational responses MUST NOT carry END_STREAM on the
// HEADERS event, even though they have no body and no trailers. The actual
// final response follows on the same stream; closing it from the proxy
// side leaves the peer in half-closed (remote) state and the subsequent
// final-response HEADERS is rejected as a STREAM_CLOSED stream error.
//
// Reproducer: Vercel-hosted origins (buzzriya.com, …) emit 103 Early Hints
// before the actual 200; with the bug, the browser receives the 103 then
// silently drops the 200 — page never paints.
func TestAggregator_Send_Informational_NoEndStream(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"100 Continue", 100},
		{"102 Processing", 102},
		{"103 Early Hints", 103},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := newFakeChannel()
			ch := Wrap(inner, RoleServer, nil, WrapOptions{})

			err := ch.Send(context.Background(), &envelope.Envelope{
				Direction: envelope.Receive,
				Protocol:  envelope.ProtocolHTTP,
				Message: &envelope.HTTPMessage{
					Status:  tc.status,
					Headers: []envelope.KeyValue{{Name: "link", Value: "</a.css>; rel=preload"}},
				},
			})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if len(inner.sent) != 1 {
				t.Fatalf("sent = %d events, want 1 (HEADERS only, no DATA, no trailers)", len(inner.sent))
			}
			evt, ok := inner.sent[0].Message.(*http2.H2HeadersEvent)
			if !ok {
				t.Fatalf("sent[0].Message = %T, want *H2HeadersEvent", inner.sent[0].Message)
			}
			if evt.Status != tc.status {
				t.Errorf("Status = %d, want %d", evt.Status, tc.status)
			}
			if evt.EndStream {
				t.Errorf("EndStream = true on %d HEADERS; 1xx must not END_STREAM "+
					"(final response follows on the same stream — peer would reject it as STREAM_CLOSED)",
					tc.status)
			}
		})
	}
}

// Send path: a 1xx followed by a 200 with body must produce HEADERS(1xx, no
// END_STREAM) then HEADERS(200, no END_STREAM) then DATA(END_STREAM) on the
// same Channel — the wire shape that lets the peer accept the final
// response without a STREAM_CLOSED error.
func TestAggregator_Send_Informational_ThenFinal(t *testing.T) {
	inner := newFakeChannel()
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	// 103 Early Hints.
	if err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:  103,
			Headers: []envelope.KeyValue{{Name: "link", Value: "</a.css>; rel=preload"}},
		},
	}); err != nil {
		t.Fatalf("Send 103: %v", err)
	}

	// 200 OK with body.
	if err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:  200,
			Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/html"}},
			Body:    []byte("<html>hi</html>"),
		},
	}); err != nil {
		t.Fatalf("Send 200: %v", err)
	}

	if len(inner.sent) != 3 {
		t.Fatalf("sent = %d events, want 3 (HEADERS-103, HEADERS-200, DATA)", len(inner.sent))
	}

	hdr103, ok := inner.sent[0].Message.(*http2.H2HeadersEvent)
	if !ok || hdr103.Status != 103 {
		t.Fatalf("sent[0] = %T (status=%d), want *H2HeadersEvent status=103", inner.sent[0].Message, hdr103.Status)
	}
	if hdr103.EndStream {
		t.Error("103 HEADERS EndStream = true, want false")
	}

	hdr200, ok := inner.sent[1].Message.(*http2.H2HeadersEvent)
	if !ok || hdr200.Status != 200 {
		t.Fatalf("sent[1] = %T (status=%d), want *H2HeadersEvent status=200", inner.sent[1].Message, hdr200.Status)
	}
	if hdr200.EndStream {
		t.Error("200 HEADERS EndStream = true, want false (DATA follows)")
	}

	data, ok := inner.sent[2].Message.(*http2.H2DataEvent)
	if !ok {
		t.Fatalf("sent[2] = %T, want *H2DataEvent", inner.sent[2].Message)
	}
	if !data.EndStream {
		t.Error("DATA EndStream = false, want true")
	}
	if string(data.Payload) != "<html>hi</html>" {
		t.Errorf("DATA Payload = %q, want <html>hi</html>", data.Payload)
	}
}

// Regression guard: a Send-direction HEADERS (request) with Status==0 must
// NOT be misclassified as a 1xx. (Requests legitimately have :status absent,
// surfaced as Status == 0 by buildHeadersEvent.)
func TestAggregator_RequestHeaders_NotTreatedAs1xx(t *testing.T) {
	inner := newFakeChannel()

	reqEvt := &http2.H2HeadersEvent{
		Method:    "POST",
		Scheme:    "https",
		Authority: "x",
		Path:      "/login",
		Headers:   []envelope.KeyValue{{Name: "content-type", Value: "application/json"}},
		EndStream: false,
	}
	inner.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   reqEvt,
	})
	inner.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: []byte(`{"a":1}`), EndStream: true},
	})

	agg := Wrap(inner, RoleServer, nil, WrapOptions{}).(*aggregatorChannel)
	got, err := agg.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := got.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", got.Message)
	}
	if msg.Method != "POST" || msg.Path != "/login" {
		t.Errorf("Method/Path = %q %q, want POST /login", msg.Method, msg.Path)
	}
	if string(msg.Body) != `{"a":1}` {
		t.Errorf("Body = %q, want JSON body — request must absorb body, not be fast-emitted as bodyless 1xx", msg.Body)
	}
}
