package httpaggregator

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1199: on the aggregator path a body-bearing stream's first
// wire_level=h2-frame overlay (Message=nil) reaches RecordStep BEFORE the
// semantic HTTPMessage, and RecordStep caches its capture_scope decision
// on that first Send envelope. The overlay must therefore carry the
// wire-observed request-head fields of its stream (the HEADERS frame's
// :method / :path / query / :authority) on its Context, exactly as the
// semantic envelope's Context already does (USK-833).
//
// Fixture shape: H2HeadersEvent followed by H2DataEvent envelopes, the
// event sequence internal/layer/http2 emits for a request with a body
// (same shape as h2_frame_callback_test.go). The DATA event Context does
// not carry Request* fields — that is what the real http2 Layer produces.

// TestChannel_H2FrameRecordCallback_SendCarriesRequestHead verifies the
// Send-direction overlay carries the HEADERS request-head fields while
// keeping the DATA event's own Context (ReceivedAt, ConnID, TargetHost).
func TestChannel_H2FrameRecordCallback_SendCarriesRequestHead(t *testing.T) {
	stub := newFakeChannel()

	var observed []envelope.EnvelopeContext
	cb := func(env *envelope.Envelope) { observed = append(observed, env.Context) }

	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))

	headersAt := time.Unix(1000, 0)
	data1At := time.Unix(1001, 0)
	data2At := time.Unix(1002, 0)
	baseCtx := envelope.EnvelopeContext{ConnID: "conn-1199", TargetHost: "a.example.com:443"}

	hctx := baseCtx
	hctx.ReceivedAt = headersAt
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 0, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "POST", Path: "/api/usk1199", RawQuery: "case=post",
			Scheme: "https", Authority: "b.example.com:8443",
		},
		Raw:     []byte("HEADERS"),
		Context: hctx,
	})
	d1ctx := baseCtx
	d1ctx.ReceivedAt = data1At
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 1, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: []byte("a=")},
		Raw:      []byte("a="),
		Context:  d1ctx,
	})
	d2ctx := baseCtx
	d2ctx.ReceivedAt = data2At
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 2, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: []byte("1"), EndStream: true},
		Raw:      []byte("1"),
		Context:  d2ctx,
	})

	out, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if out.Context.RequestAuthority != "b.example.com:8443" {
		t.Errorf("semantic Context.RequestAuthority = %q, want %q", out.Context.RequestAuthority, "b.example.com:8443")
	}

	if len(observed) != 2 {
		t.Fatalf("callback fired %d times, want 2", len(observed))
	}
	wantAt := []time.Time{data1At, data2At}
	for i, c := range observed {
		if c.RequestMethod != "POST" {
			t.Errorf("overlay[%d].Context.RequestMethod = %q, want POST", i, c.RequestMethod)
		}
		if c.RequestPath != "/api/usk1199" {
			t.Errorf("overlay[%d].Context.RequestPath = %q, want /api/usk1199", i, c.RequestPath)
		}
		if c.RequestRawQuery != "case=post" {
			t.Errorf("overlay[%d].Context.RequestRawQuery = %q, want case=post", i, c.RequestRawQuery)
		}
		if c.RequestAuthority != "b.example.com:8443" {
			t.Errorf("overlay[%d].Context.RequestAuthority = %q, want b.example.com:8443 (wire :authority, verbatim)", i, c.RequestAuthority)
		}
		if !c.ReceivedAt.Equal(wantAt[i]) {
			t.Errorf("overlay[%d].Context.ReceivedAt = %v, want the DATA event's %v", i, c.ReceivedAt, wantAt[i])
		}
		if c.ConnID != "conn-1199" || c.TargetHost != "a.example.com:443" {
			t.Errorf("overlay[%d] connection context = (%q, %q), want (conn-1199, a.example.com:443)", i, c.ConnID, c.TargetHost)
		}
	}
}

// TestChannel_H2FrameRecordCallback_ReceiveCarriesPairedRequestHead
// verifies a Receive-direction overlay on the upstream-side (RoleClient)
// aggregator carries the paired request's head fields, captured when the
// request was sent through the same aggregator.
func TestChannel_H2FrameRecordCallback_ReceiveCarriesPairedRequestHead(t *testing.T) {
	stub := newFakeChannel()

	var observed []envelope.EnvelopeContext
	cb := func(env *envelope.Envelope) { observed = append(observed, env.Context) }

	ch := Wrap(stub, RoleClient, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))

	if err := ch.Send(context.Background(), &envelope.Envelope{
		StreamID: "fake-stream", Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST", Scheme: "https", Authority: "b.example.com",
			Path: "/api/usk1199", RawQuery: "case=post", Body: []byte("a=1"),
		},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 0, Direction: envelope.Receive,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2HeadersEvent{Status: 200},
		Raw:      []byte("HEADERS"),
	})
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 1, Direction: envelope.Receive,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: []byte("ok"), EndStream: true},
		Raw:      []byte("ok"),
	})

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(observed) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(observed))
	}
	c := observed[0]
	if c.RequestMethod != "POST" || c.RequestPath != "/api/usk1199" || c.RequestRawQuery != "case=post" || c.RequestAuthority != "b.example.com" {
		t.Errorf("Receive overlay request head = (method %q, path %q, query %q, authority %q), want (POST, /api/usk1199, case=post, b.example.com)",
			c.RequestMethod, c.RequestPath, c.RequestRawQuery, c.RequestAuthority)
	}
}
