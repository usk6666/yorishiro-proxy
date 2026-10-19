package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1202: a proxy-synthesized Receive-direction GRPCEndMessage (SafetyFilter
// block, intercept drop, plugin RESPOND_GRPC) on a client-facing RoleServer
// channel that has not yet relayed response HEADERS must render as a gRPC
// "Trailers-Only" response — ONE HEADERS frame carrying :status 200,
// content-type, and grpc-status with END_STREAM (gRPC PROTOCOL-HTTP2.md).
// Emitting a bare trailers block instead produces a HEADERS frame without
// :status, which RFC 9113 §8.3.2 makes malformed.

func (s *stubInner) sentSnapshot() []*envelope.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*envelope.Envelope, len(s.sent))
	copy(out, s.sent)
	return out
}

func receiveEnd(status uint32, msg string, trailers ...envelope.KeyValue) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCEndMessage{
			Status:   status,
			Message:  msg,
			Trailers: trailers,
		},
	}
}

func receiveStart() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCStartMessage{ContentType: "application/grpc"},
	}
}

func headerValue(kvs []envelope.KeyValue, name string) (string, bool) {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value, true
		}
	}
	return "", false
}

func TestChannel_SendEnd_TrailersOnlyWhenNoResponseHeaders(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	// The client's request HEADERS carry content-type application/grpc+proto;
	// the Trailers-Only response mirrors it.
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()
	drainNext(t, ch, 1)

	if err := ch.Send(context.Background(), receiveEnd(7, "blocked by safety_filter",
		envelope.KeyValue{Name: "server", Value: "yorishiro-proxy"})); err != nil {
		t.Fatalf("Send(End): %v", err)
	}

	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("inner Send count = %d, want 1 (single Trailers-Only HEADERS)", len(sent))
	}
	hdr, ok := sent[0].Message.(*http2.H2HeadersEvent)
	if !ok {
		t.Fatalf("inner Send message = %T, want *http2.H2HeadersEvent (Trailers-Only)", sent[0].Message)
	}
	if hdr.Status != 200 {
		t.Errorf("Trailers-Only :status = %d, want 200", hdr.Status)
	}
	if !hdr.EndStream {
		t.Errorf("Trailers-Only EndStream = false, want true")
	}
	if sent[0].Direction != envelope.Receive {
		t.Errorf("inner env Direction = %v, want Receive", sent[0].Direction)
	}
	if ct, _ := headerValue(hdr.Headers, "content-type"); ct != "application/grpc+proto" {
		t.Errorf("content-type = %q, want %q (mirrors request)", ct, "application/grpc+proto")
	}
	if len(hdr.Headers) == 0 || hdr.Headers[0].Name != "content-type" {
		t.Errorf("first header = %v, want content-type first", hdr.Headers)
	}
	if v, _ := headerValue(hdr.Headers, "grpc-status"); v != "7" {
		t.Errorf("grpc-status = %q, want 7", v)
	}
	if v, _ := headerValue(hdr.Headers, "grpc-message"); v == "" || !strings.Contains(v, "safety_filter") {
		t.Errorf("grpc-message = %q, want percent-encoded message containing safety_filter", v)
	}
	if v, _ := headerValue(hdr.Headers, "server"); v != "yorishiro-proxy" {
		t.Errorf("server trailer = %q, want yorishiro-proxy", v)
	}
}

func TestChannel_SendEnd_TrailersOnlyDefaultContentType(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	if err := ch.Send(context.Background(), receiveEnd(7, "")); err != nil {
		t.Fatalf("Send(End): %v", err)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("inner Send count = %d, want 1", len(sent))
	}
	hdr, ok := sent[0].Message.(*http2.H2HeadersEvent)
	if !ok {
		t.Fatalf("inner Send message = %T, want *http2.H2HeadersEvent", sent[0].Message)
	}
	if ct, _ := headerValue(hdr.Headers, "content-type"); ct != "application/grpc" {
		t.Errorf("content-type = %q, want application/grpc (no request observed)", ct)
	}
	if _, ok := headerValue(hdr.Headers, "grpc-message"); ok {
		t.Errorf("grpc-message present for empty Message: %v", hdr.Headers)
	}
}

func TestChannel_SendEnd_TrailersAfterResponseStart(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	if err := ch.Send(context.Background(), receiveStart()); err != nil {
		t.Fatalf("Send(Start): %v", err)
	}
	if err := ch.Send(context.Background(), receiveEnd(7, "blocked")); err != nil {
		t.Fatalf("Send(End): %v", err)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 2 {
		t.Fatalf("inner Send count = %d, want 2", len(sent))
	}
	if _, ok := sent[0].Message.(*http2.H2HeadersEvent); !ok {
		t.Errorf("sent[0] = %T, want *http2.H2HeadersEvent", sent[0].Message)
	}
	tr, ok := sent[1].Message.(*http2.H2TrailersEvent)
	if !ok {
		t.Fatalf("sent[1] = %T, want *http2.H2TrailersEvent (response HEADERS already relayed)", sent[1].Message)
	}
	if v, _ := headerValue(tr.Trailers, "grpc-status"); v != "7" {
		t.Errorf("grpc-status = %q, want 7", v)
	}
	if _, ok := headerValue(tr.Trailers, "content-type"); ok {
		t.Errorf("trailers carry content-type; only Trailers-Only should: %v", tr.Trailers)
	}
}

func TestChannel_SendAfterEnd_Rejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		env  *envelope.Envelope
	}{
		{name: "start", env: receiveStart()},
		{name: "data", env: &envelope.Envelope{
			StreamID:  "stream-1",
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolGRPC,
			Message:   &envelope.GRPCDataMessage{Payload: []byte("late")},
		}},
		{name: "end", env: receiveEnd(0, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newStubInner("stream-1")
			ch := Wrap(stub, nil, RoleServer)
			defer ch.Close()

			if err := ch.Send(context.Background(), receiveEnd(7, "blocked")); err != nil {
				t.Fatalf("Send(End): %v", err)
			}
			err := ch.Send(context.Background(), tt.env)
			if !errors.Is(err, errSendAfterEnd) {
				t.Errorf("Send(%s) after End err = %v, want errSendAfterEnd", tt.name, err)
			}
			if got := len(stub.sentSnapshot()); got != 1 {
				t.Errorf("inner Send count = %d, want 1 (nothing after END_STREAM)", got)
			}
		})
	}
}

// TestChannel_SendEnd_SendDirectionUnaffected guards that the Trailers-Only
// rendering is a Receive-only rule: a RoleClient (upstream-facing) Send-
// direction End keeps the trailers form.
func TestChannel_SendEnd_SendDirectionUnaffected(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	env := receiveEnd(0, "")
	env.Direction = envelope.Send
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send(End): %v", err)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("inner Send count = %d, want 1", len(sent))
	}
	if _, ok := sent[0].Message.(*http2.H2TrailersEvent); !ok {
		t.Errorf("Send-direction End = %T, want *http2.H2TrailersEvent", sent[0].Message)
	}
}
