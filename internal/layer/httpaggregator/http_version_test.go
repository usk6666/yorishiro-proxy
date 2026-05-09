package httpaggregator

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestAggregator_HTTPVersion_H2 pins that an HTTP/2 stream emitted with
// scheme="https" (the standard production path: ALPN negotiates h2 over
// TLS) yields HTTPMessage.HTTPVersion == "h2" (USK-788).
func TestAggregator_HTTPVersion_H2(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Scheme: "https", Authority: "x", Path: "/h2",
			EndStream: true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersionH2 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersionH2)
	}
}

// TestAggregator_HTTPVersion_H2C pins that an HTTP/2 stream emitted with
// scheme="http" (the h2c handler path — internal/connector/h2c_handler.go
// constructs the Layer with WithScheme("http")) yields HTTPMessage.HTTPVersion
// == "h2c" (USK-788). This is the cleartext-HTTP/2 wire-version signal
// downstream consumers cannot derive from ALPN (h2c is not negotiated via
// ALPN in production).
func TestAggregator_HTTPVersion_H2C(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Scheme: "http", Authority: "x", Path: "/h2c",
			EndStream: true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersionH2C {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersionH2C)
	}
}

// TestAggregator_HTTPVersion_Response_H2 pins that the response side of
// an HTTP/2 exchange (server → client) also stamps HTTPVersion="h2" when
// the Layer scheme is "https" (USK-788). The version is read from the
// per-event Scheme field, which the HTTP/2 Layer copies from the Layer
// option onto every emitted HEADERS event regardless of direction.
func TestAggregator_HTTPVersion_Response_H2(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status: 200, Scheme: "https",
			EndStream: true,
		},
	})
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *HTTPMessage", env.Message)
	}
	if msg.HTTPVersion != envelope.HTTPVersionH2 {
		t.Errorf("HTTPVersion = %q, want %q", msg.HTTPVersion, envelope.HTTPVersionH2)
	}
}
