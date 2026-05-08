package httpaggregator

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestAggregator_ExtendedCONNECT_RequestEmitsWithoutEndStream is the
// USK-775 client-side regression gate. RFC 8441 extended CONNECT opens
// a bidirectional stream; the request HEADERS does not carry END_STREAM
// because the client keeps the stream open for the negotiated
// protocol's frames (WS DATA, etc.). Pre-fix the aggregator parked in
// phaseCollectingBody waiting for an END_STREAM that never arrived,
// blocking the request HTTPMessage from reaching the Pipeline and
// preventing UpgradeStep / runUpgradeWSOverH2 from firing.
func TestAggregator_ExtendedCONNECT_RequestEmitsWithoutEndStream(t *testing.T) {
	inner := newFakeChannel()
	// Request: extended CONNECT, NO END_STREAM (the wire-realistic shape).
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method:          "CONNECT",
			Scheme:          "https",
			Authority:       "echo.example.com",
			Path:            "/chat",
			ConnectProtocol: "websocket",
			EndStream:       false,
		},
	})

	// RoleServer = client-side aggregator (Next=>Send/requests).
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	// Request must emit immediately even without END_STREAM.
	envReq, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next (request): %v", err)
	}
	reqMsg, ok := envReq.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("request Message = %T, want *HTTPMessage", envReq.Message)
	}
	if reqMsg.Method != "CONNECT" {
		t.Errorf("request Method = %q, want CONNECT", reqMsg.Method)
	}
	if reqMsg.ConnectProtocol != "websocket" {
		t.Errorf("request ConnectProtocol = %q, want websocket", reqMsg.ConnectProtocol)
	}
	if envReq.Direction != envelope.Send {
		t.Errorf("request Direction = %v, want Send", envReq.Direction)
	}
}

// TestAggregator_ExtendedCONNECT_ResponseEmitsWithoutEndStream verifies
// the upstream-side (RoleClient) short-circuit: a 2xx response on a
// stream where Send already saw an extended-CONNECT request must emit
// immediately so UpgradeStep can flip Pending=UpgradeWSOverH2 even
// though the upstream keeps the stream open for the negotiated
// protocol's frames.
func TestAggregator_ExtendedCONNECT_ResponseEmitsWithoutEndStream(t *testing.T) {
	inner := newFakeChannel()
	// 2xx response, no END_STREAM (upstream keeps the stream open).
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status:    200,
			EndStream: false,
		},
	})

	// RoleClient = upstream-side aggregator (Next=>Receive/responses).
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	// Simulate Send-side bootstrap: in production the proxy session
	// invokes Send(extended-CONNECT request) which marks the aggregator
	// tunnelled before any Next() pulls the response.
	if err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:          "CONNECT",
			Scheme:          "https",
			Authority:       "echo.example.com",
			Path:            "/chat",
			ConnectProtocol: "websocket",
		},
	}); err != nil {
		t.Fatalf("Send(extended CONNECT): %v", err)
	}

	envResp, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next (response): %v", err)
	}
	respMsg, ok := envResp.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("response Message = %T, want *HTTPMessage", envResp.Message)
	}
	if respMsg.Status != 200 {
		t.Errorf("response Status = %d, want 200", respMsg.Status)
	}
	if envResp.Direction != envelope.Receive {
		t.Errorf("response Direction = %v, want Receive", envResp.Direction)
	}
}

// TestAggregator_ExtendedCONNECT_PropagatesProtocol verifies the USK-764
// plumbing: an H2HeadersEvent carrying Protocol="websocket" folds into
// an HTTPMessage with the same Protocol value, while Method stays
// "CONNECT". This is the contract the downstream session-layer swap
// orchestrator (USK-765) consumes to decide whether to switch the stack
// to a WebSocket Layer.
func TestAggregator_ExtendedCONNECT_PropagatesProtocol(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method:          "CONNECT",
			Scheme:          "https",
			Authority:       "echo.example.com",
			Path:            "/chat",
			ConnectProtocol: "websocket",
			EndStream:       true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", env.Message)
	}
	if msg.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", msg.Method)
	}
	if msg.ConnectProtocol != "websocket" {
		t.Errorf("Protocol = %q, want websocket", msg.ConnectProtocol)
	}
	if msg.Path != "/chat" {
		t.Errorf("Path = %q, want /chat", msg.Path)
	}
}

// TestAggregator_NormalRequest_ProtocolEmpty verifies that a regular
// (non-CONNECT) HTTP/2 request leaves HTTPMessage.Protocol empty so the
// downstream session layer cannot accidentally treat it as extended
// CONNECT.
func TestAggregator_NormalRequest_ProtocolEmpty(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method:    "GET",
			Scheme:    "https",
			Authority: "x",
			Path:      "/",
			EndStream: true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.ConnectProtocol != "" {
		t.Errorf("Protocol = %q, want empty for GET request", msg.ConnectProtocol)
	}
}

// TestEncodeWireBytes_ExtendedCONNECT_EmitsProtocolPseudo verifies the
// re-encoder emits :protocol on the wire for an HTTPMessage that
// represents an extended CONNECT request. The recorded "modified
// variant" wire bytes must round-trip back through the HPACK decoder
// with Protocol intact so replay tools (resend / fuzz) can faithfully
// reproduce the bootstrap request.
func TestEncodeWireBytes_ExtendedCONNECT_EmitsProtocolPseudo(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:          "CONNECT",
			Scheme:          "https",
			Authority:       "echo.example.com",
			Path:            "/chat",
			ConnectProtocol: "websocket",
		},
	}
	wire, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}

	r := frame.NewReader(bytes.NewReader(wire))
	f, rerr := r.ReadFrame()
	if rerr != nil {
		t.Fatalf("ReadFrame: %v", rerr)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame type = %s, want HEADERS", f.Header.Type)
	}

	// HPACK decode the header block. EncodeWireBytes uses single-block
	// HEADERS without padding/priority — decoder consumes the payload
	// directly when END_HEADERS is set on a single frame.
	dec := hpack.NewDecoder(4096)
	fields, derr := dec.Decode(f.Payload)
	if derr != nil {
		t.Fatalf("HPACK decode: %v", derr)
	}

	gotProtocol := ""
	gotMethod := ""
	for _, hf := range fields {
		if hf.Name == ":protocol" {
			gotProtocol = hf.Value
		}
		if hf.Name == ":method" {
			gotMethod = hf.Value
		}
	}
	if gotMethod != "CONNECT" {
		t.Errorf(":method = %q, want CONNECT", gotMethod)
	}
	if gotProtocol != "websocket" {
		t.Errorf(":protocol = %q, want websocket", gotProtocol)
	}
}

// TestEncodeWireBytes_NormalRequest_OmitsProtocolPseudo verifies the
// re-encoder does NOT emit :protocol for a regular HTTP request, even if
// the HTTPMessage.Protocol field is somehow non-empty for a non-CONNECT
// method (defence-in-depth — flushAnomalies catches this on the receive
// side, but the send side independently filters).
func TestEncodeWireBytes_NormalRequest_OmitsProtocolPseudo(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:          "GET",
			Scheme:          "https",
			Authority:       "x",
			Path:            "/",
			ConnectProtocol: "websocket", // Should be ignored on encode for non-CONNECT.
		},
	}
	wire, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}

	r := frame.NewReader(bytes.NewReader(wire))
	f, rerr := r.ReadFrame()
	if rerr != nil {
		t.Fatalf("ReadFrame: %v", rerr)
	}
	dec := hpack.NewDecoder(4096)
	fields, _ := dec.Decode(f.Payload)
	for _, hf := range fields {
		if hf.Name == ":protocol" {
			t.Errorf("non-CONNECT request emitted :protocol=%q on the wire", hf.Value)
		}
	}
}
