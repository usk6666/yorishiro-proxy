// Package exchange defines the protocol-agnostic message unit at the heart of
// the Codec + Pipeline + Session architecture. All Pipeline Steps operate on
// Exchange. All Codecs produce and consume Exchange.
//
// Wire bytes -> Codec.Next() -> Exchange -> Pipeline.Run() -> Exchange -> Codec.Send() -> Wire bytes
package exchange

import (
	"net/url"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Direction indicates the data flow direction.
type Direction int

const (
	// Send represents data flowing from client to server.
	Send Direction = iota
	// Receive represents data flowing from server to client.
	Receive
)

// String returns the string representation of a Direction.
func (d Direction) String() string {
	switch d {
	case Send:
		return "Send"
	case Receive:
		return "Receive"
	default:
		return "Unknown"
	}
}

// Protocol is a protocol identifier string.
type Protocol string

const (
	HTTP1   Protocol = "HTTP/1.x"
	HTTP2   Protocol = "HTTP/2"
	GRPC    Protocol = "gRPC"
	GRPCWeb Protocol = "gRPC-Web"
	WS      Protocol = "WebSocket"
	SSE     Protocol = "SSE"
	TCP     Protocol = "TCP"
)

// String returns the string representation of a Protocol.
func (p Protocol) String() string {
	return string(p)
}

// KeyValue is a single header entry. Order and case are preserved.
//
// Aliased to envelope.KeyValue so the safety engine (rehomed to operate on
// envelope.KeyValue at USK-704) accepts headers from this dying tree without
// per-call-site conversions. Both packages die together at USK-697 final.
type KeyValue = envelope.KeyValue

// Exchange is the protocol-agnostic message unit.
//
// Identity fields (StreamID, FlowID, Sequence, Direction) locate the message
// within a stream. L7 structured view fields (Method, URL, Status, Headers,
// Trailers, Body) provide a protocol-independent representation. Protocol and
// RawBytes carry protocol identity and wire data respectively.
//
// Opaque holds Codec-specific data that Pipeline Steps must never type-assert.
// Metadata holds protocol-specific key-value pairs (e.g., WebSocket opcode,
// gRPC service/method).
//
// Body being nil signals passthrough mode: the Codec streams the body directly
// and Pipeline processes only Headers.
type Exchange struct {
	// Identity
	StreamID  string    // stream (connection/RPC) this exchange belongs to
	FlowID    string    // this individual flow's unique ID (resend/fuzz target unit)
	Sequence  int       // order within the stream (0-origin)
	Direction Direction // Send or Receive

	// L7 structured view
	Method   string     // HTTP method (empty for non-HTTP or Receive)
	URL      *url.URL   // target URL (nil for Receive, TCP, WS frames)
	Status   int        // response status code (0 for Send)
	Headers  []KeyValue // ordered, case-preserving
	Trailers []KeyValue // gRPC/HTTP trailers
	Body     []byte     // nil = passthrough mode (large body streamed by Codec)

	// Protocol identity
	Protocol Protocol

	// Wire data (managed by Codec; Pipeline treats as read-only)
	RawBytes []byte

	// Codec-specific opaque data (Pipeline must never touch this)
	Opaque any

	// Protocol-specific metadata (ws opcode, grpc service/method, etc.)
	Metadata map[string]any
}

// Clone returns a deep copy of the Exchange suitable for variant recording.
// Headers, Trailers, Body, RawBytes, and Metadata are deep-copied.
// URL is cloned via url.URL value copy. Opaque is shallow-copied because
// it is managed by the Codec.
func (e *Exchange) Clone() *Exchange {
	if e == nil {
		return nil
	}

	c := &Exchange{
		StreamID:  e.StreamID,
		FlowID:    e.FlowID,
		Sequence:  e.Sequence,
		Direction: e.Direction,
		Method:    e.Method,
		Status:    e.Status,
		Protocol:  e.Protocol,
		Opaque:    e.Opaque,
	}

	if e.URL != nil {
		u := *e.URL
		if e.URL.User != nil {
			u.User = url.UserPassword(e.URL.User.Username(), "")
			if p, ok := e.URL.User.Password(); ok {
				u.User = url.UserPassword(e.URL.User.Username(), p)
			}
		}
		c.URL = &u
	}

	if e.Headers != nil {
		c.Headers = make([]KeyValue, len(e.Headers))
		copy(c.Headers, e.Headers)
	}

	if e.Trailers != nil {
		c.Trailers = make([]KeyValue, len(e.Trailers))
		copy(c.Trailers, e.Trailers)
	}

	if e.Body != nil {
		c.Body = make([]byte, len(e.Body))
		copy(c.Body, e.Body)
	}

	if e.RawBytes != nil {
		c.RawBytes = make([]byte, len(e.RawBytes))
		copy(c.RawBytes, e.RawBytes)
	}

	if e.Metadata != nil {
		c.Metadata = make(map[string]any, len(e.Metadata))
		for k, v := range e.Metadata {
			c.Metadata[k] = v
		}
	}

	return c
}

// GetHeaders returns the current Headers slice. Use with SetHeaders to
// read-modify-write the full header list.
func (e *Exchange) GetHeaders() []KeyValue {
	return e.Headers
}

// HeaderValues returns the values of all headers matching name
// (case-insensitive). Returns nil if no match is found. Useful for headers
// that may appear multiple times (e.g. Set-Cookie, or duplicate headers
// intentionally crafted for pentesting).
func (e *Exchange) HeaderValues(name string) []string {
	return headerValues(e.Headers, name)
}

// SetHeaders replaces the entire Headers slice. The caller has full control
// over order, casing, and duplicates — all of which are valid in pentesting
// scenarios (e.g. duplicate Host for header injection, duplicate
// Content-Length for request smuggling).
func (e *Exchange) SetHeaders(headers []KeyValue) {
	e.Headers = headers
}

// GetTrailers returns the current Trailers slice.
func (e *Exchange) GetTrailers() []KeyValue {
	return e.Trailers
}

// TrailerValues returns the values of all trailers matching name
// (case-insensitive). Returns nil if no match is found.
func (e *Exchange) TrailerValues(name string) []string {
	return headerValues(e.Trailers, name)
}

// SetTrailers replaces the entire Trailers slice.
func (e *Exchange) SetTrailers(trailers []KeyValue) {
	e.Trailers = trailers
}
