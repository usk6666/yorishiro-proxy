package http1

import (
	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// BuildSendEnvelope constructs a synthetic Send Envelope with an HTTPMessage
// populated from the given parameters. The returned Envelope has no Opaque
// field, which causes the http1 Channel.Send to take the synthetic
// serialization path (constructing wire bytes from structured fields).
//
// This is used by L7 resend and macro SendFunc adapters to build envelopes
// from stored flow data or user-specified parameters.
func BuildSendEnvelope(method, scheme, authority, path, rawQuery string, headers []envelope.KeyValue, body []byte) *envelope.Envelope {
	return &envelope.Envelope{
		FlowID:    uuid.NewString(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    method,
			Scheme:    scheme,
			Authority: authority,
			Path:      path,
			RawQuery:  rawQuery,
			Headers:   headers,
			Body:      body,
		},
		// No Opaque — triggers synthetic send path in Channel.Send.
		// No Raw — synthetic envelopes have no wire-observed bytes.
	}
}
