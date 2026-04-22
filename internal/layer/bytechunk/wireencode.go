package bytechunk

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EncodeWireBytes returns the post-mutation wire-form bytes for a raw
// byte-chunk envelope. For the bytechunk protocol the wire format is
// exactly the current message payload — there are no framing layers to
// re-serialize — so this function simply returns env.Message.Bytes when
// the Message is a *RawMessage.
//
// When env.Message is nil (a case that should not arise in practice; the
// Channel always attaches a RawMessage before emitting the envelope), the
// ingress env.Raw is returned so the caller (pipeline.RecordStep) still has
// a sensible modified-variant RawBytes.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("bytechunk: EncodeWireBytes: nil envelope")
	}
	if env.Message == nil {
		return env.Raw, nil
	}
	raw, ok := env.Message.(*envelope.RawMessage)
	if !ok {
		return nil, fmt.Errorf("bytechunk: EncodeWireBytes: requires *RawMessage, got %T", env.Message)
	}
	return raw.Bytes, nil
}
