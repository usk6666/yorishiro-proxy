package pluginv2

import (
	"errors"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

type nopBodySource struct{}

func (nopBodySource) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopBodySource) Finish(error) envelope.BodyResult { return envelope.BodyResult{} }

// TestConvertMessageToDict_BodyStreamIsTooLarge: a streamed body is never
// presented to a plugin as an empty body; the conversion reports
// ErrBodyTooLarge so the dispatcher skips the hook (USK-1409 T14 / R15).
func TestConvertMessageToDict_BodyStreamIsTooLarge(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:     200,
			BodyStream: envelope.NewBodyStream(nopBodySource{}),
		},
	}
	d, err := convertMessageToDict(env, 1<<20)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("convertMessageToDict err = %v (dict %v), want ErrBodyTooLarge", err, d)
	}
}
