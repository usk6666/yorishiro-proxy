package job

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EnvelopeSource generates Envelopes for resend / fuzz operations.
//
// Each per-protocol Source implementation in this package (HTTPResendSource,
// WSResendSource, GRPCResendSource, RawResendSource) implements this
// interface. RawResendSource is consumed by the resend_raw / fuzz_raw MCP
// tool helpers in internal/mcp/.
//
// Return io.EOF to signal source exhaustion.
type EnvelopeSource interface {
	Next(ctx context.Context) (*envelope.Envelope, error)
}
