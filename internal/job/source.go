package job

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EnvelopeSource generates Envelopes for resend / fuzz operations.
//
// Each per-protocol Source implementation in this package (HTTPResendSource,
// WSResendSource, GRPCResendSource, RawResendSource, FuzzHTTPSource,
// FuzzRawSource) implements this interface and is consumed by the
// corresponding fuzz / resend MCP tool helper in internal/mcp/.
//
// Return io.EOF to signal source exhaustion.
type EnvelopeSource interface {
	Next(ctx context.Context) (*envelope.Envelope, error)
}
