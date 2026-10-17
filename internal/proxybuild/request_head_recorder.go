package proxybuild

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// requestHeadFailure identifies one request head the proxy closed before an
// Envelope existed (USK-1181).
type requestHeadFailure struct {
	// ConnID is the connection-stack ConnID, shared with every Stream
	// recorded on the same connection.
	ConnID string
	// ClientAddr is the client's remote address.
	ClientAddr string
	// Target is the authority the connection was bound for (CONNECT /
	// plain-forward target / tcp_forwards target). May be empty.
	Target string
	// Head describes what the wire showed.
	Head *http1.RequestHeadError
}

// requestHeadRecorder persists a requestHeadFailure. Synchronous; safe for
// concurrent use.
type requestHeadRecorder func(ctx context.Context, f requestHeadFailure)

// buildRequestHeadRecorder returns the USK-1181 recorder. Scaffold.
func buildRequestHeadRecorder(store flow.Writer, _ *flow.RecordScope, _ string, _ *slog.Logger) requestHeadRecorder {
	if store == nil {
		return nil
	}
	return func(context.Context, requestHeadFailure) {}
}
