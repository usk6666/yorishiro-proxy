package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

type snapshotKey struct{}

// withSnapshot stores an Exchange snapshot in the context.
// Pipeline.Run() calls this before executing any Steps so that RecordStep
// can later compare the original Exchange with the (possibly modified) one.
func withSnapshot(ctx context.Context, snap *exchange.Exchange) context.Context {
	return context.WithValue(ctx, snapshotKey{}, snap)
}

// SnapshotFromContext retrieves the Exchange snapshot stored by Pipeline.Run().
// Returns nil if no snapshot is present.
func SnapshotFromContext(ctx context.Context) *exchange.Exchange {
	if v, ok := ctx.Value(snapshotKey{}).(*exchange.Exchange); ok {
		return v
	}
	return nil
}
