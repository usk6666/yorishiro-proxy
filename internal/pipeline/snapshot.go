package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

type snapshotKey struct{}

// withSnapshot stores an Envelope snapshot in the context.
// Pipeline.Run() calls this before executing any Steps so that RecordStep
// can later compare the original Envelope with the (possibly modified) one.
func withSnapshot(ctx context.Context, snap *envelope.Envelope) context.Context {
	return context.WithValue(ctx, snapshotKey{}, snap)
}

// SnapshotFromContext retrieves the Envelope snapshot stored by Pipeline.Run().
// Returns nil if no snapshot is present.
func SnapshotFromContext(ctx context.Context) *envelope.Envelope {
	if v, ok := ctx.Value(snapshotKey{}).(*envelope.Envelope); ok {
		return v
	}
	return nil
}
