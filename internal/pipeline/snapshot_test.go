package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestSnapshotFromContext_NoSnapshot(t *testing.T) {
	snap := SnapshotFromContext(context.Background())
	if snap != nil {
		t.Fatal("expected nil when no snapshot in context")
	}
}

func TestSnapshotFromContext_RoundTrip(t *testing.T) {
	env := &envelope.Envelope{FlowID: "test-1"}
	ctx := withSnapshot(context.Background(), env)
	got := SnapshotFromContext(ctx)
	if got != env {
		t.Fatal("expected same pointer from context")
	}
}
