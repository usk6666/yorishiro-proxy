package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

func TestSnapshotFromContext_NoSnapshot(t *testing.T) {
	snap := SnapshotFromContext(context.Background())
	if snap != nil {
		t.Fatal("expected nil when no snapshot in context")
	}
}

func TestSnapshotFromContext_RoundTrip(t *testing.T) {
	ex := &exchange.Exchange{FlowID: "test-1"}
	ctx := withSnapshot(context.Background(), ex)
	got := SnapshotFromContext(ctx)
	if got != ex {
		t.Fatal("expected same pointer from context")
	}
}
