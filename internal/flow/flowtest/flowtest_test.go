package flowtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/flow/flowtest"
)

// TestNewStore_TemplateBuiltOnce: creating several stores builds the migrated
// template exactly once, and each store is at the template's version (the
// pre-open check inside NewStore enforces that no migration step is left for
// NewSQLiteStore to apply).
func TestNewStore_TemplateBuiltOnce(t *testing.T) {
	ctx := context.Background()
	stores := make([]*flow.SQLiteStore, 3)
	for i := range stores {
		stores[i] = flowtest.NewStore(t)
	}
	// Checked before TemplateVersion, which would itself build the template:
	// the stores alone must have caused exactly one build.
	if n := flowtest.TemplateBuilds(); n != 1 {
		t.Fatalf("TemplateBuilds() = %d after creating %d stores, want exactly 1", n, len(stores))
	}
	want, err := flowtest.TemplateVersion()
	if err != nil {
		t.Fatalf("TemplateVersion: %v", err)
	}
	if want == 0 {
		t.Fatal("template schema version is 0; the migration chain did not run")
	}
	for i, s := range stores {
		var got int
		if err := s.DB().QueryRowContext(ctx, "SELECT MAX(version) FROM schema_version").Scan(&got); err != nil {
			t.Fatalf("store %d: query version: %v", i, err)
		}
		if got != want {
			t.Fatalf("store %d: schema version = %d, want %d", i, got, want)
		}
	}
}

// TestNewStore_StoresAreIndependent: a write in one store is not visible in
// another, including when stores are created by parallel tests.
func TestNewStore_StoresAreIndependent(t *testing.T) {
	for _, name := range []string{"a", "b", "c"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := flowtest.NewStore(t)
			n, err := s.CountStreams(ctx, flow.StreamListOptions{})
			if err != nil {
				t.Fatalf("CountStreams: %v", err)
			}
			if n != 0 {
				t.Fatalf("fresh store already has %d streams; stores share state", n)
			}
			st := &flow.Stream{ID: "stream-" + name, Protocol: "raw", State: "complete", Timestamp: time.Now()}
			if err := s.SaveStream(ctx, st); err != nil {
				t.Fatalf("SaveStream: %v", err)
			}
			n, err = s.CountStreams(ctx, flow.StreamListOptions{})
			if err != nil {
				t.Fatalf("CountStreams after save: %v", err)
			}
			if n != 1 {
				t.Fatalf("store has %d streams after one save, want 1", n)
			}
		})
	}
}
