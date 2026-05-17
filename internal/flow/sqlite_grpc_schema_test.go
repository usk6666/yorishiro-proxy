package flow

import (
	"context"
	"testing"
)

func TestSaveGRPCSchema_Create(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	payload := []byte{0x01, 0x02, 0x03}
	if err := store.SaveGRPCSchema(ctx, "pkg.Greeter", payload, "v1"); err != nil {
		t.Fatalf("SaveGRPCSchema: %v", err)
	}

	rec, err := store.GetGRPCSchema(ctx, "pkg.Greeter")
	if err != nil {
		t.Fatalf("GetGRPCSchema: %v", err)
	}
	if rec.Service != "pkg.Greeter" {
		t.Errorf("Service = %q", rec.Service)
	}
	if string(rec.DescriptorSet) != string(payload) {
		t.Errorf("DescriptorSet = %v, want %v", rec.DescriptorSet, payload)
	}
	if rec.SourceLabel != "v1" {
		t.Errorf("SourceLabel = %q, want v1", rec.SourceLabel)
	}
	if rec.RegisteredAt.IsZero() {
		t.Error("RegisteredAt is zero")
	}
	if rec.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestSaveGRPCSchema_Upsert(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.SaveGRPCSchema(ctx, "pkg.Greeter", []byte("v1"), "first"); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := store.SaveGRPCSchema(ctx, "pkg.Greeter", []byte("v2"), "second"); err != nil {
		t.Fatalf("second save: %v", err)
	}
	rec, err := store.GetGRPCSchema(ctx, "pkg.Greeter")
	if err != nil {
		t.Fatalf("GetGRPCSchema: %v", err)
	}
	if string(rec.DescriptorSet) != "v2" {
		t.Errorf("DescriptorSet = %q, want v2 (upsert)", rec.DescriptorSet)
	}
	if rec.SourceLabel != "second" {
		t.Errorf("SourceLabel = %q, want second (upsert)", rec.SourceLabel)
	}
}

func TestGetGRPCSchema_NotFound(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.GetGRPCSchema(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing schema")
	}
}

func TestListGRPCSchemas(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.SaveGRPCSchema(ctx, "z.Late", []byte("z"), ""); err != nil {
		t.Fatalf("save z: %v", err)
	}
	if err := store.SaveGRPCSchema(ctx, "a.Early", []byte("a"), ""); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := store.SaveGRPCSchema(ctx, "m.Mid", []byte("m"), ""); err != nil {
		t.Fatalf("save m: %v", err)
	}

	records, err := store.ListGRPCSchemas(ctx)
	if err != nil {
		t.Fatalf("ListGRPCSchemas: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len = %d, want 3", len(records))
	}
	if records[0].Service != "a.Early" || records[1].Service != "m.Mid" || records[2].Service != "z.Late" {
		t.Errorf("ordering wrong: %s, %s, %s", records[0].Service, records[1].Service, records[2].Service)
	}
}

func TestDeleteGRPCSchema(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.SaveGRPCSchema(ctx, "x", []byte("x"), ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.DeleteGRPCSchema(ctx, "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.GetGRPCSchema(ctx, "x"); err == nil {
		t.Error("expected not-found after delete")
	}
	// Delete again is an error (matches MacroStore behavior).
	if err := store.DeleteGRPCSchema(ctx, "x"); err == nil {
		t.Error("expected error for delete of nonexistent")
	}
}

func TestClearGRPCSchemas(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	for _, name := range []string{"a", "b", "c"} {
		if err := store.SaveGRPCSchema(ctx, name, []byte(name), ""); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	deleted, err := store.ClearGRPCSchemas(ctx)
	if err != nil {
		t.Fatalf("ClearGRPCSchemas: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}
	records, _ := store.ListGRPCSchemas(ctx)
	if len(records) != 0 {
		t.Errorf("after clear, list len = %d", len(records))
	}
	// Clear when already empty: returns 0 with no error.
	if d, err := store.ClearGRPCSchemas(ctx); err != nil || d != 0 {
		t.Errorf("clear of empty: deleted=%d err=%v", d, err)
	}
}
