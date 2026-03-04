package flow

import (
	"context"
	"testing"
	"time"
)

func TestSaveMacro_Create(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.SaveMacro(ctx, "auth-flow", "Login and get token", `{"steps":[{"id":"login","flow_id":"s1"}]}`)
	if err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	rec, err := store.GetMacro(ctx, "auth-flow")
	if err != nil {
		t.Fatalf("GetMacro: %v", err)
	}

	if rec.Name != "auth-flow" {
		t.Errorf("Name = %q, want %q", rec.Name, "auth-flow")
	}
	if rec.Description != "Login and get token" {
		t.Errorf("Description = %q, want %q", rec.Description, "Login and get token")
	}
	if rec.ConfigJSON != `{"steps":[{"id":"login","flow_id":"s1"}]}` {
		t.Errorf("ConfigJSON = %q", rec.ConfigJSON)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if rec.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestSaveMacro_Upsert(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create initial macro.
	err := store.SaveMacro(ctx, "auth-flow", "v1 description", `{"steps":[]}`)
	if err != nil {
		t.Fatalf("SaveMacro (create): %v", err)
	}

	rec1, _ := store.GetMacro(ctx, "auth-flow")
	createdAt := rec1.CreatedAt

	// Wait a bit to ensure different timestamps.
	time.Sleep(10 * time.Millisecond)

	// Update the same macro.
	err = store.SaveMacro(ctx, "auth-flow", "v2 description", `{"steps":[{"id":"new","flow_id":"s2"}]}`)
	if err != nil {
		t.Fatalf("SaveMacro (update): %v", err)
	}

	rec2, err := store.GetMacro(ctx, "auth-flow")
	if err != nil {
		t.Fatalf("GetMacro after update: %v", err)
	}

	if rec2.Description != "v2 description" {
		t.Errorf("Description after update = %q, want %q", rec2.Description, "v2 description")
	}
	if rec2.ConfigJSON != `{"steps":[{"id":"new","flow_id":"s2"}]}` {
		t.Errorf("ConfigJSON after update = %q", rec2.ConfigJSON)
	}

	// created_at should remain unchanged after upsert.
	if !rec2.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt changed after update: %v -> %v", createdAt, rec2.CreatedAt)
	}
	// updated_at should be newer.
	if !rec2.UpdatedAt.After(rec2.CreatedAt) {
		t.Errorf("UpdatedAt %v should be after CreatedAt %v", rec2.UpdatedAt, rec2.CreatedAt)
	}
}

func TestGetMacro_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.GetMacro(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestListMacros_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	macros, err := store.ListMacros(ctx)
	if err != nil {
		t.Fatalf("ListMacros: %v", err)
	}
	if len(macros) != 0 {
		t.Errorf("expected 0 macros, got %d", len(macros))
	}
}

func TestListMacros_OrderedByName(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save macros in non-alphabetical order.
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		if err := store.SaveMacro(ctx, name, "", `{}`); err != nil {
			t.Fatalf("SaveMacro(%s): %v", name, err)
		}
	}

	macros, err := store.ListMacros(ctx)
	if err != nil {
		t.Fatalf("ListMacros: %v", err)
	}
	if len(macros) != 3 {
		t.Fatalf("expected 3 macros, got %d", len(macros))
	}

	expected := []string{"alpha", "bravo", "charlie"}
	for i, m := range macros {
		if m.Name != expected[i] {
			t.Errorf("macros[%d].Name = %q, want %q", i, m.Name, expected[i])
		}
	}
}

func TestDeleteMacro_Success(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.SaveMacro(ctx, "to-delete", "will be deleted", `{}`); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	if err := store.DeleteMacro(ctx, "to-delete"); err != nil {
		t.Fatalf("DeleteMacro: %v", err)
	}

	_, err := store.GetMacro(ctx, "to-delete")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestDeleteMacro_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.DeleteMacro(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestSaveMacro_EmptyDescription(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.SaveMacro(ctx, "minimal", "", `{"steps":[{"id":"s1","flow_id":"fl-1"}]}`)
	if err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	rec, err := store.GetMacro(ctx, "minimal")
	if err != nil {
		t.Fatalf("GetMacro: %v", err)
	}
	if rec.Description != "" {
		t.Errorf("Description = %q, want empty", rec.Description)
	}
}

func TestMacroTableSurvivesMigration(t *testing.T) {
	// Tests that the macros table exists after V2 migration.
	store := newTestStore(t)
	ctx := context.Background()

	// Verify we can insert and retrieve.
	if err := store.SaveMacro(ctx, "test", "desc", `{"steps":[]}`); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	rec, err := store.GetMacro(ctx, "test")
	if err != nil {
		t.Fatalf("GetMacro: %v", err)
	}
	if rec.Name != "test" {
		t.Errorf("Name = %q, want %q", rec.Name, "test")
	}
}
