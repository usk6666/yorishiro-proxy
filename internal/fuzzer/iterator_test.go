package fuzzer

import (
	"testing"
)

func TestSequentialIterator(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "set-a"},
		{ID: "pos-1", Location: "header", Name: "X-B", PayloadSet: "set-b"},
	}
	resolved := map[string][]string{
		"set-a": {"a1", "a2"},
		"set-b": {"b1", "b2", "b3"},
	}

	iter, err := NewIterator("sequential", positions, resolved)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	if got := iter.Total(); got != 5 {
		t.Errorf("Total() = %d, want 5", got)
	}

	// Collect all cases.
	var cases []FuzzCase
	for {
		fc, ok := iter.Next()
		if !ok {
			break
		}
		cases = append(cases, fc)
	}

	if len(cases) != 5 {
		t.Fatalf("got %d cases, want 5", len(cases))
	}

	// First two cases: pos-0 with set-a payloads.
	if cases[0].Payloads["pos-0"] != "a1" {
		t.Errorf("case[0] pos-0 = %q, want %q", cases[0].Payloads["pos-0"], "a1")
	}
	if cases[1].Payloads["pos-0"] != "a2" {
		t.Errorf("case[1] pos-0 = %q, want %q", cases[1].Payloads["pos-0"], "a2")
	}

	// Next three cases: pos-1 with set-b payloads.
	if cases[2].Payloads["pos-1"] != "b1" {
		t.Errorf("case[2] pos-1 = %q, want %q", cases[2].Payloads["pos-1"], "b1")
	}
	if cases[3].Payloads["pos-1"] != "b2" {
		t.Errorf("case[3] pos-1 = %q, want %q", cases[3].Payloads["pos-1"], "b2")
	}
	if cases[4].Payloads["pos-1"] != "b3" {
		t.Errorf("case[4] pos-1 = %q, want %q", cases[4].Payloads["pos-1"], "b3")
	}

	// Verify indexes are sequential.
	for i, fc := range cases {
		if fc.Index != i {
			t.Errorf("case[%d].Index = %d, want %d", i, fc.Index, i)
		}
	}
}

func TestSequentialIterator_WithRemove(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "set-a"},
		{ID: "pos-1", Location: "header", Name: "X-Debug", Mode: "remove"},
	}
	resolved := map[string][]string{
		"set-a": {"a1", "a2"},
	}

	iter, err := NewIterator("sequential", positions, resolved)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	if got := iter.Total(); got != 3 {
		t.Errorf("Total() = %d, want 3 (2 from set-a + 1 remove)", got)
	}

	var cases []FuzzCase
	for {
		fc, ok := iter.Next()
		if !ok {
			break
		}
		cases = append(cases, fc)
	}

	if len(cases) != 3 {
		t.Fatalf("got %d cases, want 3", len(cases))
	}

	// The third case should be the remove for pos-1.
	if _, ok := cases[2].Payloads["pos-1"]; !ok {
		t.Error("case[2] missing pos-1 key")
	}
}

func TestParallelIterator(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "set-a"},
		{ID: "pos-1", Location: "header", Name: "X-B", PayloadSet: "set-b"},
	}
	resolved := map[string][]string{
		"set-a": {"a1", "a2", "a3"},
		"set-b": {"b1", "b2"},
	}

	iter, err := NewIterator("parallel", positions, resolved)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	// parallel uses zip: stops at shortest set (2).
	if got := iter.Total(); got != 2 {
		t.Errorf("Total() = %d, want 2 (shortest set)", got)
	}

	var cases []FuzzCase
	for {
		fc, ok := iter.Next()
		if !ok {
			break
		}
		cases = append(cases, fc)
	}

	if len(cases) != 2 {
		t.Fatalf("got %d cases, want 2", len(cases))
	}

	// First case: both positions get their first payload.
	if cases[0].Payloads["pos-0"] != "a1" || cases[0].Payloads["pos-1"] != "b1" {
		t.Errorf("case[0] = %v, want pos-0:a1, pos-1:b1", cases[0].Payloads)
	}
	if cases[1].Payloads["pos-0"] != "a2" || cases[1].Payloads["pos-1"] != "b2" {
		t.Errorf("case[1] = %v, want pos-0:a2, pos-1:b2", cases[1].Payloads)
	}
}

func TestParallelIterator_WithRemove(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "set-a"},
		{ID: "pos-1", Location: "header", Name: "X-Debug", Mode: "remove"},
	}
	resolved := map[string][]string{
		"set-a": {"a1", "a2"},
	}

	iter, err := NewIterator("parallel", positions, resolved)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	// Remove positions participate in every iteration.
	if got := iter.Total(); got != 2 {
		t.Errorf("Total() = %d, want 2", got)
	}

	var cases []FuzzCase
	for {
		fc, ok := iter.Next()
		if !ok {
			break
		}
		cases = append(cases, fc)
	}

	for i, fc := range cases {
		if _, ok := fc.Payloads["pos-1"]; !ok {
			t.Errorf("case[%d] missing pos-1 (remove position)", i)
		}
	}
}

func TestParallelIterator_AllRemove(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", Mode: "remove"},
		{ID: "pos-1", Location: "header", Name: "X-B", Mode: "remove"},
	}
	resolved := map[string][]string{}

	iter, err := NewIterator("parallel", positions, resolved)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	if got := iter.Total(); got != 1 {
		t.Errorf("Total() = %d, want 1 (all remove)", got)
	}
}

func TestNewIterator_InvalidType(t *testing.T) {
	_, err := NewIterator("invalid", nil, nil)
	if err == nil {
		t.Error("expected error for invalid attack type")
	}
}

func TestNewIterator_MissingPayloadSet(t *testing.T) {
	positions := []Position{
		{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "missing"},
	}
	resolved := map[string][]string{}

	_, err := NewIterator("sequential", positions, resolved)
	if err == nil {
		t.Error("expected error for missing payload set")
	}
}

func TestParallelIterator_Empty(t *testing.T) {
	iter, err := NewIterator("parallel", nil, nil)
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}
	if got := iter.Total(); got != 0 {
		t.Errorf("Total() = %d, want 0", got)
	}
	_, ok := iter.Next()
	if ok {
		t.Error("expected exhausted iterator")
	}
}
