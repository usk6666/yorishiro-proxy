package job

import (
	"bytes"
	"testing"
)

func TestApplyPatches_NilPatches(t *testing.T) {
	src := []byte("hello world")
	result := ApplyPatches(src, nil)
	if !bytes.Equal(result, src) {
		t.Errorf("got %q, want %q", result, src)
	}
	// Verify it's a copy, not the same slice.
	src[0] = 'X'
	if result[0] == 'X' {
		t.Error("result should be a copy, not a reference")
	}
}

func TestApplyPatches_SinglePatch(t *testing.T) {
	src := []byte("hello world")
	patches := []BytePatch{
		{Offset: 6, Data: []byte("earth")},
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("hello earth")) {
		t.Errorf("got %q, want %q", result, "hello earth")
	}
}

func TestApplyPatches_MultipleNonOverlapping(t *testing.T) {
	src := []byte("AAABBBCCC")
	patches := []BytePatch{
		{Offset: 0, Data: []byte("XX")},
		{Offset: 6, Data: []byte("YY")},
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("XXABBBYYC")) {
		t.Errorf("got %q, want %q", result, "XXABBBYYC")
	}
}

func TestApplyPatches_Overlapping(t *testing.T) {
	src := []byte("ABCDEFGH")
	patches := []BytePatch{
		{Offset: 2, Data: []byte("1234")}, // C→1, D→2, E→3, F→4
		{Offset: 4, Data: []byte("XY")},   // overwrites 3→X, 4→Y
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("AB12XYGH")) {
		t.Errorf("got %q, want %q", result, "AB12XYGH")
	}
}

func TestApplyPatches_ExtendsBeyondSource(t *testing.T) {
	src := []byte("AB")
	patches := []BytePatch{
		{Offset: 1, Data: []byte("CDEF")},
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("ACDEF")) {
		t.Errorf("got %q, want %q", result, "ACDEF")
	}
}

func TestApplyPatches_UnsortedInput(t *testing.T) {
	src := []byte("ABCDEF")
	// Patches given in reverse order — should still apply correctly.
	patches := []BytePatch{
		{Offset: 4, Data: []byte("Y")},
		{Offset: 0, Data: []byte("X")},
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("XBCDYF")) {
		t.Errorf("got %q, want %q", result, "XBCDYF")
	}
}

func TestApplyPatches_EmptySource(t *testing.T) {
	patches := []BytePatch{
		{Offset: 0, Data: []byte("ABC")},
	}
	result := ApplyPatches(nil, patches)
	if !bytes.Equal(result, []byte("ABC")) {
		t.Errorf("got %q, want %q", result, "ABC")
	}
}

func TestApplyPatches_EmptyPatchData(t *testing.T) {
	src := []byte("hello")
	patches := []BytePatch{
		{Offset: 2, Data: []byte{}},
	}
	result := ApplyPatches(src, patches)
	if !bytes.Equal(result, []byte("hello")) {
		t.Errorf("got %q, want %q", result, "hello")
	}
}

func TestApplyPatches_DoesNotMutateSource(t *testing.T) {
	src := []byte("ABCDEF")
	original := make([]byte, len(src))
	copy(original, src)

	patches := []BytePatch{
		{Offset: 0, Data: []byte("XYZ")},
	}
	ApplyPatches(src, patches)

	if !bytes.Equal(src, original) {
		t.Errorf("source was mutated: got %q, want %q", src, original)
	}
}
