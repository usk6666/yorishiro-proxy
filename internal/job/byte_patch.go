package job

import "sort"

// BytePatch describes a single byte-level replacement at a given offset.
type BytePatch struct {
	// Offset is the zero-based byte position in the original data.
	Offset int
	// Data is the replacement bytes to write starting at Offset.
	Data []byte
}

// ApplyPatches applies a list of byte patches to src, returning a new slice.
// Patches are sorted by offset before application. If a patch extends beyond
// the end of src, the result is extended to accommodate it. Overlapping
// patches are applied in offset order — later patches overwrite earlier ones
// at overlapping positions.
func ApplyPatches(src []byte, patches []BytePatch) []byte {
	if len(patches) == 0 {
		dst := make([]byte, len(src))
		copy(dst, src)
		return dst
	}

	// Sort patches by offset for deterministic application.
	sorted := make([]BytePatch, len(patches))
	copy(sorted, patches)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Offset < sorted[j].Offset
	})

	// Calculate the required output size.
	requiredLen := len(src)
	for _, p := range sorted {
		end := p.Offset + len(p.Data)
		if end > requiredLen {
			requiredLen = end
		}
	}

	dst := make([]byte, requiredLen)
	copy(dst, src)

	for _, p := range sorted {
		copy(dst[p.Offset:], p.Data)
	}

	return dst
}
