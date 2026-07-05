package main

import (
	"strconv"
	"strings"
)

// compareVersions returns -1, 0, or 1 comparing two dotted numeric versions.
// A leading "v" is ignored. Any pre-release / build suffix (after "-" or "+")
// is stripped before comparison, so 1.2.3 and 1.2.3-rc1 compare equal on their
// numeric core; this is intentionally coarse — we only need a stable ordering
// to pick the highest patched version among several advisories for one package.
// Non-numeric fields are treated as 0.
func compareVersions(a, b string) int {
	ai := numericFields(a)
	bi := numericFields(b)
	n := len(ai)
	if len(bi) > n {
		n = len(bi)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(ai) {
			x = ai[i]
		}
		if i < len(bi) {
			y = bi[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numericFields(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Drop pre-release / build metadata.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
