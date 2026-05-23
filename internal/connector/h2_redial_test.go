package connector

import (
	"testing"
)

// TestRedialConnIDLabel_GenerationProgression locks the USK-991 label
// scheme:
//   - generation<=1 preserves the USK-816 historical suffix
//     `/upstream-redial` so existing log scrapers / flow filters keep
//     working unchanged.
//   - generation>=2 appends `-N` so each chain step is visibly distinct
//     in flow rows / structured logs / debugging dumps.
//
// Also pins the empty-base-ConnID fallback to "redial" so the suffix is
// never the only component (which would conflict across CONNECTs in any
// log aggregator that groups by ConnID prefix).
func TestRedialConnIDLabel_GenerationProgression(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		generation int
		want       string
	}{
		{"first redial preserves USK-816 label", "conn-abc", 1, "conn-abc/upstream-redial"},
		{"generation 0 also yields the first-redial label", "conn-abc", 0, "conn-abc/upstream-redial"},
		{"second redial appends -2", "conn-abc", 2, "conn-abc/upstream-redial-2"},
		{"third redial appends -3", "conn-abc", 3, "conn-abc/upstream-redial-3"},
		{"empty base ConnID falls back to 'redial'", "", 1, "redial/upstream-redial"},
		{"empty base + Nth redial still labels uniquely", "", 5, "redial/upstream-redial-5"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redialConnIDLabel(tc.base, tc.generation)
			if got != tc.want {
				t.Errorf("redialConnIDLabel(%q, %d) = %q, want %q",
					tc.base, tc.generation, got, tc.want)
			}
		})
	}
}

// TestRedialConnIDLabel_ChainUniqueness asserts that a 5-step chain
// produces 5 distinct ConnID labels — the user-visible guarantee USK-991
// added so a multi-GOAWAY flow can be triaged in logs / flow lists.
func TestRedialConnIDLabel_ChainUniqueness(t *testing.T) {
	const base = "live-conn-xyz"
	seen := make(map[string]struct{})
	for gen := 1; gen <= 5; gen++ {
		label := redialConnIDLabel(base, gen)
		if _, dup := seen[label]; dup {
			t.Errorf("generation %d label %q collides with a prior chain step", gen, label)
		}
		seen[label] = struct{}{}
	}
	if got := len(seen); got != 5 {
		t.Fatalf("5-step chain produced %d distinct labels, want 5", got)
	}
}
