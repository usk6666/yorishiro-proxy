package main

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.2", "1.2.0", 0},
		{"1.2.0", "1.2", 0},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"1.2.3-rc1", "1.2.3", 0},
		{"v1.2.3+meta", "1.2.3", 0},
		{"", "0.0.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry.
		if got := compareVersions(c.b, c.a); got != -c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestGoVersionTag(t *testing.T) {
	cases := map[string]string{
		// The shape the Dependabot API actually returns for Go advisories.
		"0.52.0":                             "v0.52.0",
		"1.83.1":                             "v1.83.1",
		"v0.52.0":                            "v0.52.0", // idempotent
		" 0.52.0":                            "v0.52.0",
		"":                                   "",
		"v0.0.0-20260210143700-b62fd896b91b": "v0.0.0-20260210143700-b62fd896b91b",
	}
	for in, want := range cases {
		if got := goVersionTag(in); got != want {
			t.Errorf("goVersionTag(%q) = %q, want %q", in, got, want)
		}
		if got := goVersionTag(want); got != want {
			t.Errorf("goVersionTag(%q) not idempotent: %q", want, got)
		}
	}
}
