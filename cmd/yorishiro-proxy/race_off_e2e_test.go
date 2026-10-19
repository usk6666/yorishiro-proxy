//go:build e2e && !race

package main_test

// raceEnabled reports whether this test binary was built with -race; see
// race_on_e2e_test.go.
const raceEnabled = false
