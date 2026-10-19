//go:build e2e && race

package main_test

// raceEnabled reports whether this test binary was built with -race.
// buildBinary mirrors it so `go build` reuses the packages `go test`
// already compiled instead of rebuilding the whole tree without the race
// instrumentation (USK-1208). The `e2e` term keeps the constant out of
// the default build, where nothing references it.
const raceEnabled = true
