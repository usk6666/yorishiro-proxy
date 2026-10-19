//go:build e2e && race

package raceonly

import "testing"

// TestRaceOnly is built only when the race detector is on. The smoke recipe
// runs `go test -race`, so the selector must list packages with -race too.
func TestRaceOnly(t *testing.T) {}
