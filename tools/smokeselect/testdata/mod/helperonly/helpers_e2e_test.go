//go:build e2e

package helperonly

// startEcho is a smoke-tagged helper with no tests of its own.
func startEcho() string { return "echo" }
