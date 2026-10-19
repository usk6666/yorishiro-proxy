// Command smokeselect computes the test selection for the smoke CI tier
// (`make test-e2e-smoke`, USK-1209).
//
// The smoke tier is defined by build tags (USK-728): plain `//go:build e2e`
// files are smoke, `//go:build e2e && !e2e_smoke` files are exhaustive-only.
// Building with `-tags 'e2e e2e_smoke'` therefore compiles every untagged test
// too, so running `go test ./...` under those tags repeats the whole fast tier.
// smokeselect instead derives, from `go list` and the Go parser, exactly the
// packages that declare smoke tests and the top-level names of those tests.
//
// Output (stdout): line 1 is an anchored `-run` regexp; each following line is
// one import path. With -list, each line is "<import path>\t<test name>".
// Any `go list` failure or an empty selection exits non-zero.
package main

import (
	"context"
	"io"
	"os"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], GoList, os.Stdout, os.Stderr))
}

// run is main without the process exit, for testing.
func run(ctx context.Context, args []string, list Lister, stdout, stderr io.Writer) int {
	return 0
}
