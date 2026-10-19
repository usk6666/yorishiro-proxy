// Command smokeselect computes the test selection for the smoke CI tier
// (`make test-e2e-smoke`, USK-1209).
//
// The smoke tier is defined by build tags (USK-728): plain `//go:build e2e`
// files are smoke, `//go:build e2e && !e2e_smoke` files are exhaustive-only.
// Building with `-tags 'e2e e2e_smoke'` also compiles every untagged test, so
// running `go test ./...` under those tags repeats the whole fast tier.
// smokeselect instead derives, from `go list` and the Go parser, exactly the
// packages that declare smoke tests and the top-level names of those tests.
//
// Usage:
//
//	go run ./tools/smokeselect [-C dir] [-tags e2e,e2e_smoke] [-list] [packages]
//
// Output (stdout): line 1 is an anchored `-run` regexp; each following line is
// one import path. With -list, each line is "<import path>\t<test name>".
// Warnings go to stderr. Any `go list` failure or an empty selection exits
// non-zero with nothing on stdout, so a caller can never fall through to an
// unfiltered or empty `go test`.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], GoList, os.Stdout, os.Stderr))
}

// run is main without the process exit, for testing.
func run(ctx context.Context, args []string, list Lister, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smokeselect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", ".", "module directory to run `go list` in")
	tags := fs.String("tags", strings.Join(DefaultTags, ","), "comma-separated build tags that define the smoke tier")
	listMode := fs.Bool("list", false, "print one \"<import path>\\t<test name>\" line per selected test")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	patterns := fs.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	sel, err := Select(ctx, list, *dir, splitTags(*tags), patterns)
	if err != nil {
		fmt.Fprintf(stderr, "smokeselect: %v\n", err)
		return 1
	}
	for _, w := range sel.Warnings {
		fmt.Fprintf(stderr, "smokeselect: warning: %s\n", w)
	}
	if len(sel.Tests) == 0 {
		fmt.Fprintf(stderr, "smokeselect: no smoke tests found under tags %q in %v; refusing to emit an empty selection\n", *tags, patterns)
		return 1
	}

	var b strings.Builder
	if *listMode {
		for _, p := range sel.Packages() {
			for _, n := range sel.Tests[p] {
				fmt.Fprintf(&b, "%s\t%s\n", p, n)
			}
		}
	} else {
		b.WriteString(sel.RunRegexp() + "\n")
		for _, p := range sel.Packages() {
			b.WriteString(p + "\n")
		}
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		fmt.Fprintf(stderr, "smokeselect: write output: %v\n", err)
		return 1
	}
	return 0
}

func splitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}
