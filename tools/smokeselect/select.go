package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultTags are the build tags that define the smoke tier (USK-728): the
// `e2e` tag admits every e2e file, and the `e2e_smoke` exclusion filter drops
// the `e2e && !e2e_smoke` (exhaustive-only) files again.
var DefaultTags = []string{"e2e", "e2e_smoke"}

// excludedAll is the go list error for a directory whose every file is
// excluded by build constraints. Under the default tags it means "this
// package exists only under the smoke tags", which is not a failure.
const excludedAll = "build constraints exclude all Go files"

// PackageError mirrors the Error field of `go list -json`.
type PackageError struct {
	Err string
}

// Package is the subset of a `go list -json` record the selector needs.
type Package struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
	Error        *PackageError
}

// testFiles returns the package's _test.go files (internal and external).
func (p Package) testFiles() []string {
	out := make([]string, 0, len(p.TestGoFiles)+len(p.XTestGoFiles))
	out = append(out, p.TestGoFiles...)
	return append(out, p.XTestGoFiles...)
}

// Lister lists the packages matching patterns, as seen from module directory
// dir under the given build tags. A nil/empty tags slice means the default
// build configuration.
type Lister func(ctx context.Context, dir string, tags, patterns []string) ([]Package, error)

// GoList is the production Lister: it runs `go list -e -race -json` in dir.
// With -e, per-package problems are reported in Package.Error rather than as
// a non-zero exit; Select decides which of those are fatal.
//
// -race is passed on every call (tagged and default alike) because the smoke
// recipe runs `go test -race`, which adds the `race` build tag: without it a
// `//go:build e2e && race` file would be invisible here yet built by the
// recipe, silently shrinking the merge gate.
func GoList(ctx context.Context, dir string, tags, patterns []string) ([]Package, error) {
	args := []string{"list", "-e", "-race", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles,Error"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "--")
	args = append(args, patterns...)

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	var pkgs []Package
	dec := json.NewDecoder(&stdout)
	for {
		var p Package
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		pkgs = append(pkgs, p)
	}
}

// Selection is the result of Select.
type Selection struct {
	// Tests maps an import path to the sorted top-level test names declared
	// in that package's smoke-eligible files. Only packages with at least one
	// name are present.
	Tests map[string][]string
	// Warnings are non-fatal diagnostics (e.g. a selected name that also names
	// an untagged test in another selected package).
	Warnings []string
}

// Packages returns the selected import paths, sorted.
func (s *Selection) Packages() []string {
	out := make([]string, 0, len(s.Tests))
	for p := range s.Tests {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Names returns the union of selected test names, sorted and de-duplicated.
func (s *Selection) Names() []string {
	set := map[string]bool{}
	for _, names := range s.Tests {
		for _, n := range names {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RunRegexp returns the anchored `go test -run` expression selecting exactly
// Names() at the top level. It is "" when nothing is selected.
func (s *Selection) RunRegexp() string {
	names := s.Names()
	if len(names) == 0 {
		return ""
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = regexp.QuoteMeta(n)
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}

// Select computes the smoke-tier test selection for patterns in module
// directory dir.
//
// A test file is smoke-eligible when `go list` includes it under tags but not
// under the default build configuration — `go list` is the authority on build
// constraints, so no constraint expression is re-implemented here. Only those
// files are parsed; their top-level test names, per package, form the
// selection. Any package error other than "build constraints exclude all Go
// files" is fatal, because silently skipping a package would silently shrink
// the merge gate.
func Select(ctx context.Context, list Lister, dir string, tags, patterns []string) (*Selection, error) {
	tagged, err := listByPath(ctx, list, dir, tags, patterns)
	if err != nil {
		return nil, err
	}
	plain, err := listByPath(ctx, list, dir, nil, patterns)
	if err != nil {
		return nil, err
	}

	sel := &Selection{Tests: map[string][]string{}}
	for path, tp := range tagged {
		names, err := smokeNames(tp, plain[path])
		if err != nil {
			return nil, err
		}
		if len(names) > 0 {
			sel.Tests[path] = names
		}
	}
	if err := sel.warnCollisions(plain); err != nil {
		return nil, err
	}
	return sel, nil
}

// listByPath runs list and indexes the result by import path, failing on any
// package error other than excludedAll.
func listByPath(ctx context.Context, list Lister, dir string, tags, patterns []string) (map[string]Package, error) {
	pkgs, err := list(ctx, dir, tags, patterns)
	if err != nil {
		return nil, fmt.Errorf("list packages (tags %q): %w", strings.Join(tags, ","), err)
	}
	out := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		if p.Error != nil {
			if strings.Contains(p.Error.Err, excludedAll) {
				continue
			}
			return nil, fmt.Errorf("go list (tags %q): package %s: %s", strings.Join(tags, ","), p.ImportPath, p.Error.Err)
		}
		out[p.ImportPath] = p
	}
	return out, nil
}

// smokeNames parses the test files that tagged has and plain lacks, and
// returns their sorted top-level test names.
func smokeNames(tagged, plain Package) ([]string, error) {
	have := map[string]bool{}
	for _, f := range plain.testFiles() {
		have[f] = true
	}
	var names []string
	for _, f := range tagged.testFiles() {
		if have[f] {
			continue
		}
		got, err := parseFile(filepath.Join(tagged.Dir, f))
		if err != nil {
			return nil, err
		}
		names = append(names, got...)
	}
	sort.Strings(names)
	return names, nil
}

// warnCollisions records a warning for every selected name that also names a
// default-build (untagged) test in some selected package. The run regexp is
// global, so `go test` would run that untagged test in the smoke tier too —
// harmless over-selection, but it is a repeat of a fast-tier test.
func (s *Selection) warnCollisions(plain map[string]Package) error {
	selected := map[string]bool{}
	for _, n := range s.Names() {
		selected[n] = true
	}
	for _, path := range s.Packages() {
		p, ok := plain[path]
		if !ok {
			continue
		}
		for _, f := range p.testFiles() {
			names, err := parseFile(filepath.Join(p.Dir, f))
			if err != nil {
				return err
			}
			for _, n := range names {
				if selected[n] {
					s.Warnings = append(s.Warnings, fmt.Sprintf(
						"%s also names an untagged test in %s (%s); it will run in both the fast and smoke tiers", n, path, f))
				}
			}
		}
	}
	return nil
}

func parseFile(path string) ([]string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}
	return testFuncNames(path, src)
}

// testFuncNames returns the top-level test, fuzz and example function names
// declared in Go source src, following `go test`'s naming rule: the name is
// the prefix alone, or the prefix followed by a rune that is not lowercase.
// Methods, benchmarks and TestMain are excluded.
func testFuncNames(filename string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}
	var names []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		name := fn.Name.Name
		if name == "TestMain" {
			continue
		}
		if isTest(name, "Test") || isTest(name, "Fuzz") || isTest(name, "Example") {
			names = append(names, name)
		}
	}
	return names, nil
}

// isTest mirrors cmd/go's rule for recognising test function names.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}
