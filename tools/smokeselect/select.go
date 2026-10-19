package main

import (
	"context"
	"errors"
)

// DefaultTags are the build tags that define the smoke tier (USK-728): the
// `e2e` tag admits every e2e file, and the `e2e_smoke` exclusion filter drops
// the `e2e && !e2e_smoke` (exhaustive-only) files again.
var DefaultTags = []string{"e2e", "e2e_smoke"}

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

// Lister lists the packages matching patterns, as seen from module directory
// dir under the given build tags. A nil/empty tags slice means the default
// build configuration.
type Lister func(ctx context.Context, dir string, tags, patterns []string) ([]Package, error)

// GoList is the production Lister: it runs `go list -e -json`.
func GoList(ctx context.Context, dir string, tags, patterns []string) ([]Package, error) {
	return nil, errors.New("not implemented")
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
func (s *Selection) Packages() []string { return nil }

// Names returns the union of selected test names, sorted and de-duplicated.
func (s *Selection) Names() []string { return nil }

// RunRegexp returns the anchored `go test -run` expression selecting exactly
// Names() at the top level.
func (s *Selection) RunRegexp() string { return "" }

// Select computes the smoke-tier test selection.
func Select(ctx context.Context, list Lister, dir string, tags, patterns []string) (*Selection, error) {
	return &Selection{}, nil
}

// testFuncNames returns the top-level test, fuzz and example function names
// declared in Go source src, following `go test`'s naming rule.
func testFuncNames(filename string, src []byte) ([]string, error) {
	return nil, nil
}
