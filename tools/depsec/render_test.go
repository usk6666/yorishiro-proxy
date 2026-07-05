package main

import (
	"strings"
	"testing"
	"time"
)

func TestRenderBody(t *testing.T) {
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	plan := Plan{
		MinAgeDays:  7,
		GeneratedAt: now,
		GoAccepted: []Candidate{
			{Ecosystem: "go", Name: "github.com/foo/bar", TargetVersion: "v1.2.3", Severity: "high", AgeDays: 30, GHSA: "GHSA-xxxx", URL: "https://example/adv"},
		},
		NpmUpdate: []Candidate{
			{Ecosystem: "npm", Name: "left-pad", TargetVersion: "1.3.0", Severity: "critical", GHSA: "GHSA-zzzz"},
		},
		GoDeferred: []Candidate{
			{Ecosystem: "go", Name: "github.com/baz/qux", TargetVersion: "v0.9.0", Severity: "low", EligibleAt: now.Add(5 * 24 * time.Hour)},
		},
		NpmManual: []Candidate{
			{Ecosystem: "npm", Name: "nested", TargetVersion: "2.0.1", Severity: "medium", GHSA: "GHSA-yyyy"},
		},
		Errors: []string{"go weird/mod: no fixed version"},
	}

	body := renderBody(plan)
	for _, want := range []string{
		"minimum release age: 7 days",
		"### Go — applied",
		"`github.com/foo/bar`",
		"[GHSA-xxxx](https://example/adv)",
		"### npm — updated",
		"`left-pad`",
		"### Go — deferred",
		"github.com/baz/qux",
		"2026-07-10", // eligible date
		"### npm — needs manual review",
		"`nested`",
		"### Could not process",
		"no fixed version",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n---\n%s", want, body)
		}
	}
}
