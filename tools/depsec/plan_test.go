package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeClock returns canned release times keyed by "ecosystem name version".
type fakeClock struct {
	times map[string]time.Time
	errs  map[string]error
}

func (f fakeClock) releasedAt(_ context.Context, eco, name, ver string) (time.Time, error) {
	key := eco + " " + name + " " + ver
	if err := f.errs[key]; err != nil {
		return time.Time{}, err
	}
	t, ok := f.times[key]
	if !ok {
		return time.Time{}, fmt.Errorf("no canned time for %q", key)
	}
	return t, nil
}

func TestBuildPlan(t *testing.T) {
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	minAge := 7 * 24 * time.Hour
	old := now.Add(-30 * 24 * time.Hour)  // eligible
	fresh := now.Add(-2 * 24 * time.Hour) // too new

	clock := fakeClock{times: map[string]time.Time{
		"go github.com/foo/bar v1.2.3": old,
		"go github.com/baz/qux v0.9.0": fresh,
	}}

	alerts := []Alert{
		{Ecosystem: "go", Name: "github.com/foo/bar", FirstPatched: "v1.2.3", Severity: "high"},
		{Ecosystem: "npm", Name: "left-pad", FirstPatched: "1.3.0", Severity: "critical"},
		{Ecosystem: "npm", Name: "nested-thing", FirstPatched: "2.0.1", Severity: "medium"},
		{Ecosystem: "go", Name: "github.com/baz/qux", FirstPatched: "v0.9.0", Severity: "low"},
	}
	npmDirect := map[string]bool{"left-pad": true} // nested-thing is transitive

	plan := buildPlan(context.Background(), alerts, npmDirect, clock, minAge, now)

	if !hasCandidate(plan.GoAccepted, "github.com/foo/bar") {
		t.Errorf("eligible go module should be accepted, got %+v", plan.GoAccepted)
	}
	if !hasCandidate(plan.GoDeferred, "github.com/baz/qux") {
		t.Errorf("too-new go module should be deferred, got %+v", plan.GoDeferred)
	}
	if !hasCandidate(plan.NpmUpdate, "left-pad") {
		t.Errorf("direct npm dep should be routed to pnpm update, got %+v", plan.NpmUpdate)
	}
	if !hasCandidate(plan.NpmManual, "nested-thing") {
		t.Errorf("transitive npm dep should be manual-review, got %+v", plan.NpmManual)
	}

	// npm candidates must NOT trigger a release-age lookup (pnpm/.npmrc owns that).
	if c := findCandidate(plan.NpmUpdate, "left-pad"); c != nil && !c.ReleasedAt.IsZero() {
		t.Errorf("npm candidate should not carry a resolved release time: %+v", c)
	}

	// Deferred candidate carries an eligibility date = released + minAge.
	def := findCandidate(plan.GoDeferred, "github.com/baz/qux")
	if want := fresh.Add(minAge); def == nil || !def.EligibleAt.Equal(want) {
		t.Errorf("EligibleAt = %v, want %v", def, want)
	}
}

func TestBuildPlan_GoGateBoundary(t *testing.T) {
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	minAge := 7 * 24 * time.Hour

	cases := []struct {
		name     string
		released time.Time
		accept   bool
	}{
		{"exactly at min age", now.Add(-minAge), true},
		{"one second short", now.Add(-minAge + time.Second), false},
		{"one second over", now.Add(-minAge - time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := fakeClock{times: map[string]time.Time{"go m v1.0.0": tc.released}}
			plan := buildPlan(context.Background(), []Alert{{Ecosystem: "go", Name: "m", FirstPatched: "v1.0.0"}}, nil, clock, minAge, now)
			got := len(plan.GoAccepted) == 1
			if got != tc.accept {
				t.Errorf("accepted=%v, want %v (deferred=%d)", got, tc.accept, len(plan.GoDeferred))
			}
		})
	}
}

func TestBuildPlan_PicksHighestPatchedVersion(t *testing.T) {
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	old := now.Add(-30 * 24 * time.Hour)
	clock := fakeClock{times: map[string]time.Time{"go m v1.5.0": old}}

	alerts := []Alert{
		{Ecosystem: "go", Name: "m", FirstPatched: "v1.2.0", Severity: "low"},
		{Ecosystem: "go", Name: "m", FirstPatched: "v1.5.0", Severity: "high"},
		{Ecosystem: "go", Name: "m", FirstPatched: "v1.3.0", Severity: "medium"},
	}
	plan := buildPlan(context.Background(), alerts, nil, clock, 7*24*time.Hour, now)
	if len(plan.GoAccepted) != 1 {
		t.Fatalf("want 1 accepted, got %d (%+v, errors=%v)", len(plan.GoAccepted), plan.GoAccepted, plan.Errors)
	}
	if v := plan.GoAccepted[0].TargetVersion; v != "v1.5.0" {
		t.Errorf("target = %s, want v1.5.0 (must satisfy all advisories)", v)
	}
	if s := plan.GoAccepted[0].Severity; s != "high" {
		t.Errorf("severity = %s, want high (max across alerts)", s)
	}
}

func TestBuildPlan_GoNoFixedVersion(t *testing.T) {
	now := time.Now().UTC()
	clock := fakeClock{times: map[string]time.Time{}}
	plan := buildPlan(context.Background(), []Alert{{Ecosystem: "go", Name: "m", FirstPatched: ""}}, nil, clock, time.Hour, now)
	if len(plan.Errors) != 1 {
		t.Fatalf("want 1 error for missing fix, got %v", plan.Errors)
	}
	if n := len(plan.GoAccepted) + len(plan.GoDeferred); n != 0 {
		t.Errorf("no go candidate should be produced without a fixed version, got %d", n)
	}
}

func TestBuildPlan_GoReleaseLookupErrorSkips(t *testing.T) {
	now := time.Now().UTC()
	clock := fakeClock{errs: map[string]error{"go m v1.0.0": fmt.Errorf("proxy 500")}}
	plan := buildPlan(context.Background(), []Alert{{Ecosystem: "go", Name: "m", FirstPatched: "v1.0.0"}}, nil, clock, time.Hour, now)
	if len(plan.GoAccepted) != 0 {
		t.Errorf("must not accept go module when release age is unknown")
	}
	if len(plan.Errors) != 1 {
		t.Errorf("want 1 error recorded, got %v", plan.Errors)
	}
}

func TestBuildPlan_NpmNeedsNoClock(t *testing.T) {
	now := time.Now().UTC()
	// A clock that fails on any call — npm routing must not touch it.
	clock := fakeClock{}
	alerts := []Alert{
		{Ecosystem: "npm", Name: "direct-dep", FirstPatched: "1.0.0", Severity: "high"},
		{Ecosystem: "npm", Name: "trans-dep", FirstPatched: "2.0.0", Severity: "low"},
	}
	plan := buildPlan(context.Background(), alerts, map[string]bool{"direct-dep": true}, clock, time.Hour, now)
	if len(plan.NpmUpdate) != 1 || plan.NpmUpdate[0].Name != "direct-dep" {
		t.Errorf("direct npm routing wrong: %+v", plan.NpmUpdate)
	}
	if len(plan.NpmManual) != 1 || plan.NpmManual[0].Name != "trans-dep" {
		t.Errorf("transitive npm routing wrong: %+v", plan.NpmManual)
	}
	if len(plan.Errors) != 0 {
		t.Errorf("npm routing must not error via clock, got %v", plan.Errors)
	}
}

func hasCandidate(cs []Candidate, name string) bool {
	return findCandidate(cs, name) != nil
}

func findCandidate(cs []Candidate, name string) *Candidate {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}
