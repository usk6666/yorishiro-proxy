package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Alert is the normalized subset of a GitHub Dependabot alert we act on.
type Alert struct {
	Number       int    `json:"number"`
	Ecosystem    string `json:"ecosystem"` // "go" | "npm"
	Name         string `json:"name"`
	ManifestPath string `json:"manifest_path"`
	FirstPatched string `json:"first_patched"` // version identifier, may be empty
	Severity     string `json:"severity"`
	GHSA         string `json:"ghsa"`
	CVE          string `json:"cve"`
	URL          string `json:"url"`
}

// Candidate is a per-package upgrade decision.
type Candidate struct {
	Ecosystem     string    `json:"ecosystem"`
	Name          string    `json:"name"`
	TargetVersion string    `json:"target_version"`
	ManifestPath  string    `json:"manifest_path"`
	Severity      string    `json:"severity"`
	GHSA          string    `json:"ghsa"`
	CVE           string    `json:"cve"`
	URL           string    `json:"url"`
	ReleasedAt    time.Time `json:"released_at,omitempty"`
	AgeDays       float64   `json:"age_days,omitempty"`
	EligibleAt    time.Time `json:"eligible_at,omitempty"` // set when deferred as too-new
	Reason        string    `json:"reason,omitempty"`
}

// Plan is the full decision output for one run.
//
// The minimum-release-age gate is applied differently per ecosystem, on purpose:
//
//   - npm: NOT gated here. web/.npmrc already configures pnpm (>=10.16) with
//     `minimum-release-age` + the Takumi Guard registry, so pnpm enforces the age
//     window and supply-chain proxy natively at install time. We only tell the
//     workflow WHICH direct packages to `pnpm update`; pnpm decides the version.
//     Transitive npm packages are never auto-overridden (NpmManual).
//   - go: Go has no native minimum-release-age mechanism, so we gate explicitly
//     using the module's publish time from the Go proxy (GoAccepted / GoDeferred).
type Plan struct {
	MinAgeDays  float64   `json:"min_age_days"`
	GeneratedAt time.Time `json:"generated_at"`

	GoAccepted []Candidate `json:"go_accepted"` // apply via `go get name@target`
	GoDeferred []Candidate `json:"go_deferred"` // patched version younger than min age
	NpmUpdate  []Candidate `json:"npm_update"`  // direct deps for `pnpm update --latest name` (pnpm gates age)
	NpmManual  []Candidate `json:"npm_manual"`  // transitive npm; manual review only
	Errors     []string    `json:"errors"`
}

// buildPlan groups alerts per package, resolves the highest patched version, and
// routes each package to the correct ecosystem-specific track. `clock` is only
// consulted for Go modules; npm age-gating is delegated to pnpm/.npmrc.
func buildPlan(ctx context.Context, alerts []Alert, npmDirect map[string]bool, clock releaseClock, minAge time.Duration, now time.Time) Plan {
	plan := Plan{
		MinAgeDays:  minAge.Hours() / 24,
		GeneratedAt: now,
	}

	for _, g := range groupByPackage(alerts) {
		cand := Candidate{
			Ecosystem:     g.Ecosystem,
			Name:          g.Name,
			TargetVersion: g.TargetVersion,
			ManifestPath:  g.ManifestPath,
			Severity:      g.Severity,
			GHSA:          g.GHSA,
			CVE:           g.CVE,
			URL:           g.URL,
		}

		switch g.Ecosystem {
		case "npm":
			if npmDirect[g.Name] {
				// Version selection + age gate happen in pnpm via .npmrc.
				plan.NpmUpdate = append(plan.NpmUpdate, cand)
			} else {
				cand.Reason = "transitive npm dependency; not auto-overridden (manual review required)"
				plan.NpmManual = append(plan.NpmManual, cand)
			}

		case "go":
			if g.TargetVersion == "" {
				plan.Errors = append(plan.Errors,
					fmt.Sprintf("go %s: no fixed version in any advisory; needs manual triage", g.Name))
				continue
			}
			released, err := clock.releasedAt(ctx, g.Ecosystem, g.Name, g.TargetVersion)
			if err != nil {
				plan.Errors = append(plan.Errors,
					fmt.Sprintf("go %s@%s: cannot determine release age (%v); skipped for safety", g.Name, g.TargetVersion, err))
				continue
			}
			cand.ReleasedAt = released
			age := now.Sub(released)
			cand.AgeDays = age.Hours() / 24
			if age < minAge {
				cand.EligibleAt = released.Add(minAge)
				cand.Reason = fmt.Sprintf("released %.1fd ago (< %.0fd minimum release age)", cand.AgeDays, plan.MinAgeDays)
				plan.GoDeferred = append(plan.GoDeferred, cand)
				continue
			}
			plan.GoAccepted = append(plan.GoAccepted, cand)

		default:
			plan.Errors = append(plan.Errors,
				fmt.Sprintf("%s %s: unsupported ecosystem; needs manual triage", g.Ecosystem, g.Name))
		}
	}

	sortCandidates(plan.GoAccepted)
	sortCandidates(plan.GoDeferred)
	sortCandidates(plan.NpmUpdate)
	sortCandidates(plan.NpmManual)
	sort.Strings(plan.Errors)
	return plan
}

type pkgGroup struct {
	Ecosystem     string
	Name          string
	ManifestPath  string
	TargetVersion string
	Severity      string
	GHSA          string
	CVE           string
	URL           string
}

// groupByPackage collapses multiple alerts for the same (ecosystem, name) into
// one upgrade target: the highest first-patched version across the alerts, which
// is the single bump that resolves them all.
func groupByPackage(alerts []Alert) []pkgGroup {
	byKey := map[string]*pkgGroup{}
	order := []string{}
	for _, a := range alerts {
		key := a.Ecosystem + "\x00" + a.Name
		g, ok := byKey[key]
		if !ok {
			g = &pkgGroup{Ecosystem: a.Ecosystem, Name: a.Name, ManifestPath: a.ManifestPath}
			byKey[key] = g
			order = append(order, key)
		}
		if a.FirstPatched != "" && (g.TargetVersion == "" || compareVersions(a.FirstPatched, g.TargetVersion) > 0) {
			g.TargetVersion = a.FirstPatched
		}
		// Track the highest severity + a representative advisory for the PR body.
		if g.GHSA == "" || severityRank(a.Severity) > severityRank(g.Severity) {
			g.Severity = maxSeverity(g.Severity, a.Severity)
			g.GHSA = a.GHSA
			g.CVE = a.CVE
			g.URL = a.URL
		}
	}
	out := make([]pkgGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

func maxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sortCandidates(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if r := severityRank(cs[j].Severity) - severityRank(cs[i].Severity); r != 0 {
			return r < 0
		}
		return cs[i].Name < cs[j].Name
	})
}
