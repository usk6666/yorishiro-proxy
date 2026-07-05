// Command depsec reads a repository's open Dependabot alerts, decides which
// fixes are old enough to apply under a minimum-release-age gate, and writes a
// machine-readable plan plus a Markdown PR body. It performs no git/go/pnpm
// mutations itself — the calling workflow applies the accepted bumps. This keeps
// the security-sensitive decision logic pure and unit-tested.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		owner   = flag.String("owner", "", "repository owner")
		repo    = flag.String("repo", "", "repository name")
		minAge  = flag.Duration("min-age", 7*24*time.Hour, "minimum release age before a fix is applied")
		pkgJSON = flag.String("package-json", "web/package.json", "path to the npm package.json for direct-dependency classification")
		planOut = flag.String("plan-out", "plan.json", "path to write the JSON plan")
		bodyOut = flag.String("body-out", "pr-body.md", "path to write the Markdown PR body")
		apiBase = flag.String("api-base", "https://api.github.com", "GitHub API base URL")
	)
	flag.Parse()

	if *owner == "" || *repo == "" {
		fatal("owner and repo are required")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fatal("GITHUB_TOKEN env is required (needs Dependabot alerts: read)")
	}

	ctx := context.Background()
	alerts, err := fetchAlerts(ctx, *apiBase, *owner, *repo, token)
	if err != nil {
		fatal("fetch alerts: %v", err)
	}

	npmDirect, err := loadNpmDirect(*pkgJSON)
	if err != nil {
		// Non-fatal: without package.json every npm alert is treated as transitive
		// (routed to manual review), which is the safe default.
		fmt.Fprintf(os.Stderr, "warning: %v; treating all npm alerts as transitive\n", err)
		npmDirect = map[string]bool{}
	}

	plan := buildPlan(ctx, alerts, npmDirect, newHTTPClock(), *minAge, time.Now().UTC())

	if err := writeJSON(*planOut, plan); err != nil {
		fatal("write plan: %v", err)
	}
	if err := os.WriteFile(*bodyOut, []byte(renderBody(plan)), 0o644); err != nil {
		fatal("write body: %v", err)
	}

	fmt.Printf("alerts: %d open · go-accepted: %d · go-deferred: %d · npm-update: %d · npm-manual: %d · errors: %d\n",
		len(alerts), len(plan.GoAccepted), len(plan.GoDeferred), len(plan.NpmUpdate), len(plan.NpmManual), len(plan.Errors))
	for _, c := range plan.GoAccepted {
		fmt.Printf("  go get   %s@%s (%.1fd old)\n", c.Name, c.TargetVersion, c.AgeDays)
	}
	for _, c := range plan.NpmUpdate {
		fmt.Printf("  pnpm up  %s (advisory fix %s)\n", c.Name, c.TargetVersion)
	}
	for _, c := range plan.GoDeferred {
		fmt.Printf("  defer    go %s@%s (eligible %s)\n", c.Name, c.TargetVersion, c.EligibleAt.Format("2006-01-02"))
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "depsec: "+format+"\n", args...)
	os.Exit(1)
}

// ghAlert mirrors the fields we consume from the Dependabot alerts REST API.
type ghAlert struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	HTMLURL    string `json:"html_url"`
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
	} `json:"dependency"`
	SecurityVulnerability struct {
		Severity            string `json:"severity"`
		FirstPatchedVersion struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
	SecurityAdvisory struct {
		GHSAID string `json:"ghsa_id"`
		CVEID  string `json:"cve_id"`
	} `json:"security_advisory"`
}

func fetchAlerts(ctx context.Context, apiBase, owner, repo, token string) ([]Alert, error) {
	hc := &http.Client{Timeout: 30 * time.Second}
	// The Dependabot alerts API uses cursor pagination (Link header rel="next"),
	// NOT ?page=N — the page parameter returns HTTP 400. Follow the Link header.
	url := fmt.Sprintf("%s/repos/%s/%s/dependabot/alerts?state=open&per_page=100", apiBase, owner, repo)
	var out []Alert
	for pages := 0; url != "" && pages < 1000; pages++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("status %d — token lacks 'Dependabot alerts: read'? body: %s", resp.StatusCode, truncate(body, 300))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(body, 300))
		}

		var batch []ghAlert
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("decode alerts: %w", err)
		}
		for _, a := range batch {
			if a.State != "open" {
				continue
			}
			out = append(out, Alert{
				Number:       a.Number,
				Ecosystem:    strings.ToLower(a.Dependency.Package.Ecosystem),
				Name:         a.Dependency.Package.Name,
				ManifestPath: a.Dependency.ManifestPath,
				FirstPatched: a.SecurityVulnerability.FirstPatchedVersion.Identifier,
				Severity:     a.SecurityVulnerability.Severity,
				GHSA:         a.SecurityAdvisory.GHSAID,
				CVE:          a.SecurityAdvisory.CVEID,
				URL:          a.HTMLURL,
			})
		}

		next := parseNextLink(link)
		if next == "" || next == url {
			break
		}
		url = next
	}
	return out, nil
}

// parseNextLink extracts the rel="next" URL from a GitHub Link header, or "" if
// there is no next page. Format:
//
//	<https://api.github.com/...&after=CUR>; rel="next", <...>; rel="prev"
func parseNextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		segs := strings.Split(part, ";")
		if len(segs) < 2 {
			continue
		}
		u := strings.TrimSpace(segs[0])
		if !strings.HasPrefix(u, "<") || !strings.HasSuffix(u, ">") {
			continue
		}
		for _, s := range segs[1:] {
			if v := strings.TrimSpace(s); v == `rel="next"` || v == "rel=next" {
				return u[1 : len(u)-1]
			}
		}
	}
	return ""
}

// loadNpmDirect returns the set of package names declared directly in
// package.json (dependencies + devDependencies).
func loadNpmDirect(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	set := map[string]bool{}
	for name := range doc.Dependencies {
		set[name] = true
	}
	for name := range doc.DevDependencies {
		set[name] = true
	}
	return set, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
