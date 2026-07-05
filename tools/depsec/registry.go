package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// releaseClock resolves the wire-published time of a specific package version.
// Extracted as an interface so buildPlan can be exercised with a deterministic
// fake in tests (no network, no wall clock).
//
// Only the Go module proxy is consulted: npm age-gating is handled natively by
// pnpm via web/.npmrc, so we never look up npm release times here.
type releaseClock interface {
	releasedAt(ctx context.Context, ecosystem, name, version string) (time.Time, error)
}

// httpClock looks up Go module release times from the public Go module proxy,
// which exposes a per-version publish timestamp we can trust for the gate.
type httpClock struct {
	hc     *http.Client
	goBase string // default https://proxy.golang.org
}

func newHTTPClock() *httpClock {
	return &httpClock{
		hc:     &http.Client{Timeout: 20 * time.Second},
		goBase: "https://proxy.golang.org",
	}
}

func (c *httpClock) releasedAt(ctx context.Context, ecosystem, name, version string) (time.Time, error) {
	if ecosystem != "go" {
		return time.Time{}, fmt.Errorf("release-age lookup not supported for ecosystem %q (npm is gated by pnpm/.npmrc)", ecosystem)
	}
	url := fmt.Sprintf("%s/%s/@v/%s.info", c.goBase, goModuleEscape(name), version)
	body, err := c.get(ctx, url)
	if err != nil {
		return time.Time{}, err
	}
	var doc struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return time.Time{}, fmt.Errorf("decode go proxy info for %s@%s: %w", name, version, err)
	}
	if doc.Time.IsZero() {
		return time.Time{}, fmt.Errorf("go %s@%s: empty Time in proxy response", name, version)
	}
	return doc.Time, nil
}

func (c *httpClock) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return body, nil
}

// goModuleEscape applies the Go module proxy path encoding: every uppercase
// ASCII letter is replaced by "!" + its lowercase form (see golang.org/x/mod/module).
func goModuleEscape(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
