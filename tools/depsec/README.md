# depsec — supply-chain-aware Dependabot update planner

A tiny, stdlib-only Go module (separate from the main module, so it is never
compiled into the proxy binary). It reads the repository's open Dependabot
alerts and decides which fixes are safe to apply this run under a
**minimum-release-age** gate. It writes a machine-readable `plan.json` and a
Markdown `pr-body.md`; it performs **no** git/go/pnpm mutations itself — the
calling workflow (`.github/workflows/dependabot-security.yml`) applies the plan.

## Why the split between Go and npm

The minimum-release-age policy (a released version must have been public for at
least N days before we adopt it — supply-chain hardening) is applied through the
mechanism native to each ecosystem:

| Ecosystem | Age gate mechanism | This tool's role |
|-----------|--------------------|------------------|
| **npm**   | pnpm (>= 10.16) via `web/.npmrc` `minimum-release-age=10080` (7 days) + Takumi Guard registry + `minimum-release-age-exclude[]` | Only classifies which **direct** deps Dependabot flagged, so the workflow runs `pnpm update --latest <them>`. pnpm refuses too-new versions. Transitive npm packages are routed to manual review, never auto-overridden. |
| **go**    | none native | This tool queries the Go module proxy for each fix's publish time and applies only fixes `>= min-age` old (`go_accepted`); newer fixes are deferred (`go_deferred`) and retried next run. |

## Run

```bash
GITHUB_TOKEN=<token with Dependabot alerts: read> \
  go run . -owner <owner> -repo <repo> \
    -package-json ../../web/package.json \
    -plan-out plan.json -body-out pr-body.md \
    -min-age 168h        # matches web/.npmrc 10080 minutes = 7 days
```

`GITHUB_TOKEN` **must** grant `Dependabot alerts: read` — the default Actions
`GITHUB_TOKEN` does not, which is why the workflow mints a GitHub App token.

## Required repository secrets (for the workflow)

Create a GitHub App installed on this repo only, with permissions:
**Dependabot alerts: read**, **Contents: write**, **Pull requests: write**.
Store its credentials as:

- `DEPSEC_APP_ID`
- `DEPSEC_APP_PRIVATE_KEY`

## Test

```bash
go test -race ./...
```
