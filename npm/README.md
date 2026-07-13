# npm distribution (maintainer notes)

This directory holds the templates and generator that turn the cross-compiled Go
binaries (produced by `.github/workflows/release.yml`) into npm packages, using
the **optionalDependencies pattern** (the same approach as esbuild / Biome / swc):

- `@usk6666/yorishiro-proxy` — parent package. Ships only `bin/cli.js` and lists
  the five platform packages in `optionalDependencies`. No binary, no
  postinstall.
- `@usk6666/yorishiro-proxy-<os>-<cpu>` — five platform packages, each declaring
  `os`/`cpu` and bundling exactly one prebuilt binary.

npm installs exactly the one child whose `os`/`cpu` match the host and silently
skips the rest. `bin/cli.js` resolves that child's binary via `require.resolve`
and re-execs it with full argv passthrough. Because there is **no postinstall and
no network fetch at install time**, this works under `--ignore-scripts`, in CI,
behind corporate proxies, on offline mirrors, and is robust against supply-chain
attacks.

## Files

| Path                        | Role                                                                 |
| --------------------------- | -------------------------------------------------------------------- |
| `generate.mjs`              | Generator. **Single source of truth** for the GOOS/GOARCH→os/cpu table and platform list. Zero dependencies (Node stdlib only). |
| `parent/package.json`       | Parent metadata base. The generator injects `version` + `optionalDependencies`. |
| `parent/bin/cli.js`         | Zero-dependency CLI shim (argv passthrough + exit-code fidelity).     |
| `parent/README.md`          | Published parent README (user-facing).                               |
| `child.template/README.md`  | Published child README template (`{{PKG_NAME}}`/`{{OS}}`/`{{CPU}}`).  |

## Local dry-run

```bash
# Fabricate release-named dummy binaries.
mkdir -p /tmp/usk-dist
for t in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
  name="yorishiro-proxy-v0.16.0-${t}"; [ "$t" = "windows-amd64" ] && name="${name}.exe"
  printf '#!/bin/sh\n' > "/tmp/usk-dist/${name}"
done

node npm/generate.mjs --version v0.16.0 --dist /tmp/usk-dist --out /tmp/usk-npm
ls /tmp/usk-npm            # 6 package dirs
```

The tag string (`v0.16.0`) is used verbatim to locate the binary files; the
leading `v` is stripped only for the npm `version` field (`0.16.0`).

## Publish order

Children first, parent last — so that when the parent hits the registry, all of
its `optionalDependencies` already resolve:

```
@usk6666/yorishiro-proxy-linux-x64
@usk6666/yorishiro-proxy-linux-arm64
@usk6666/yorishiro-proxy-darwin-x64
@usk6666/yorishiro-proxy-darwin-arm64
@usk6666/yorishiro-proxy-win32-x64
@usk6666/yorishiro-proxy            <- last
```

Prereleases (tag matching `-(alpha|beta|rc)`) publish under the `next` dist-tag;
all others publish to `latest`. This mirrors the GitHub Release `--prerelease`
detection so the two channels stay consistent.

## One-time manual prerequisite: Trusted Publishing (OIDC)

CI publishes with npm **Trusted Publishing** (OIDC) — no long-lived `NPM_TOKEN`,
`--provenance` attached. Before the FIRST publish can succeed, a maintainer must
register the trusted publisher **once**, manually, in the npm web UI for each of
the six package names (or configure it at the org level for `@usk6666`):

1. Sign in to npmjs.com as an owner of the `@usk6666` scope.
2. For each package, open **Settings → Trusted Publishing → GitHub Actions** and
   add: repository `usk6666/yorishiro-proxy`, workflow `release.yml`.
   (For not-yet-created packages, create the package once by publishing, or
   pre-register via the org settings.)
3. Ensure the npm version used in CI is ≥ 11.5.1 (the workflow pins this).

Until this registration exists, `npm publish --provenance` from CI will fail with
an OIDC authorization error. GitHub Releases + `yorishiro-proxy upgrade`
self-update continue to work regardless of npm publish status.
