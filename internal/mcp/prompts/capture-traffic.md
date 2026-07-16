# Capture Traffic via playwright-cli

Capture HTTP / WebSocket / gRPC traffic by driving a real browser through yorishiro-proxy. Use this to obtain `flow_id`s for the other verification playbooks.

## Prerequisites

- `yorishiro-proxy install` has been run (CA certificate installed).
- `yorishiro-proxy install playwright` has been run (Playwright proxy settings in `.playwright/cli.config.json`).
- `playwright-cli` is available in the host.

## Inputs

- `target_host`: hostname or glob of the application under test (e.g. `*.target.example.com`). Required.
- `listen_addr`: where the proxy should listen (defaults to `127.0.0.1:8080`). Optional.

If `target_host` is empty, ask the user.

## Plan

### 1. Start the proxy with a scoped capture filter

The recording filter (`capture_scope`) drops third-party / CDN / analytics noise from the flow store. Out-of-scope traffic still flows through the proxy unchanged, so the page renders normally — only persistence is suppressed.

```json
// proxy_start
{
  "listen_addr": "{{listen_addr}}",
  "tls_passthrough": ["*.googleapis.com", "*.gstatic.com"],
  "capture_scope": {
    "includes": [
      {"hostname": "{{target_host}}"}
    ],
    "excludes": [
      {"hostname": "*.cloudfront.net"},
      {"url_prefix": "/healthz"}
    ]
  }
}
```

If `listen_addr` was not provided, default to `127.0.0.1:8080`.

Scope tips:
- Use `capture_scope` (recording filter) to keep the flow store focused.
- Use `tls_passthrough` for services with certificate pinning — TLS interception is what breaks pinning, not recording.
- For Cloudflare-style WAF detection issues, configure `tls_fingerprint` on `proxy_start` (default `firefox`).
- Only use `security set_target_scope` (the transmission gate) if you must hard-block third-party requests — it typically breaks browser-driven flows because pages depend on third-party assets.

### 2. Drive the browser via playwright-cli

Use `.playwright/cli.config.json` (installed by `yorishiro-proxy install playwright`). Do not author a separate config.

Perform each operation deliberately and separately — every action you want to use later as a macro step must be its own captured request:

1. Navigate to the login page and log in.
2. Operate the feature under test (CRUD, settings changes, etc.).
3. Log out.

### 3. Verify proxy connection (required after the first page access)

```json
// query
{"resource": "flows", "limit": 5}
```

If zero flows: the browser is not routing through the proxy.

1. Close the playwright-cli browser.
2. Verify `.playwright/cli.config.json` has `proxy.server` matching your `listen_addr`.
3. For Chromium-based browsers, verify `launchOptions.channel` matches an installed browser; in containers, verify `--no-sandbox` is in `launchOptions.args`.
4. Restart playwright-cli and redo step 2.

Do not skip the verification — without a proxy connection, all subsequent operations have to be redone.

### 4. List and filter captured flows

```json
// query
{"resource": "flows", "limit": 50}
```

Narrow by URL pattern or method:

```json
// query
{
  "resource": "flows",
  "filter": {"url_pattern": "/api/", "method": "POST"},
  "limit": 50
}
```

For WebSocket: add `"protocol": "ws"` to the filter.

### 5. Inspect flow details

```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

From the response, identify:
- Request and response headers and bodies.
- CSRF token location (header vs body).
- Session cookie name.
- JSON response shape (for designing extraction rules in macros).

### 6. Map flow IDs to a verification plan

Organise flows by purpose, for example:

```
login-flow:           <flow-id-1>  -- Login request
csrf-page-flow:       <flow-id-2>  -- CSRF token retrieval page
target-api-flow:      <flow-id-3>  -- Target API under test
create-item-flow:     <flow-id-4>  -- Test resource creation
delete-item-flow:     <flow-id-5>  -- Test resource deletion
logout-flow:          <flow-id-6>  -- Logout
```

Pass these `flow_id`s into the verification playbooks (`verify-idor`, `verify-sqli`, `audit-auth`, ...) or feed them into `define_macro` step definitions.

## Narrowing further during analysis

In order from cheapest to most invasive:

1. `capture_scope` (recording filter) — persists only the scoped flows. Tune at `proxy_start`, refine via `configure`.
2. `query` filters — keep recording everything, analyse only a subset.
3. `security set_target_scope` (transmission gate) — blocks the proxy from contacting unscoped hosts at all. Use only for time-boxed engagements.
