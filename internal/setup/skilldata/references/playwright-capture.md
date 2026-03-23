# Playwright-CLI Integration Capture Procedure

Combine yorishiro-proxy with playwright-cli to capture traffic from browser operations.

## Prerequisites

- `yorishiro-proxy install` has been run (CA certificate installed)
- `yorishiro-proxy install playwright` has been run (proxy settings configured in `.playwright/cli.config.json`)
  - This subcommand auto-detects the browser and configures `channel` to match the environment (priority: chromium > firefox > chrome)
  - In container environments (Docker/devcontainer/Codespaces) with Chromium-based browsers, `--no-sandbox` is automatically added
  - If no browser is detected, automatically attempts installation via `npx playwright install <browser>`
- playwright-cli skill is installed

## Step 1: Start the Proxy

Start with a scope configured to capture only the target host.

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [
      {"hostname": "target.example.com"}
    ],
    "excludes": [
      {"hostname": "static.example.com"},
      {"url_prefix": "/assets/"}
    ]
  },
  "tls_passthrough": ["*.googleapis.com", "*.gstatic.com"]
}
```

**Scope design tips:**
- Use `includes` to limit to the target host only (reduces noise)
- Use `excludes` to filter out static assets, health checks, etc.
- Use `tls_passthrough` to exclude services with certificate pinning
- If bot detection triggers on Cloudflare or similar WAFs, configure `tls_fingerprint` (default: "chrome")

## Step 2: Browser Operations with playwright-cli

Use playwright-cli to operate the target application.
Proxy settings are automatically configured in `.playwright/cli.config.json` by `yorishiro-proxy install`.

**Required**: Always use `.playwright/cli.config.json` when launching playwright-cli. Do not create custom configuration files.

Example operations:
1. Navigate to the login page and log in
2. Operate the feature under test (CRUD operations, settings changes, etc.)
3. Log out

**Important**: Since you will reference each operation as a Macro step later, perform each action deliberately and separately.

Once the first page access is complete, **you must verify the proxy connection in Step 2.5 before continuing**.

## Step 2.5: Verify Proxy Connection (Required)

After the first page access, verify that traffic is being recorded via the proxy.

```json
// query
{"resource": "flows", "limit": 5}
```

### If 1 or More Flows Exist

Proxy connection is working. Proceed to Step 3.

### If 0 Flows Exist

The browser is not routing through the proxy. Fix using the following steps:

1. Close the playwright-cli browser
2. Check `.playwright/cli.config.json` and verify the settings are correct:
   - Does `proxy.server` match the `listen_addr` from `proxy_start`?
   - Does `browser.browserName` match the expected browser (`"chromium"`, `"firefox"`, `"webkit"`)?
   - For Chromium-based browsers only, does `launchOptions.channel` match a browser installed in the environment (`yorishiro-proxy install playwright` can auto-detect and reconfigure this)? For Firefox/WebKit, `channel` should be empty/unset.
   - In container environments with Chromium-based browsers, does `launchOptions.args` include `--no-sandbox`? (usually added automatically)
3. After fixing the settings, restart playwright-cli and redo from Step 2

**Do not skip this step.** If you continue without a proxy connection:
- All operations must be redone (flows were not recorded)
- `capture_scope` and `security` target scope controls will not function

## Step 3: Review Captured Flows

```json
// query
{"resource": "flows", "limit": 50}
```

Filter by a specific URL pattern:

```json
// query
{
  "resource": "flows",
  "filter": {"url_pattern": "/api/", "method": "POST"},
  "limit": 50
}
```

## Step 4: Review Flow Details

Check the details of each flow to identify the flow IDs to use in Macros.

```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

From the response, verify:
- Request/response headers and body
- Location of CSRF token (header or body)
- Session cookie name
- JSON structure of the response (for designing extraction rules)

## Step 5: Map Flow IDs

Organize the captured flows by purpose:

```
login-flow:          <flow-id-1>  -- Login request
csrf-page-flow:      <flow-id-2>  -- CSRF token retrieval page
target-api-flow:     <flow-id-3>  -- Target API under test
create-item-flow:    <flow-id-4>  -- Test resource creation
delete-item-flow:    <flow-id-5>  -- Test resource deletion
logout-flow:         <flow-id-6>  -- Logout
```

Reference these flow IDs as `flow_id` in each step of the Macro definition (`define_macro`).

## Changing Scope During Testing

If you need to change scope during testing, use `configure`:

```json
// configure
{
  "capture_scope": {
    "add_includes": [{"hostname": "api2.target.example.com"}]
  }
}
```

## Tips

- If unwanted flows accumulate during capture, narrow the scope
- Use `filter` and `limit` when the flow list gets large
- Check WebSocket flows using the `protocol` filter: `{"filter": {"protocol": "WebSocket"}}`
