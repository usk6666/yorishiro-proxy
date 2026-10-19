# security tool

Configure runtime security settings including target scope rules.

This tool is separate from `configure` to allow MCP clients to apply different approval policies (e.g., manual approval for security changes).

## Two-Layer Architecture

Target scope uses a **Policy Layer** and an **Agent Layer**:

- **Policy Layer** (immutable by the agent): Set at startup from `-target-policy-file`, else the config file's `target_scope_policy` section. Defines the upper boundary for what the agent can access. No action of this tool — or of any MCP tool, over stdio or HTTP — can modify it; only the operator can replace it at runtime (see [Reloading the Policy Layer](#reloading-the-policy-layer-operator-only)). Policy rules are validated at startup with the same rules as this tool (`schemes` only `http` / `https`, ports 1-65535, a hostname that can match — no `*`, `host:port` or URL), except that a Policy rule may omit `hostname`; `rate_limits` / `budget` values must be >= 0, and the dedicated policy file must not contain unknown fields. An invalid policy stops the server instead of loading a rule that silently matches nothing.
- **Agent Layer** (mutable): Controlled by this tool. Can further restrict access within the Policy Layer boundaries. Agent allow rules must fall within the Policy allow scope.

### Evaluation Order

1. **Policy denies** -- always block (highest priority)
2. **Agent denies** -- block
3. **Policy allows** (if any) -- target must match at least one, otherwise block
4. **Agent allows** (if any) -- target must match at least one, otherwise block
5. All checks passed -- allow

When neither layer has rules, all targets are permitted (open mode).

### Applicability

Both Policy Layer and Agent Layer `target_scope` rules apply to **all** proxy traffic. There is a single shared `target_scope` evaluator (Policy + Agent rules merged via the order above); every code path that opens or forwards a connection consults it.

| Traffic source | Policy Layer | Agent Layer |
|---|---|---|
| Transparent MITM (HTTP CONNECT tunnel, plain HTTP forward proxy, SOCKS5 tunnel) | Applied | Applied |
| MCP tool-initiated requests (`resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`, `fuzz_http`, `fuzz_ws`, `fuzz_grpc`, `fuzz_raw`, `macro`) | Applied | Applied |
| Intercepted traffic released from a hold (`intercept` `release` / `modify_and_forward`, timeout auto-release) | Applied | Applied |

This means `set_target_scope` and `update_target_scope` take effect immediately for both AI-agent-driven MCP calls and any client traffic flowing through the proxy (curl, browser, etc.). The same evaluator drives both the live pipeline's `HostScopeStep` / `HTTPScopeStep` and the MCP-tool pre-flight check.

#### Deny manifestation by path

A `target_scope` deny surfaces differently depending on how the request entered the proxy. Operators should read the symptom in context:

| Path | Deny symptom |
|---|---|
| Transparent HTTPS via CONNECT tunnel | Proxy returns `HTTP/1.1 200 Connection Established` (the tunnel acknowledgement is sent before the scope check), then closes the connection. The client's inner TLS handshake fails with EOF. Note that the `200` line refers to the CONNECT tunnel, **not** to the backend -- no backend bytes are exchanged. |
| Transparent plain-HTTP forward proxy | Proxy returns `HTTP/1.1 403 Forbidden` with body `yorishiro-proxy: target blocked by scope`. |
| MCP tool-initiated request (`resend_*`, `fuzz_*`, `macro`) | MCP error response with the violation reason. |
| Intercept release (`release`, `modify_and_forward`, timeout auto-release) | The `intercept` call itself succeeds. Scope is checked again at release time, with the rules in force then, against the request being forwarded — for `modify_and_forward`, the modified one. A deny added while the request was held (policy reload or this tool) or a rewrite of `authority` / `path` into a denied target blocks it: an HTTP request gets `403 Forbidden` with body `{"error":"blocked by target_scope","blocked_by":"target_scope"}`, a WebSocket / gRPC message is dropped, and the block is recorded as a flow with `blocked_by: target_scope`. |

### Reloading the Policy Layer (operator only)

The operator replaces the running Policy Layer — target scope `allows` / `denies`, `rate_limits` and `budget` together — by editing the policy source and sending the server process `SIGHUP` (Unix only). There is deliberately no MCP tool or action for this: the path is reserved for whoever controls the process, never for the agent.

- **Enabled only with a policy source**: the `SIGHUP` handler is installed only when the server was started with `-target-policy-file` or `-config`. Without either, `SIGHUP` terminates the process as before.
- **When it is safe to signal**: the handler is installed only once the flags are parsed and the boot policy has loaded, so a `SIGHUP` sent earlier in startup still terminates the process. Wait for the Info line `target scope policy reload enabled` before sending `SIGHUP`.
- **Terminal hangup**: closing the terminal that launched the server also sends `SIGHUP`. With a policy source configured this now triggers a reload instead of stopping the server, so the process keeps running and keeps its listening ports. Stop it explicitly with `SIGTERM` or `SIGINT`.
- **Source**: the same one used at startup — `-target-policy-file` when given, otherwise the config file's `target_scope_policy` section (the whole config file is validated as at startup, but only the policy section is applied; other config sections are not reloaded).
- **Full replacement**: reloading is equivalent to starting with that file. A section omitted from the new file (e.g. `rate_limits`) is cleared.
- **Atomic**: the new file is validated completely before anything changes. Malformed JSON, an out-of-vocabulary `schemes` token or a negative limit rejects the whole reload; the previous policy stays in force and an Error line (`target scope policy reload rejected; previous policy retained`) is logged.
- **Unknown fields — prefer `-target-policy-file` for live edits**: only `-target-policy-file` is decoded strictly, so an unknown or misspelled field there (e.g. `denys`) rejects the reload. The `-config` source is decoded leniently, exactly as at startup: a misspelled `target_scope_policy` key, a misspelled key inside it (e.g. `deny` for `denies`), or a file that is just `{}` or `null` is accepted and reloads as "no policy", dropping the rules it was meant to keep. When a reload drops every policy allow and deny rule, a Warn line (`reloaded policy has no allow or deny rules; the previous target scope policy rules were removed`) names the source path and the previous counts. Check for it after every reload.
- **What it applies to**: new connections and new requests, and also work already in flight. Every live connection admitted by the CONNECT, SOCKS5 or plain-HTTP-forward gate — TLS passthrough relays, MITM'd HTTP/1.x / HTTP/2 / WebSocket / SSE / gRPC connections and raw (bytechunk) tunnels alike — is re-evaluated with the same check that admitted it (the CONNECT / SOCKS5 authority or forward target, never the SNI), and is closed when an identical new connection would no longer be admitted. One Info line (`live connection closed: target no longer in scope`) is logged per closed connection, and the reload's Info line carries `live_conns_closed` (a Warn line is added when it is non-zero). A connection with held intercepts is revoked at once — new requests on it are answered 403 `blocked_by: target_scope` and nothing more is sent to the denied host — but closed only after its holds are released or time out; each held request is then answered and recorded per the release re-check below. Until then, data the denied host sends toward the client (responses of other HTTP/2 streams, SSE events, WebSocket server frames) keeps flowing, bounded by the intercept hold timeout: a revoked connection takes no new holds, so a server message that matches an intercept rule meanwhile is dropped (`blocked_by: target_scope`) instead of held. `live_conns_closed` counts the revoked connections and `live_conns_deferred` the ones whose close was deferred this way (`live connection revoked: close deferred until intercept holds resolve` is logged for each, then the `closed` line once they close). A deny that only names a `path_prefix` closes no connection; it is enforced per request. Running fuzz jobs re-check the scope for every variant they send, and a held intercept re-checks it when released (manually, by timeout auto-release, or via `modify_and_forward`). The same reconciliation runs after `set_target_scope` / `update_target_scope`.
- **Agent Layer on narrowing**: Agent rules are kept unchanged. An agent allow rule the new policy no longer covers simply stops matching (requests to it are blocked with `not in policy allow list`) and a Warn line lists such rules. The agent's restriction is never dropped, so narrowing the policy never widens what the agent can reach.
- **Budget**: the request counter is **not** reset by a reload; the duration limit is re-armed against the new value, measured from the original session start. A budget narrowed below current usage stops the proxy (on the next request, or immediately for the duration limit).
- **Audit**: a successful reload logs `target scope policy reloaded` at Info with the trigger, source path, file `sha256` and `mtime`, rule counts before/after, and the resulting policy and effective rate limits and budget. `get_target_scope` reports `source` and `loaded_at` so the agent can see that the policy changed.
- **Placement**: keep the policy file in a directory that neither the proxy's user nor the agent can write. File permissions alone are not enough — anyone who can write the directory can replace the file by rename, which is how `manage` export writes its files — so never place it where `manage` export can write.

## Actions

### `set_target_scope`

Replace all Agent Layer allow/deny rules. Use empty arrays to clear rules.

Agent allow rules must fall within the Policy allow boundary. If any agent allow rule is outside the policy scope, the entire operation is rejected with an error.

```json
{
  "action": "set_target_scope",
  "params": {
    "allows": [
      {"hostname": "api.target.com", "ports": [443], "schemes": ["https"]},
      {"hostname": "*.target.com"}
    ],
    "denies": [
      {"hostname": "admin.target.com"}
    ]
  }
}
```

### `update_target_scope`

Apply incremental changes to Agent Layer rules.

- `add_allows` / `remove_allows` -- modify agent allow rules
- `add_denies` / `remove_denies` -- modify agent deny rules
- `add_allows` rules must fall within the Policy allow boundary
- `remove_denies` cannot remove Policy deny rules (returns error)
- Duplicate additions are ignored

```json
{
  "action": "update_target_scope",
  "params": {
    "add_allows": [{"hostname": "new-api.target.com"}],
    "remove_allows": [{"hostname": "old-api.target.com"}],
    "add_denies": [{"hostname": "staging.target.com"}]
  }
}
```

### `get_target_scope`

Returns both Policy and Agent Layer rules with their enforcement mode.

```json
{
  "action": "get_target_scope"
}
```

Response:

```json
{
  "policy": {
    "allows": [{"hostname": "*.target.com"}],
    "denies": [{"hostname": "*.internal.corp"}],
    "source": "policy file",
    "loaded_at": "2026-10-16T09:30:00Z",
    "immutable": true
  },
  "agent": {
    "allows": [{"hostname": "api.target.com"}],
    "denies": [{"hostname": "admin.target.com"}]
  },
  "effective_mode": "enforcing"
}
```

### `test_target`

Check a URL against current rules without making a request (dry run). Reports which layer and rule decided the outcome.

```json
{
  "action": "test_target",
  "params": {
    "url": "https://api.target.com/v1/users"
  }
}
```

Response:

```json
{
  "allowed": true,
  "reason": "",
  "layer": "agent",
  "matched_rule": {"hostname": "api.target.com"},
  "tested_target": {"hostname": "api.target.com", "port": 443, "scheme": "https", "path": "/v1/users"}
}
```

## Target Rule Fields

| Field | Type | Description |
|---|---|---|
| `hostname` | string | Required. Exact match or wildcard `*.example.com`. IPv4 and IPv6 literals are accepted; IPv6 may be bare (`::1`) or bracketed (`[::1]`) and every zone-less textual form of one address is the same host. A zone-qualified target such as `[fe80::1%eth0]` keeps its zone and does not match a zone-less rule (rules cannot carry a zone). A wildcard over an IP literal (`*.10.0.0.1`) is rejected |
| `ports` | int[] | Optional. Match specific ports. Empty = all ports |
| `path_prefix` | string | Optional. Literal, case-sensitive prefix of the request path — not a glob. Must start with `/`; `*`, `?` and `#` are rejected (`/api/` already matches everything under `/api/`; the query and fragment are not part of the path). Matches when either the wire-form path or its percent-decoded form starts with the prefix (`/admin` also matches `/%61dmin`; `/a%20b` matches the wire bytes `/a%20b`); dot-segments and `%2F` are not normalized. Empty = all paths |
| `schemes` | string[] | Optional. Match transport confidentiality: `http` = plaintext, `https` = TLS. Only these two values are accepted. Empty = both |

All specified fields must match for a rule to apply (AND logic).

### What `schemes` means

`schemes` is a **transport confidentiality** axis, not an L7 application-protocol
axis. It is spelled with the `http` / `https` tokens because those are the names
operators already use for "plaintext" and "TLS", but it applies to every protocol
the proxy scopes:

- A WebSocket target is matched as `http` (`ws://`) or `https` (`wss://`). Writing
  `"schemes": ["ws"]` is rejected — the rule would never match anything.
- A raw TCP or gRPC target is matched the same way: `https` when the leg is
  TLS-terminated, `http` when it is cleartext.
- A `CONNECT` tunnel is matched as `https` even if it turns out to carry SMTP.

**A `schemes` condition narrows a rule in both directions.** A deny rule carrying
`"schemes": ["https"]` does not block the plaintext dial to the same host, and an
allow rule carrying `"schemes": ["https"]` does not permit one. Omit `schemes` when
you mean "this host, on any transport" — that is the safer default for deny rules.

**SOCKS5 targets are deliberately unmatchable by any `schemes`-bearing rule**: a
SOCKS5 `CONNECT` is scope-checked before the tunnel carries a single byte, so the
proxy does not yet know whether TLS follows. Scope such traffic by `hostname` /
`ports`, or scope the tunneled protocol instead.

The tunneled protocol *is* scoped with a scheme: once a SOCKS5 or `CONNECT`
tunnel carries traffic, the connection-level host check runs on it again with
the scheme of the client-facing leg — including raw TCP that matches no known
protocol (`http` when it is cleartext, `https` when the proxy terminated TLS on
it) and every `tcp_forwards` entry, `protocol: raw` included.

Two live-data-path admission gates do not observe the transport: SOCKS5
(blank scheme) and the `CONNECT` admission gate (always `https`); the tunneled
traffic behind them is re-checked as described above.

For HTTP requests (including WebSocket / SSE upgrade requests and HTTP/2), the
proxy matches `schemes` against the transport of the client's connection — TLS or not — not
a client-declared HTTP/2 `:scheme` (which may be absent or disagree with the
connection) and not a `scheme` set via intercept `modify_and_forward`. The
recorded request still shows the scheme exactly as the client declared it.

### How a deny shows up on the wire

| Traffic | What the client sees | Recorded |
|---|---|---|
| HTTP/1.x, HTTP/2 request | `403` with `X-Blocked-By: target_scope` | Stream with `blocked_by: target_scope`, `state: error` |
| Raw TCP (bytechunk — CONNECT / SOCKS5 tunnels carrying an unknown protocol, `raw_passthrough_hosts`, `tcp_forwards` with `protocol: raw` or an `auto` fallback to raw) | The connection is closed (EOF) at the first byte the client sends; none of the client's bytes reach the denied host | One raw Stream with `blocked_by: target_scope`, `state: error` |
| WebSocket, gRPC message | The message is dropped; the connection stays open | Stream with `blocked_by: target_scope` |

A raw connection is closed rather than having single chunks dropped because a
byte stream has no message boundary to drop at: removing some bytes and relaying
the rest would hand the peer a corrupted stream. An upstream that speaks first
(an SMTP / FTP / IMAP banner) can still deliver its greeting before the client's
first byte is checked.

The check runs on the client's first byte, not at connect time, so the denied
host is still *contacted*: the upstream TCP connection is already open when
that byte is examined, and on `raw_passthrough_hosts`, an unrecognised-ALPN
tunnel or a `tcp_forwards` entry with `upstream_tls` the upstream TLS handshake
(SNI included) has already completed too. A CONNECT admitted as `https` and
then denied by an `http`-scheme rule on its inner plaintext, and every
`tcp_forwards` entry, are cases that reach the denied host this way; an
accept-time gate for `tcp_forwards` is tracked as USK-1161.

## Rate Limiting

Rate limits use the same two-layer architecture as target scope. The Policy Layer defines upper bounds (set via the policy file or config file; replaceable only by the operator's `SIGHUP` reload); the Agent Layer can set equal or stricter limits at runtime.

Requests that exceed rate limits receive a `429 Too Many Requests` response with an `X-Blocked-By: rate_limit` header.

**Applicability**: Both Policy Layer and Agent Layer rate limits apply to **all** proxy traffic -- transparent MITM traffic (HTTP CONNECT tunnel, plain HTTP forward proxy, SOCKS5 tunnel) and MCP tool-initiated requests (the same list as for `target_scope`). The effective rate (the stricter of policy and agent) is shared across both paths.

### `set_rate_limits`

Set Agent Layer rate limits. Omitted fields reset to 0 (no limit). This is full-replace semantics.

```json
{
  "action": "set_rate_limits",
  "params": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}
```

**Parameters:**
- **max_requests_per_second** (number, optional): Global rate limit in RPS. `0` means no global limit.
- **max_requests_per_host_per_second** (number, optional): Per-host rate limit in RPS. `0` means no per-host limit.

Returns: status, effective (merged Policy+Agent limits), agent (current Agent Layer values).

### `get_rate_limits`

Returns Policy and Agent Layer rate limits with the effective (merged) values.

```json
{
  "action": "get_rate_limits"
}
```

Response:

```json
{
  "policy": {
    "max_requests_per_second": 50,
    "max_requests_per_host_per_second": 20
  },
  "agent": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  },
  "effective": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}
```

## Diagnostic Budget

Diagnostic budgets limit the total number of requests and/or the session duration. When a budget is exhausted, the proxy automatically stops accepting new requests. Like rate limits, budgets use the two-layer architecture.

**Applicability**: Both Policy Layer and Agent Layer budgets apply to **all** proxy traffic -- transparent MITM traffic and MCP tool-initiated requests share the same request counter and duration timer. When the effective budget is exhausted, the proxy stops every listener regardless of how the next request would have arrived.

### `set_budget`

Set Agent Layer budget limits. Omitted fields reset to 0 (no limit). This is full-replace semantics.

```json
{
  "action": "set_budget",
  "params": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}
```

**Parameters:**
- **max_total_requests** (integer, optional): Maximum total requests for the session. `0` means no request count limit.
- **max_duration** (string, optional): Maximum session duration as a Go duration string (e.g. `"30m"`, `"1h"`, `"2h30m"`). `"0s"` means no duration limit.

Returns: status, effective (merged Policy+Agent limits), agent (current Agent Layer values).

### `get_budget`

Returns Policy and Agent Layer budgets with effective values and current usage.

```json
{
  "action": "get_budget"
}
```

Response:

```json
{
  "policy": {
    "max_total_requests": 5000,
    "max_duration": "2h"
  },
  "agent": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  },
  "effective": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  },
  "request_count": 142,
  "stop_reason": ""
}
```

- **request_count**: Number of requests made so far.
- **stop_reason**: Non-empty when the budget has been exhausted (e.g. `"max_total_requests exceeded"`, `"max_duration exceeded"`).

## SafetyFilter (Input Filter)

SafetyFilter is a **Policy Layer** mechanism that prevents destructive payloads from being sent to target systems. It inspects outgoing HTTP requests (body, URL, query string, headers) against a set of regex rules and blocks or logs matches before the request reaches the target.

SafetyFilter rules are **immutable at runtime** — they are defined in the configuration file and cannot be modified by AI agents. This ensures that safety boundaries remain enforced regardless of agent behavior.

**Applicability**: As a Policy Layer mechanism, the Input Filter applies to **all** proxy traffic -- transparent MITM traffic and MCP tool-initiated requests (see the [Applicability](#applicability) table under "Two-Layer Architecture").

### `get_safety_filter`

Returns the current SafetyFilter configuration and compiled rules (read-only).

```json
{
  "action": "get_safety_filter"
}
```

Response:

```json
{
  "enabled": true,
  "input_rules": [
    {
      "id": "destructive-sql:drop",
      "name": "DROP statement",
      "pattern": "(compiled regex)",
      "targets": ["body", "url", "query"],
      "action": "block",
      "category": "destructive-sql"
    }
  ],
  "immutable": true
}
```

- **enabled**: Whether SafetyFilter is active.
- **input_rules**: List of compiled input filter rules currently in effect.
- **immutable**: Always `true` — SafetyFilter rules cannot be changed at runtime.

### Rule Configuration

Rules are defined in the config file under `safety_filter.input`. Each rule can be a preset reference or a custom rule.

#### Presets

Built-in presets provide curated rule sets for common destructive patterns:

| Preset | Rules | Description |
|--------|-------|-------------|
| `destructive-sql` | 6 rules | DROP TABLE/DATABASE/INDEX/VIEW/SCHEMA, TRUNCATE TABLE, DELETE without WHERE, UPDATE WHERE 1=1, ALTER TABLE DROP, xp_ stored procedures |
| `destructive-os-command` | 5 rules | rm -rf, shutdown/reboot/halt/poweroff, mkfs, dd if=, Windows format |

#### Custom Rules

Custom rules require `id`, `pattern`, and `targets` fields. The action is inherited from the section-level `input.action` setting:

```json
{
  "id": "custom-api",
  "name": "Dangerous API endpoint",
  "pattern": "(?i)/api/v[0-9]+/(delete-all|reset)",
  "targets": ["url"]
}
```

### Targets

| Target | Description |
|--------|-------------|
| `body` | Request body content |
| `url` | Full URL string |
| `query` | Query string portion of the URL |
| `header` | Individual header values (use `header:Name` for a specific header) |
| `headers` | All header values concatenated |

### Actions

| Action | Description |
|--------|-------------|
| `block` | Reject the request with 403 status. The response includes `X-Block-Reason: safety_filter` header and a JSON body with violation details |
| `log_only` | Log the match but allow the request through. Useful for testing rules before enforcement |

### Blocked Response Format

When SafetyFilter blocks a request at the proxy layer:

- **Status**: `403 Forbidden`
- **Header**: `X-Block-Reason: safety_filter`
- **Body**: JSON object with violation details (rule ID, rule name, and match location)

For a native gRPC call the RPC fails with `grpc-status: 7` (PERMISSION_DENIED) and `grpc-message: blocked by safety_filter`; the matched rule IDs travel comma-separated in the `x-yorishiro-matched-rules` trailer (bytes outside visible ASCII, `%`, and `,` inside an ID are percent-encoded). A blocked message in a bidi/client stream ends the whole RPC. gRPC-Web messages are dropped without a status.

When SafetyFilter blocks an MCP tool operation (resend, fuzz, intercept modify_and_forward, macro):

- **MCP error response** with violation details

## SafetyFilter (Output Filter)

The Output Filter is a **Policy Layer** mechanism that prevents sensitive information (PII) from being exposed to AI agents. It inspects outgoing HTTP response bodies and headers against a set of regex rules and masks matching content before returning data to the AI agent.

Raw data is always preserved in the Flow Store -- masking is applied only when data is returned to AI agents (via MCP tools or proxy responses).

Output Filter rules are **immutable at runtime** -- they are defined in the configuration file and cannot be modified by AI agents.

**Applicability**: As a Policy Layer mechanism, the Output Filter applies to **all** proxy traffic returning data to AI agents -- masking is performed both in the live pipeline (responses returned to the proxied client) and in MCP tool responses (query results, resend responses, fuzz results, intercept queue entries, compare diffs, export data).

### How It Works

1. **Proxy Layer**: Response body and headers are masked before returning to the client (HTTP/1.x, HTTPS CONNECT, HTTP/2)
2. **MCP Tool Layer**: Query results, resend responses, fuzz results, intercept queue entries, compare diffs, and export data are masked before returning to the AI agent
3. **Raw Data Preserved**: The Flow Store always contains the original unmasked data for human review via the Web UI

### Output Rule Configuration

Output rules are defined in the config file under `safety_filter.output`. Each rule can be a preset reference or a custom rule.

#### PII Presets

Built-in presets provide curated rule sets for common PII patterns:

| Preset | Rules | Description |
|--------|-------|-------------|
| `credit-card` | 2 rules | Credit card numbers -- separated (1234-5678-9012-3456) and continuous (1234567890123456). Luhn validation is applied to the continuous format only |
| `japan-my-number` | 1 rule | Japanese My Number (12-digit individual number) with check digit validation |
| `email` | 1 rule | Email addresses (user@example.com) |
| `japan-phone` | 2 rules | Japanese phone numbers -- mobile (090-1234-5678) and landline (03-1234-5678) |

#### Validators

Some presets use **Validator** functions for additional verification beyond regex matching, reducing false positives:

- **credit-card (continuous)**: Luhn algorithm check -- only masks digit sequences that pass the Luhn checksum
- **japan-my-number**: Check digit validation -- only masks 12-digit sequences with a valid My Number check digit

Rules with Validators use a **slow path** (individual match validation) instead of the **fast path** (bulk `ReplaceAll`), but provide significantly better precision.

#### Custom Output Rules

Custom rules require `id`, `pattern`, and `targets` fields. The `action` and `replacement` fields are available via the programmatic API (`safety.Config`). In config files, the section-level `action` applies to all rules within that section (config file support is coming soon).

```json
{
  "id": "custom-api-key",
  "name": "API key pattern",
  "pattern": "(sk-[a-zA-Z0-9]{32,})",
  "targets": ["body"],
  "action": "mask",
  "replacement": "[MASKED:api_key]"
}
```

### Output Filter Actions

| Action | Description |
|--------|-------------|
| `mask` | Replace matched content with the replacement string. This is the primary action for output rules |
| `log_only` | Log the match but return data unmodified. Useful for testing rules before enforcement |

### Replacement Strings

Replacement strings support regex capture group references:

| Syntax | Description |
|--------|-------------|
| `[MASKED:credit_card]` | Static replacement (used by credit-card preset) |
| `$1` | First capture group from the regex pattern |
| `$2` | Second capture group |
| `${name}` | Named capture group |

### Output Filter Targets

Output rules typically use `body` as the target. Header-level masking is also supported:

| Target | Description |
|--------|-------------|
| `body` | Response body content |
| `header` | Individual header values (use `header:Name` for a specific header) |
| `headers` | All header values |

## Protocol Support Matrix

| Protocol | Input Filter | Output Filter | Notes |
|----------|-------------|---------------|-------|
| HTTP/1.x | Supported | Supported | Full support |
| HTTP/2 | Supported | Supported | Full support |
| gRPC | Supported | Supported | Via HTTP/2 |
| WebSocket | Supported (text only) | Supported (text only) | Binary frames not covered; fragment bypass possible |
| SOCKS5 | N/A | N/A | Transport layer only (filters apply after HTTP delegation) |
| Raw TCP | N/A | N/A | Binary stream |

## WebSocket Safety Filter

SafetyFilter is applied to WebSocket traffic on a per-frame basis. Only **text frames** (opcode 0x1) are inspected; binary frames and control frames are passed through without filtering.

- **Send direction (Input Filter)**: `CheckInput` inspects the text frame payload and the upgrade request URL. If a rule matches with `block` action, the frame is silently dropped (not forwarded) and the connection remains open for subsequent frames. If the blocked frame is non-FIN (start of a fragmented message), subsequent continuation frames belonging to that message are also dropped.
- **Receive direction (Output Filter)**: `FilterOutput` inspects the text frame payload and masks matching content. The original unmasked payload is preserved in the Flow Store.

### Applicable Rule Targets

WebSocket frames do not carry HTTP headers. The applicable rule targets differ between Input Filter and Output Filter:

| Target | Input Filter | Output Filter | Reason |
|--------|-------------|---------------|--------|
| `body` | Yes | Yes | Matches against the text frame payload |
| `url` | Yes (upgrade URL) | No | Input Filter receives the upgrade request URL; Output Filter has no URL context |
| `query` | Yes (upgrade URL) | No | Input Filter can match the query string of the upgrade request URL |
| `header` / `headers` | No | No | WebSocket frames have no HTTP headers |

### Known Limitations

1. **Binary frames not covered**: Binary frames (opcode 0x2) are not inspected by either Input Filter or Output Filter. Regex-based pattern matching is not meaningful for binary data.
2. **Fragment bypass**: Filters are applied per-frame, not per-message. Only text frames (opcode 0x1) are inspected; continuation frames (opcode 0x0) are not inspected by the safety filter even if the entire pattern is contained within a single continuation frame. Additionally, if a fragmented message splits a pattern across frame boundaries (e.g., `DROP` in one frame and ` TABLE` in the next), the pattern will not be detected.
3. **No header matching**: WebSocket data frames lack HTTP headers, so rules targeting `header` or `headers` have no effect. However, `url` and `query` rules are effective for the Input Filter because `CheckInput` receives the upgrade request URL.

## Error Handling

- **Policy boundary violation**: Setting agent allows outside policy scope returns an error with the offending hostname and current policy allows.
- **Policy deny removal**: Attempting to remove a policy deny rule via `update_target_scope` returns an error stating that policy rules are immutable.
- **Rate limit boundary violation**: Agent rate limits cannot exceed Policy rate limits. If the policy sets 50 RPS, the agent cannot set 100 RPS.
- **Budget boundary violation**: Agent budget limits cannot exceed Policy budget limits.
- **Enforcement mode**: `"open"` when no rules exist in either layer; `"enforcing"` when any rule is configured.
