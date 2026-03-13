# security tool

Configure runtime security settings including target scope rules.

This tool is separate from `configure` to allow MCP clients to apply different approval policies (e.g., manual approval for security changes).

## Two-Layer Architecture

Target scope uses a **Policy Layer** and an **Agent Layer**:

- **Policy Layer** (immutable): Set at startup from the configuration file. Defines the upper boundary for what the agent can access. Cannot be modified at runtime.
- **Agent Layer** (mutable): Controlled by this tool. Can further restrict access within the Policy Layer boundaries. Agent allow rules must fall within the Policy allow scope.

### Evaluation Order

1. **Policy denies** -- always block (highest priority)
2. **Agent denies** -- block
3. **Policy allows** (if any) -- target must match at least one, otherwise block
4. **Agent allows** (if any) -- target must match at least one, otherwise block
5. All checks passed -- allow

When neither layer has rules, all targets are permitted (open mode).

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
    "source": "config file",
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
| `hostname` | string | Required. Exact match or wildcard `*.example.com` |
| `ports` | int[] | Optional. Match specific ports. Empty = all ports |
| `path_prefix` | string | Optional. Match URL path prefix. Empty = all paths |
| `schemes` | string[] | Optional. Match URL schemes (http, https). Empty = all schemes |

All specified fields must match for a rule to apply (AND logic).

## Rate Limiting

Rate limits use the same two-layer architecture as target scope. The Policy Layer defines upper bounds (set via config file); the Agent Layer can set equal or stricter limits at runtime.

Requests that exceed rate limits receive a `429 Too Many Requests` response with an `X-Blocked-By: rate_limit` header.

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

When SafetyFilter blocks an MCP tool operation (resend, fuzz, intercept modify_and_forward, macro):

- **MCP error response** with violation details

## SafetyFilter (Output Filter)

The Output Filter is a **Policy Layer** mechanism that prevents sensitive information (PII) from being exposed to AI agents. It inspects outgoing HTTP response bodies and headers against a set of regex rules and masks matching content before returning data to the AI agent.

Raw data is always preserved in the Flow Store -- masking is applied only when data is returned to AI agents (via MCP tools or proxy responses).

Output Filter rules are **immutable at runtime** -- they are defined in the configuration file and cannot be modified by AI agents.

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
| `credit-card` | 2 rules | Credit card numbers -- separated (1234-5678-9012-3456) and continuous (1234567890123456) with Luhn validation |
| `japan-my-number` | 1 rule | Japanese My Number (12-digit individual number) with check digit validation |
| `email` | 1 rule | Email addresses (user@example.com) |
| `japan-phone` | 2 rules | Japanese phone numbers -- mobile (090-1234-5678) and landline (03-1234-5678) |

#### Validators

Some presets use **Validator** functions for additional verification beyond regex matching, reducing false positives:

- **credit-card (continuous)**: Luhn algorithm check -- only masks digit sequences that pass the Luhn checksum
- **japan-my-number**: Check digit validation -- only masks 12-digit sequences with a valid My Number check digit

Rules with Validators use a **slow path** (individual match validation) instead of the **fast path** (bulk `ReplaceAll`), but provide significantly better precision.

#### Custom Output Rules

Custom rules require `id`, `pattern`, `targets`, and `action` fields:

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

## Error Handling

- **Policy boundary violation**: Setting agent allows outside policy scope returns an error with the offending hostname and current policy allows.
- **Policy deny removal**: Attempting to remove a policy deny rule via `update_target_scope` returns an error stating that policy rules are immutable.
- **Rate limit boundary violation**: Agent rate limits cannot exceed Policy rate limits. If the policy sets 50 RPS, the agent cannot set 100 RPS.
- **Budget boundary violation**: Agent budget limits cannot exceed Policy budget limits.
- **Enforcement mode**: `"open"` when no rules exist in either layer; `"enforcing"` when any rule is configured.
