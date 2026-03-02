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

## Error Handling

- **Policy boundary violation**: Setting agent allows outside policy scope returns an error with the offending hostname and current policy allows.
- **Policy deny removal**: Attempting to remove a policy deny rule via `update_target_scope` returns an error stating that policy rules are immutable.
- **Enforcement mode**: `"open"` when no rules exist in either layer; `"enforcing"` when any rule is configured.
