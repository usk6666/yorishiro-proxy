# configure

Configure runtime proxy settings including capture scope, TLS passthrough, and intercept rules. Supports incremental (merge) and full replacement (replace) operations.

## Parameters

### operation (string, optional)
How the configuration should be applied.
- `"merge"` (default): Apply incremental add/remove changes to existing config.
- `"replace"`: Replace entire configuration sections with new values.

### capture_scope (object, optional)
Controls which requests are recorded. Only specified sections are modified.

**Merge operation fields:**
- **add_includes** (array of scope rules): Rules to add to the include list.
- **remove_includes** (array of scope rules): Rules to remove from the include list.
- **add_excludes** (array of scope rules): Rules to add to the exclude list.
- **remove_excludes** (array of scope rules): Rules to remove from the exclude list.

**Replace operation fields:**
- **includes** (array of scope rules): Full replacement of include rules.
- **excludes** (array of scope rules): Full replacement of exclude rules.

Each scope rule has:
- **hostname** (string): Hostname pattern (e.g. `"example.com"`, `"*.example.com"`).
- **url_prefix** (string): URL path prefix (e.g. `"/api/"`).
- **method** (string): HTTP method (e.g. `"GET"`, `"POST"`).

At least one field must be set per rule.

### tls_passthrough (object, optional)
Controls which domains bypass TLS interception.

**Merge operation fields:**
- **add** (array of strings): Patterns to add (e.g. `["*.googleapis.com"]`).
- **remove** (array of strings): Patterns to remove.

**Replace operation fields:**
- **patterns** (array of strings): Full replacement of all passthrough patterns.

## Usage Examples

### Add scope rules (merge)
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com"}],
    "add_excludes": [{"hostname": "static.target.com"}]
  }
}
```

### Remove scope rules (merge)
```json
{
  "capture_scope": {
    "remove_includes": [{"hostname": "old.target.com"}]
  }
}
```

### Replace all scope rules
```json
{
  "operation": "replace",
  "capture_scope": {
    "includes": [{"hostname": "new-target.com"}],
    "excludes": []
  }
}
```

### Add TLS passthrough patterns
```json
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "accounts.google.com"]
  }
}
```

### Replace all TLS passthrough patterns
```json
{
  "operation": "replace",
  "tls_passthrough": {
    "patterns": ["*.googleapis.com"]
  }
}
```

### intercept_rules (object, optional)
Configures intercept rules for matching requests/responses.

**Merge operation fields:**
- **add** (array of intercept rules): Rules to add.
- **remove** (array of strings): Rule IDs to remove.
- **enable** (array of strings): Rule IDs to enable.
- **disable** (array of strings): Rule IDs to disable.

**Replace operation fields:**
- **rules** (array of intercept rules): Full replacement of all intercept rules.

Each intercept rule has:
- **id** (string): Unique rule identifier.
- **enabled** (boolean): Whether the rule is active.
- **direction** (string): `"request"`, `"response"`, or `"both"`.
- **conditions** (object): Matching criteria:
  - **host_pattern** (string): Regex for hostname matching (port excluded).
  - **path_pattern** (string): Regex for URL path matching.
  - **methods** (array of strings): HTTP method whitelist.
  - **header_match** (object): Header name to regex mapping (AND logic).

## Usage Examples

### Add scope rules (merge)
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com"}],
    "add_excludes": [{"hostname": "static.target.com"}]
  }
}
```

### Remove scope rules (merge)
```json
{
  "capture_scope": {
    "remove_includes": [{"hostname": "old.target.com"}]
  }
}
```

### Replace all scope rules
```json
{
  "operation": "replace",
  "capture_scope": {
    "includes": [{"hostname": "new-target.com"}],
    "excludes": []
  }
}
```

### Add TLS passthrough patterns
```json
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "accounts.google.com"]
  }
}
```

### Replace all TLS passthrough patterns
```json
{
  "operation": "replace",
  "tls_passthrough": {
    "patterns": ["*.googleapis.com"]
  }
}
```

### Add intercept rules (merge)
```json
{
  "intercept_rules": {
    "add": [
      {
        "id": "target-host",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "host_pattern": "httpbin\\.org"
        }
      },
      {
        "id": "admin-api",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "host_pattern": "api\\.target\\.com",
          "path_pattern": "/api/admin.*",
          "methods": ["POST", "PUT", "DELETE"],
          "header_match": {"Content-Type": "application/json"}
        }
      }
    ]
  }
}
```

### Disable/enable intercept rules (merge)
```json
{
  "intercept_rules": {
    "disable": ["admin-api"],
    "enable": ["other-rule"]
  }
}
```

### Remove intercept rules (merge)
```json
{
  "intercept_rules": {
    "remove": ["admin-api"]
  }
}
```

### Replace all intercept rules
```json
{
  "operation": "replace",
  "intercept_rules": {
    "rules": [
      {
        "id": "new-rule",
        "enabled": true,
        "direction": "both",
        "conditions": {
          "path_pattern": "/api/.*"
        }
      }
    ]
  }
}
```

### Combined update
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com", "url_prefix": "/v2/"}]
  },
  "tls_passthrough": {
    "add": ["pinned.service.com"]
  },
  "intercept_rules": {
    "add": [
      {
        "id": "json-api",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "header_match": {"Content-Type": "application/json"}
        }
      }
    ]
  }
}
```
