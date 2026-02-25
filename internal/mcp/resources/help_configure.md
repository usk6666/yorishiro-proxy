# configure

Configure runtime proxy settings including capture scope and TLS passthrough. Supports incremental (merge) and full replacement (replace) operations.

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

### Combined update
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com", "url_prefix": "/v2/"}]
  },
  "tls_passthrough": {
    "add": ["pinned.service.com"]
  }
}
```
