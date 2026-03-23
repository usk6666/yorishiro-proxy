# Non-Destructive Attack Payload Patterns

Non-destructive and identifiable payloads by vulnerability type.
These do not destroy test environment data and allow success/failure determination from the response.

## Safe Payload Selection Principles

### Basic Rules

- **SQL that modifies data is prohibited**: Do not send payloads containing `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, or `TRUNCATE`
- **Condition modification (`OR 1=1`, etc.) is only permitted on SELECT-type requests**: Limit to GET method reference APIs
- **For methods with side effects (POST/PUT/PATCH/DELETE), use only time-based or error-based payloads**: These can determine vulnerability presence without modifying data

### Prohibited Payload List

The following payloads are **prohibited under any circumstances**:

| Payload | Reason |
|---------|--------|
| `DROP TABLE ...` | Drops a table |
| `DELETE FROM ...` | Deletes all data |
| `UPDATE ... SET ...` | Tampers with data |
| `INSERT INTO ...` | Inserts unauthorized data |
| `ALTER TABLE ...` | Modifies schema |
| `TRUNCATE TABLE ...` | Clears entire table |
| Stacked queries using `;` | Risk of arbitrary SQL execution |

### Prohibited Actions by HTTP Method

| HTTP Method | Prohibited Payloads |
|-------------|-------------------|
| DELETE | `OR 1=1`, `OR ''=''`, `OR true` (WHERE clause always true → mass delete) |
| PUT / PATCH | `OR 1=1`, `OR ''=''`, `OR true` (risk of mass update) |
| POST (create) | `OR 1=1`, `OR ''=''`, `OR true`, UNION SELECT |

**When in doubt, use time-based blind SQLi.** It can be safely used with any HTTP method.

## IDOR (Insecure Direct Object Reference)

### Strategy

Replace with another user's ID and determine success/failure from status code and response differences.

### Payload Position

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.user_id",
      "payload_set": "user-ids"
    }
  ],
  "payload_sets": {
    "user-ids": {
      "type": "range",
      "start": 1,
      "end": 20
    }
  }
}
```

For PATH parameters:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "path",
      "match": "/users/(\\d+)",
      "payload_set": "user-ids"
    }
  ],
  "payload_sets": {
    "user-ids": {"type": "range", "start": 1, "end": 20}
  }
}
```

### Evaluation

- Another user's ID returns 200 + data → IDOR vulnerability present
- 403/404 → Access control is properly enforced
- Sort fuzz_results by `status_code` and check payloads that returned 200

## SQL Injection (Time-based Blind)

### Strategy

Use SLEEP-based payloads to observe differences in duration_ms.

### Payloads

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.search",
      "payload_set": "sqli"
    }
  ],
  "payload_sets": {
    "sqli": {
      "type": "wordlist",
      "values": [
        "normalvalue",
        "' OR SLEEP(3)-- ",
        "' OR SLEEP(3)#",
        "1 OR SLEEP(3)",
        "1; WAITFOR DELAY '0:0:3'--",
        "1' AND (SELECT SLEEP(3))-- ",
        "1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)"
      ]
    }
  }
}
```

### Evaluation

- Record `normalvalue` duration_ms as baseline
- SLEEP payloads increase duration_ms by ~3000ms → SQLi vulnerability present
- Check fuzz_results with `sort_by: "duration_ms"`
- To configure automatic stop with `stop_on`:

```json
{
  "stop_on": {
    "latency_threshold_ms": 5000,
    "latency_baseline_multiplier": 3.0,
    "latency_window": 5
  }
}
```

## SQL Injection (Error-based)

### Strategy

Trigger SQL syntax errors and detect vulnerability from the presence of error messages or status code changes.
No data is modified whatsoever, so **this is safe to use on methods with side effects (POST/PUT/PATCH/DELETE)**.

### Payloads

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.search",
      "payload_set": "sqli-error"
    }
  ],
  "payload_sets": {
    "sqli-error": {
      "type": "wordlist",
      "values": [
        "normalvalue",
        "'",
        "''",
        "'\"",
        "1'",
        "1 AND 'a'='b",
        "1' AND 'a'='b",
        "1\" AND \"a\"=\"b"
      ]
    }
  }
}
```

### Evaluation

- Record the `normalvalue` response as baseline
- Single quote (`'`) changes status code to 500, or error message (e.g., `SQL syntax`, `ORA-`, `SQLSTATE`) appears in response → SQLi vulnerability present
- No difference in status code or response body → SQLi unlikely

## SQL Injection (UNION-based)

### Strategy

Retrieve information using UNION SELECT. Identify the number of columns and verify if information can be extracted.

**Usage restriction**: Only use on GET/read-only endpoints; do not use on POST/PUT/PATCH/DELETE or any other state-changing operations.

### Payloads

**Step 1: Identify Column Count (ORDER BY)**

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "id",
      "payload_set": "orderby"
    }
  ],
  "payload_sets": {
    "orderby": {
      "type": "wordlist",
      "values": [
        "1 ORDER BY 1-- ",
        "1 ORDER BY 2-- ",
        "1 ORDER BY 3-- ",
        "1 ORDER BY 5-- ",
        "1 ORDER BY 10-- ",
        "1 ORDER BY 20-- "
      ]
    }
  }
}
```

**Step 2: UNION SELECT (after confirming column count)**

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "id",
      "payload_set": "union"
    }
  ],
  "payload_sets": {
    "union": {
      "type": "wordlist",
      "values": [
        "1 UNION SELECT NULL,NULL,NULL-- ",
        "0 UNION SELECT NULL,NULL,NULL-- "
      ]
    }
  }
}
```

### Evaluation

- The boundary where ORDER BY N transitions from 200 → 500 = column count
- UNION SELECT NULL,... returns NULL or extra rows in the response → UNION SQLi vulnerability present
- All return errors → UNION SQLi unlikely (re-verify with time-based)

## XSS (Reflected Cross-Site Scripting)

### Strategy

Send harmless marker-tagged payloads and check whether escaping occurs in the response body.

### Payloads

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "q",
      "payload_set": "xss"
    }
  ],
  "payload_sets": {
    "xss": {
      "type": "wordlist",
      "values": [
        "YP_NORMAL_TEXT",
        "<YP_TAG>test</YP_TAG>",
        "<img src=x onerror=YP_XSS>",
        "'\"><YP_TAG>",
        "javascript:YP_XSS",
        "<svg/onload=YP_XSS>",
        "{{YP_TEMPLATE}}",
        "§YP_TEMPLATE§"
      ]
    }
  }
}
```

**Note**: The `YP_` prefix is an identification marker for YoriShiro-Proxy testing.
No actual script execution occurs. `§YP_TEMPLATE§` is a payload for detecting
macro KVS template syntax injection. The fuzzer engine does not apply template expansion
to payload values, so it is sent as a literal string.

### Evaluation

- Filter fuzz_results with `body_contains: "<YP_TAG>"`
- Response contains `<YP_TAG>` as-is → Not escaped (XSS vulnerability present)
- Converted to `&lt;YP_TAG&gt;` → Properly escaped
- Review response body in session details and analyze the context

## CSRF (Cross-Site Request Forgery)

### Strategy

Replace/empty/substitute another session's CSRF token to verify request acceptance.

### Payloads

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "X-CSRF-Token",
      "payload_set": "csrf-tokens"
    }
  ],
  "payload_sets": {
    "csrf-tokens": {
      "type": "wordlist",
      "values": [
        "",
        "invalid-token-value",
        "00000000-0000-0000-0000-000000000000"
      ]
    }
  }
}
```

Test by removing the header entirely:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "X-CSRF-Token",
      "mode": "remove",
      "payload_set": "unused"
    }
  ]
}
```

### Evaluation

- Request succeeds (200/302) with invalid/empty/removed token → No CSRF protection
- 403/400 → CSRF protection is functioning
- Test cookie-based CSRF tokens similarly (location: `cookie`)

## Authentication & Authorization Testing

### Authentication Bypass

Manipulate the Authorization header:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "Authorization",
      "payload_set": "auth-bypass"
    }
  ],
  "payload_sets": {
    "auth-bypass": {
      "type": "wordlist",
      "values": [
        "",
        "Bearer ",
        "Bearer invalid",
        "Bearer null",
        "Basic YWRtaW46YWRtaW4="
      ]
    }
  }
}
```

### Authorization (Privilege Escalation) Testing

Access admin APIs with a low-privilege user's token:

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<admin-api-flow-id>",
    "override_headers": {
      "Authorization": "Bearer <low-privilege-user-token>"
    },
    "tag": "authz-test-low-priv"
  }
}
```

### Role Downgrade Testing (fuzz)

Test the same API with tokens from multiple roles:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "Authorization",
      "match": "Bearer (.*)",
      "payload_set": "role-tokens"
    }
  ],
  "payload_sets": {
    "role-tokens": {
      "type": "wordlist",
      "values": [
        "<admin-token>",
        "<editor-token>",
        "<viewer-token>",
        "<guest-token>"
      ]
    }
  }
}
```

### Evaluation

- Low-privilege/unauthenticated access to admin API returns 200 → Auth/authz bypass
- 401/403 → Properly protected
- Sort fuzz_results by `status_code` and check results returning 200

## Payload Position (location) Reference

| location | Use Case | Required Parameters |
|----------|----------|---------------------|
| `header` | Replace HTTP header value | `name` (header name) |
| `query` | Replace query parameter | `name` (parameter name) |
| `body_json` | Replace JSON body value | `json_path` (JSONPath) |
| `body_regex` | Replace regex-matched part of body | `match` (regex) |
| `path` | Replace part of URL path | `match` (regex) |
| `cookie` | Replace Cookie value | `name` (Cookie name) |

## mode Options

| mode | Behavior |
|------|----------|
| `replace` | Replace existing value with payload (default) |
| `add` | Append payload |
| `remove` | Delete the parameter itself |
