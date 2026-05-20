# Audit Authentication and Authorization

Audit a recorded HTTP flow for authentication-bypass and authorization (privilege-escalation / role-downgrade) weaknesses.

## Inputs

- `target_flow_id`: recorded `flow_id` of a privileged or authenticated request. Required.
- `auth_header_name`: header that carries the credential (typically `Authorization`, or `Cookie` for session-based auth). Required.
- `low_priv_token`: a token / cookie value for a lower-privilege user, when testing role downgrade. Optional.

If any required field is empty, ask the user.

## Plan

### 1. Inspect the flow and locate the auth header index

```json
// query
{"resource": "flow", "id": "{{target_flow_id}}"}
```

Find `{{auth_header_name}}` in the `headers[]` array (case-insensitive compare) and note its index `N`. The typed `fuzz_http` path requires a numeric index.

### 2. Authentication bypass — empty / forged / wrong-scheme tokens

```json
// fuzz_http — substitute N with the index from step 1
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "headers[N].value",
      "payloads": [
        "",
        "Bearer ",
        "Bearer invalid",
        "Bearer null",
        "Bearer undefined",
        "Basic YWRtaW46YWRtaW4=",
        "Basic Og=="
      ]
    }
  ],
  "tag": "auth-bypass"
}
```

Also test the "no header at all" case via `resend_http` (rebuild `headers` minus the slot).

### 3. Authorization (privilege escalation) — admin endpoint with low-privilege token

If `{{low_priv_token}}` is provided, replace the credential with it on a recorded admin endpoint:

```json
// resend_http
{
  "flow_id": "{{target_flow_id}}",
  "headers": [
    {"name": "{{auth_header_name}}", "value": "Bearer {{low_priv_token}}"}
  ],
  "tag": "authz-low-priv"
}
```

Use the recorded full `headers` array as the base — copy every other header from the captured flow and overwrite only `{{auth_header_name}}`.

### 4. Role downgrade matrix — same endpoint, different roles

When you have tokens for several roles, sweep them:

```json
// fuzz_http — substitute N with the index from step 1
{
  "flow_id": "{{target_flow_id}}",
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

Substitute the real tokens before issuing the call.

### 5. Analyse results

```json
// query
{
  "resource": "fuzz_results",
  "fuzz_id": "<fuzz-id>",
  "filter": {"status_code": 200},
  "fields": ["index", "payloads", "status_code", "response_length"]
}
```

## Evaluation

- Endpoint returns 200 with empty / invalid token → authentication bypass. Severity = full impact of the endpoint.
- Endpoint returns 200 for a strictly-lower-privilege role → authorization (privilege-escalation) flaw.
- 401 / 403 for all bad tokens → access control is enforced for the tested vector.

## Reporting

Document: the credential vector tested, which payloads (or which role tokens) the endpoint accepted, and the resulting `flow_id`s. Suggested remediation: server-side authorisation policy at the resource boundary, not at the route boundary.
