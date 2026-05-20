# Stateful-Fuzz Loop with Macros (per-iteration setup / teardown)

Drive a setup → test → teardown loop around a stateful endpoint that cannot be safely fuzzed in bulk. Use this when each iteration needs its own server-side state — repeated DELETEs, single-use tokens, fresh CSRF tokens, session-limited APIs.

The typed fuzz tools (`fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw`) deliberately do **not** embed per-iteration hooks. You drive the loop yourself.

## Inputs

- `setup_macro_name`: name to give the setup macro (e.g. `setup-item`). Required.
- `teardown_macro_name`: name to give the teardown macro (e.g. `teardown`). Required.
- `target_flow_id`: recorded `flow_id` of the stateful endpoint under test. Required.

If any required field is empty, ask the user.

## Why this pattern is needed

- Repeated DELETE requests return 404 after the first successful deletion.
- CSRF tokens may rotate per request.
- Concurrent-session limits / rate limits force a logout between iterations.

## Plan

### 1. Capture the supporting requests

Using the `capture-traffic` playbook, record:
- Login request.
- CSRF token retrieval page (if applicable).
- Test resource creation request.
- The target endpoint (DELETE / single-use / rotating-token request).
- Logout request.

Note each `flow_id`. Pass them into the macro step definitions below.

### 2. Define the setup macro

The setup macro performs: login → CSRF token retrieval → test resource creation. Run it before each main request.

```json
// macro
{
  "action": "define_macro",
  "params": {
    "name": "{{setup_macro_name}}",
    "description": "Login, get CSRF token, create test item",
    "steps": [
      {
        "id": "login",
        "flow_id": "<login-flow-id>",
        "override_body": "username=testuser&password=testpass",
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1
          }
        ]
      },
      {
        "id": "get-csrf",
        "flow_id": "<csrf-page-flow-id>",
        "override_headers": {"Cookie": "PHPSESSID=§session_cookie§"},
        "extract": [
          {
            "name": "csrf_token",
            "from": "response",
            "source": "body",
            "regex": "name=\"csrf\" value=\"([^\"]+)\"",
            "group": 1
          }
        ]
      },
      {
        "id": "create-item",
        "flow_id": "<create-item-flow-id>",
        "override_headers": {
          "Cookie": "PHPSESSID=§session_cookie§",
          "X-CSRF-Token": "§csrf_token§"
        },
        "override_body": "{\"name\": \"test-item-for-delete\"}",
        "extract": [
          {
            "name": "item_id",
            "from": "response",
            "source": "body_json",
            "json_path": "$.id"
          }
        ]
      }
    ]
  }
}
```

### 3. Define the teardown macro

```json
// macro
{
  "action": "define_macro",
  "params": {
    "name": "{{teardown_macro_name}}",
    "description": "Logout after test",
    "steps": [
      {
        "id": "logout",
        "flow_id": "<logout-flow-id>",
        "override_headers": {"Cookie": "PHPSESSID=§session_cookie§"}
      }
    ]
  }
}
```

### 4. Drive the per-iteration loop

For each payload variant, run **all three** of these in order. Do not parallelise — server-side state is shared.

#### 4a. Setup

```json
// macro
{
  "action": "run_macro",
  "params": {"name": "{{setup_macro_name}}"}
}
```

Read `kv_store.item_id` (and any other extracted values) from the response.

#### 4b. Single-shot test

```json
// resend_http
{
  "flow_id": "{{target_flow_id}}",
  "body_patches": [{"json_path": "$.id", "value": "<item_id-from-setup>"}],
  "tag": "stateful-iter-<N>"
}
```

Substitute the captured `item_id` (or whatever per-iteration value the setup produced) into the request body, path, or headers as appropriate. For path substitution, use `override_path`; for header substitution, set the full `headers[]` array.

#### 4c. Teardown

```json
// macro
{
  "action": "run_macro",
  "params": {"name": "{{teardown_macro_name}}"}
}
```

### 5. Optimisation

For sweeps where the server can hold state across iterations (read-only permission matrix, role downgrade), you can use a single shared setup before the loop and run `fuzz_http` once. Only fall back to per-iteration setup/teardown when each call destroys / consumes server state.

### 6. Cleanup

After testing is complete:

```json
// macro
{"action": "delete_macro", "params": {"name": "{{setup_macro_name}}"}}
```

```json
// macro
{"action": "delete_macro", "params": {"name": "{{teardown_macro_name}}"}}
```

## KV Store rules

- Within one `run_macro` invocation, earlier steps' extracted KV pairs are available to later steps via `§var_name§` template expansion.
- KV Store is reset between top-level `run_macro` invocations.
- To carry state across macro invocations, read the returned `kv_store` and feed it into the next call's `initial_vars`.
