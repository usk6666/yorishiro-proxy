# Self-Contained Iteration Pattern

A self-contained iteration pattern using a Macro to perform precondition setup before each main test invocation.
This pattern is used when fuzzing stateful APIs — repeated DELETE / PUT / single-use-token endpoints — where each iteration must own its own server-side state.

The typed fuzz tools (`fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw`) do not embed per-iteration `pre_send` / `post_receive` hooks. Instead, drive the loop yourself: for each payload, call `run_macro` to set up, then call `resend_http` (or the matching typed resend) with the per-iteration values, then call `run_macro` to tear down.

## Core Principles

1. **Each iteration completes "precondition setup → test execution → teardown" independently**
2. The Macro KV Store is fresh per macro invocation by default; carry state forward by extracting it from the macro result and passing it into the next call
3. Server-side state is shared, so account for side effects from previous iterations

## Why This Pattern Is Needed

- Repeated DELETE requests may return 404 after the first successful deletion, so a new resource is needed each time
- CSRF tokens may need to be refreshed per request
- Logout may be needed to avoid concurrent session limits or rate limits

## Implementation Steps

### Step 1: Capture Required Requests with playwright-capture

Perform the following operations in the browser and record the flow ID for each request:

- Login request
- CSRF token retrieval page
- Target API under test (e.g., item creation, item deletion)
- Logout request

### Step 2: Define the setup Macro

The setup macro performs: login → CSRF token retrieval → test resource creation. Run it before each main request to obtain fresh state.

```json
// macro
{
  "action": "define_macro",
  "params": {
    "name": "setup-item",
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

### Step 3: Define the teardown Macro

The teardown macro runs after each main request response. To carry over state captured in the setup macro (session_cookie, etc.), read the prior `run_macro` response's `kv_store` and pass the values via `initial_vars`.

```json
// macro
{
  "action": "define_macro",
  "params": {
    "name": "teardown",
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

### Step 4: Drive the Per-Iteration Setup → Test → Teardown Loop

The typed fuzz tools do not own per-iteration macro hooks — drive the loop yourself. For each payload variant, run:

1. `macro` `run_macro` for the `setup-item` macro to create a fresh test resource and capture the extracted `item_id` from the response.
2. `resend_http` against the target endpoint, substituting the captured `item_id` into the request body (or path / headers as appropriate).
3. `macro` `run_macro` for the `teardown` macro to log out / release state.

Example iteration (repeat once per payload variant):

```json
// macro — setup
{
  "action": "run_macro",
  "params": {"name": "setup-item"}
}
```

Read the `kv_store.item_id` from the response, then:

```json
// resend_http — exercise the DELETE endpoint with the just-created resource id
{
  "flow_id": "<delete-endpoint-flow-id>",
  "body_patches": [{"json_path": "$.id", "value": "<item_id-from-setup>"}],
  "tag": "delete-test"
}
```

```json
// macro — teardown
{
  "action": "run_macro",
  "params": {"name": "teardown"}
}
```

For high-volume sweeps over the same kind of state (e.g. permission matrix), call `fuzz_http` after a single shared setup if the server state allows it, then teardown once at the end. Only fall back to the per-iteration loop when the destructive nature of the endpoint requires a fresh resource per call.

## KV Store Sharing

Within one macro run, KV Store entries extracted by earlier steps are available to later steps via `§var_name§` template expansion:

```
run_macro "setup-item":
  login step          → KV Store: {session_cookie: "abc"}
  get-csrf step       → KV Store: {session_cookie: "abc", csrf_token: "xyz"}
  create-item step    → KV Store: {session_cookie: "abc", csrf_token: "xyz", item_id: "42"}
  → macro result returns the final kv_store map to the caller
```

The KV Store is reset between top-level `run_macro` invocations. To propagate state across macros, read the returned `kv_store` from the previous invocation and feed it into the next call's `initial_vars`.

## Single Test with resend_http

Before driving a large sweep, verify behaviour with a single end-to-end iteration:

```json
// macro — setup
{"action": "run_macro", "params": {"name": "setup-item"}}
```

```json
// resend_http — single verification using the captured item_id
{
  "flow_id": "<delete-endpoint-flow-id>",
  "body_patches": [{"json_path": "$.id", "value": "<item_id-from-setup>"}],
  "tag": "delete-single-test"
}
```

```json
// macro — teardown
{"action": "run_macro", "params": {"name": "teardown"}}
```
