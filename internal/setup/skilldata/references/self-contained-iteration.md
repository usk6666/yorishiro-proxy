# Self-Contained Iteration Pattern

A self-contained iteration pattern using Macro pre_send / post_receive hooks.
Guarantees that each iteration operates independently when fuzzing stateful APIs.

## Core Principles

1. **Each iteration completes "precondition setup → test execution → teardown" independently**
2. The KV Store is not shared between fuzzer iterations (by design)
3. However, server-side state is shared, so account for side effects from previous iterations

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

### Step 2: Define the pre_send Macro

The pre_send macro runs before each main request is sent.
It performs: login → CSRF token retrieval → test resource creation.

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

### Step 3: Define the post_receive Macro

The post_receive macro runs after each main request response is received.
The KV Store from pre_send (session_cookie, etc.) is automatically passed through.

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

### Step 4: Run fuzz with Hooks

```json
// fuzz
{
  "action": "fuzz",
  "params": {
    "flow_id": "<delete-endpoint-flow-id>",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.id",
        "payload_set": "item-ids"
      }
    ],
    "payload_sets": {
      "item-ids": {
        "type": "wordlist",
        "values": ["§item_id§"]
      }
    },
    "hooks": {
      "pre_send": {
        "macro": "setup-item",
        "run_interval": "always"
      },
      "post_receive": {
        "macro": "teardown",
        "run_interval": "always"
      }
    },
    "tag": "delete-test"
  }
}
```

## KV Store Sharing

KV Store flow within a single iteration:

```
pre_send macro executes
  → KV Store: {session_cookie: "abc", csrf_token: "xyz", item_id: "42"}
    → Main request sent (template expansion uses §item_id§, etc.)
      → Response received
        → post_receive macro executes (pre_send KV Store is automatically passed)
           → Logout using correct session via §session_cookie§
```

**Important**: If the pre_send KV Store and post_receive vars config share the same key,
the pre_send KV Store value takes precedence.

## Single Test with resend

Before fuzzing, verify behavior with a single resend test:

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<delete-endpoint-flow-id>",
    "body_patches": [{"json_path": "$.id", "value": "§item_id§"}],
    "hooks": {
      "pre_send": {
        "macro": "setup-item",
        "run_interval": "always"
      },
      "post_receive": {
        "macro": "teardown",
        "run_interval": "always"
      }
    },
    "tag": "delete-single-test"
  }
}
```

## run_interval Options

### pre_send

| Value | Behavior |
|-------|----------|
| `"always"` | Run every iteration (default) |
| `"once"` | Run only on the first iteration |
| `"every_n"` | Run every N iterations (requires `n` parameter) |
| `"on_error"` | Run only when the previous iteration errored |

### post_receive

| Value | Behavior |
|-------|----------|
| `"always"` | Run every iteration (default) |
| `"on_status"` | Run when a specific status code occurs (requires `status_codes`) |
| `"on_match"` | Run when response body matches a regex (requires `match_pattern`) |
