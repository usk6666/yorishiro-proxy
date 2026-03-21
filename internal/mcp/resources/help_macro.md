# macro

Define and execute macro workflows for multi-step security testing.

## Parameters

### action (string, required)
The action to execute. One of: `define_macro`, `run_macro`, `delete_macro`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### define_macro
Save a macro definition (upsert) with steps, extraction rules, and guards. If a macro with the same name exists, it is updated.

**Parameters:**
- **name** (string, required): Unique macro identifier.
- **description** (string, optional): Human-readable description.
- **steps** (array, required): Ordered list of macro steps. Each step:
  - **id** (string, required): Unique step identifier within the macro.
  - **flow_id** (string, required): Recorded flow to use as a template.
  - **override_method** (string, optional): Override HTTP method.
  - **override_url** (string, optional): Override request URL. Supports `§variable§` templates.
  - **override_headers** (object, optional): Header overrides as key-value pairs. Supports templates.
  - **override_body** (string, optional): Override request body. Supports templates.
  - **on_error** (string, optional): Error handling: `"abort"` (default), `"skip"`, or `"retry"`.
  - **retry_count** (integer, optional): Retry count when on_error is "retry" (default: 3).
  - **retry_delay_ms** (integer, optional): Delay between retries in ms (default: 1000).
  - **timeout_ms** (integer, optional): Step timeout in ms (default: 60000).
  - **extract** (array, optional): Value extraction rules. Each rule: `name`, `from` ("request"/"response"), `source` ("header"/"body"/"body_json"/"status"/"url"), `header_name`, `regex`, `group`, `json_path`, `default`, `required`.
  - **when** (object, optional): Step guard condition: `step`, `status_code`, `status_code_range`, `header_match`, `body_match`, `extracted_var`, `negate`.
- **initial_vars** (object, optional): Pre-populated KV Store entries.
- **macro_timeout_ms** (integer, optional): Overall macro timeout in ms (default: 300000).

Returns: name, step_count, created (true if new, false if updated).

### run_macro
Execute a stored macro for testing. The macro is loaded from DB and run with the macro engine.

**Parameters:**
- **name** (string, required): Name of the macro to run.
- **vars** (object, optional): Runtime variable overrides for the KV Store.

Returns: macro_name, status ("completed"/"error"/"timeout"), steps_executed, kv_store, step_results[], error.

### delete_macro
Remove a stored macro definition.

**Parameters:**
- **name** (string, required): Name of the macro to delete.

Returns: name, deleted.

## Usage Examples

### Define a macro
```json
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "description": "Login and get CSRF token",
    "steps": [
      {
        "id": "login",
        "flow_id": "recorded-login-flow",
        "override_body": "username=admin&password=§password§",
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
        "flow_id": "recorded-csrf-flow",
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
      }
    ],
    "initial_vars": {"password": "admin123"}
  }
}
```

### Run a macro
```json
{
  "action": "run_macro",
  "params": {
    "name": "auth-flow",
    "vars": {"password": "override-password"}
  }
}
```

### Delete a macro
```json
{
  "action": "delete_macro",
  "params": {"name": "auth-flow"}
}
```
