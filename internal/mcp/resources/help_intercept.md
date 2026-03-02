# intercept

Act on intercepted requests in the intercept queue.

## Parameters

### action (string, required)
The action to execute. One of: `release`, `modify_and_forward`, `drop`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### release
Release an intercepted request, allowing it to proceed to the upstream server unmodified.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.

Returns: intercept_id, action, status.

### modify_and_forward
Modify an intercepted request and forward it to the upstream server with the specified changes.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.
- **override_method** (string, optional): Override the HTTP method.
- **override_url** (string, optional): Override the target URL.
- **override_headers** (object, optional): Header overrides as key-value pairs.
- **add_headers** (object, optional): Headers to add (appended to existing values).
- **remove_headers** (array of strings, optional): Header names to remove.
- **override_body** (string, optional): Override the request body.

Returns: intercept_id, action, status.

### drop
Drop an intercepted request, returning a 502 Bad Gateway response to the client.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.

Returns: intercept_id, action, status.

## Usage Examples

### Release intercepted request
```json
{
  "action": "release",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Modify and forward intercepted request
```json
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "int-abc-123",
    "override_method": "POST",
    "override_headers": {"Authorization": "Bearer injected-token"},
    "override_body": "{\"role\":\"admin\"}"
  }
}
```

### Drop intercepted request
```json
{
  "action": "drop",
  "params": {"intercept_id": "int-abc-123"}
}
```
