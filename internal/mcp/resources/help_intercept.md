# intercept

Act on intercepted requests, responses, or WebSocket frames in the intercept queue.

## Parameters

### action (string, required)
The action to execute. One of: `release`, `modify_and_forward`, `drop`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### release
Release an intercepted item, allowing it to proceed unmodified.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted item from the intercept queue.

Returns: intercept_id, action, status, phase, protocol, and item details.

### modify_and_forward
Modify an intercepted item and forward it with the specified changes.

**Parameters (common):**
- **intercept_id** (string, required): ID of the intercepted item from the intercept queue.

**Parameters (HTTP request phase):**
- **override_method** (string, optional): Override the HTTP method.
- **override_url** (string, optional): Override the target URL.
- **override_headers** (object, optional): Header overrides as key-value pairs.
- **add_headers** (object, optional): Headers to add (appended to existing values).
- **remove_headers** (array of strings, optional): Header names to remove.
- **override_body** (string, optional): Override the request body.

**Parameters (HTTP response phase):**
- **override_status** (integer, optional): Override the HTTP status code.
- **override_response_headers** (object, optional): Response header overrides.
- **add_response_headers** (object, optional): Response headers to add.
- **remove_response_headers** (array of strings, optional): Response header names to remove.
- **override_response_body** (string, optional): Override the response body.

**Parameters (WebSocket frame phase):**
- **override_body** (string, optional): Override the WebSocket frame payload. For text frames, provide the payload as a plain string. For binary frames, provide a Base64-encoded string.

Returns: intercept_id, action, status, phase, protocol, and item details.

### drop
Drop an intercepted item, returning a 502 Bad Gateway response to the HTTP client or discarding the WebSocket frame.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted item from the intercept queue.

Returns: intercept_id, action, status.

## Intercepted Item Fields

### HTTP items (phase: request or response)
- **protocol**: `"http"`
- **method**: HTTP method
- **url**: Request URL
- **status_code**: HTTP status code (response only)
- **headers**: Request/response headers
- **body** / **body_encoding**: Body content with encoding type

### WebSocket items (phase: websocket_frame)
- **protocol**: `"websocket"`
- **opcode**: Frame type (`"Text"`, `"Binary"`, `"Close"`, `"Ping"`, `"Pong"`)
- **direction**: `"client_to_server"` or `"server_to_client"`
- **flow_id**: WebSocket flow ID
- **upgrade_url**: Original WebSocket upgrade request URL
- **sequence**: Frame sequence number
- **body** / **body_encoding**: Payload content (text as-is, binary as Base64)

## Usage Examples

### Release intercepted HTTP request
```json
{
  "action": "release",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Modify and forward intercepted HTTP request
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

### Drop intercepted HTTP request
```json
{
  "action": "drop",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Release intercepted WebSocket frame
```json
{
  "action": "release",
  "params": {"intercept_id": "ws-frame-456"}
}
```

### Modify and forward intercepted WebSocket text frame
```json
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "ws-frame-456",
    "override_body": "{\"action\":\"modified\",\"data\":\"injected\"}"
  }
}
```

### Drop intercepted WebSocket frame
```json
{
  "action": "drop",
  "params": {"intercept_id": "ws-frame-456"}
}
```
