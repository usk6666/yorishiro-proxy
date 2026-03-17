# fuzz

Execute fuzz testing campaigns on recorded proxy data.

## Parameters

### action (string, required)
The action to execute. One of: `fuzz`, `fuzz_pause`, `fuzz_resume`, `fuzz_cancel`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### fuzz
Start an asynchronous fuzz campaign against a recorded flow. Returns fuzz_id immediately. Use `fuzz_pause`, `fuzz_resume`, `fuzz_cancel` for job control. Query `fuzz_results` resource for progress.

**Parameters:**
- **flow_id** (string, required): ID of the template flow to fuzz.
- **attack_type** (string, required): Fuzzing strategy. `"sequential"` tests one position at a time; `"parallel"` applies payloads to all positions simultaneously (zip).
- **positions** (array, required): Payload injection points. Each position specifies:
  - **id** (string, required): Unique position identifier (e.g. `"pos-0"`).
  - **location** (string, required): Where to inject: `header`, `path`, `query`, `body_regex`, `body_json`, `cookie`.
  - **name** (string): Header name, query key, or cookie name (required for header/query/cookie).
  - **json_path** (string): JSON path for body_json location (e.g. `"$.password"`).
  - **mode** (string, optional): Operation mode: `replace` (default), `add`, or `remove`.
  - **match** (string, optional): Regex pattern for partial replacement. Capture groups replace only the group.
  - **payload_set** (string): Name of the payload set to use (not required for remove mode).
- **payload_sets** (object, required): Named payload sets. Each set specifies:
  - **type** (string, required): `wordlist`, `file`, `range`, `sequence`, `charset`, `case_variation`, or `null_byte_injection`.
  - **values** (array): Payload strings (for wordlist).
  - **path** (string): Relative path under the wordlist directory (for file). Default directory: `~/.yorishiro-proxy/wordlists/`. Read the `yorishiro://info/wordlist_dir` resource to get the exact resolved path.
  - **start**, **end**, **step** (integer): Range parameters (for range/sequence).
  - **format** (string): Format string (for sequence, e.g. `"user%04d"`).
  - **charset** (string): Character set for charset type (e.g. `"abc"`, `"0123456789"`).
  - **length** (integer): Combination length for charset type.
  - **input** (string): Base string for case_variation and null_byte_injection types.
  - **encoding** (array of strings, optional): Codec chain to apply to each payload. Codecs are applied in order as a pipeline — e.g. `["url_encode_query", "base64"]` first URL-encodes the payload, then Base64-encodes the result. Maximum 10 codecs per chain. Available codecs: base64, base64url, url_encode_query, url_encode_path, url_encode_full, double_url_encode, hex, html_entity, html_escape, unicode_escape, md5, sha256, lower, upper.
- **concurrency** (integer, optional): Number of concurrent workers (default: `1`).
- **rate_limit_rps** (number, optional): Requests per second limit. `0` means unlimited.
- **delay_ms** (integer, optional): Fixed delay between requests in milliseconds.
- **timeout_ms** (integer, optional): Per-request timeout in milliseconds (default: `10000`).
- **max_retries** (integer, optional): Retry count per failed request (default: `0`).
- **stop_on** (object, optional): Automatic stop conditions:
  - **status_codes** (array of integers): Stop when any of these HTTP status codes is received.
  - **error_count** (integer): Stop when cumulative error count reaches this value.
  - **latency_threshold_ms** (integer): Stop when sliding window median latency exceeds this value.
  - **latency_baseline_multiplier** (number): Stop when current median exceeds baseline median times this multiplier.
  - **latency_window** (integer): Sliding window size for latency detection (default: `10`).
- **tag** (string, optional): Tag to label the fuzz job.
- **hooks** (object, optional): Pre/post hooks for macro integration (see resend tool help for hook syntax).

Returns: fuzz_id, status, total_requests, tag, message.

### fuzz_pause
Pause a running fuzz job. Workers will stop after completing their current request.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to pause.

Returns: fuzz_id, action, status.

### fuzz_resume
Resume a paused fuzz job.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to resume.

Returns: fuzz_id, action, status.

### fuzz_cancel
Cancel a running or paused fuzz job. The job will be terminated and marked as cancelled.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to cancel.

Returns: fuzz_id, action, status.

## Usage Examples

### Fuzz with sequential attack
```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "abc-123",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "header",
        "name": "Authorization",
        "mode": "replace",
        "match": "Bearer (.*)",
        "payload_set": "tokens"
      }
    ],
    "payload_sets": {
      "tokens": {
        "type": "wordlist",
        "values": ["token1", "token2", "admin-token"]
      }
    },
    "tag": "auth-test"
  }
}
```

### Fuzz with parallel attack
```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "abc-123",
    "attack_type": "parallel",
    "positions": [
      {"id": "pos-0", "location": "query", "name": "username", "payload_set": "users"},
      {"id": "pos-1", "location": "body_json", "json_path": "$.password", "payload_set": "passwords"}
    ],
    "payload_sets": {
      "users": {"type": "wordlist", "values": ["admin", "root", "user"]},
      "passwords": {"type": "wordlist", "values": ["pass1", "pass2", "pass3"]}
    }
  }
}
```

### Fuzz with encoded payloads
```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "abc-123",
    "attack_type": "sequential",
    "positions": [
      {"id": "pos-0", "location": "query", "name": "search", "payload_set": "xss"}
    ],
    "payload_sets": {
      "xss": {
        "type": "wordlist",
        "values": ["<script>alert(1)</script>", "<img onerror=alert(1)>"],
        "encoding": ["url_encode_query"]
      }
    }
  }
}
```

### Fuzz with charset generator
```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "abc-123",
    "attack_type": "sequential",
    "positions": [
      {"id": "pos-0", "location": "query", "name": "pin", "payload_set": "pins"}
    ],
    "payload_sets": {
      "pins": {
        "type": "charset",
        "charset": "0123456789",
        "length": 4,
        "encoding": ["url_encode_query"]
      }
    }
  }
}
```

### Fuzz with case variation generator
```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "abc-123",
    "attack_type": "sequential",
    "positions": [
      {"id": "pos-0", "location": "body_json", "json_path": "$.role", "payload_set": "roles"}
    ],
    "payload_sets": {
      "roles": {
        "type": "case_variation",
        "input": "Admin"
      }
    }
  }
}
```

### Pause a fuzz job
```json
{
  "action": "fuzz_pause",
  "params": {"fuzz_id": "fuzz-abc-123"}
}
```

### Resume a fuzz job
```json
{
  "action": "fuzz_resume",
  "params": {"fuzz_id": "fuzz-abc-123"}
}
```

### Cancel a fuzz job
```json
{
  "action": "fuzz_cancel",
  "params": {"fuzz_id": "fuzz-abc-123"}
}
```
