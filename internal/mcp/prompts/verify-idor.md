# Verify IDOR (Insecure Direct Object Reference)

Verify Insecure Direct Object Reference / privilege escalation on a recorded HTTP flow using yorishiro-proxy.

## Inputs

- `target_flow_id`: the recorded `flow_id` of the authenticated request you want to test. Required.
- `id_field`: the JSON body field or URL segment that carries the user/object id (e.g. `$.user_id` or `/users/{id}`). Required.
- `candidate_ids`: comma-separated list of ids to try in place of the authenticated user's id. Required.

If any of the above is empty, ask the user for it before issuing tool calls.

## Plan

1. Inspect the captured flow to confirm shape.

   ```json
   // query
   {"resource": "flow", "id": "{{target_flow_id}}"}
   ```

   Note the method, the body shape, and where `{{id_field}}` lives (body JSON path vs path segment vs header).

2. Choose the position type:
   - If `{{id_field}}` is a body JSON path (`$....`), fuzz `positions[].path = "body"` with full body variants.
   - If `{{id_field}}` is a path segment (`/users/{id}`), fuzz `positions[].path = "path"`.
   - If `{{id_field}}` is a header value, use `query` to find its index `N` in the recorded `headers[]` array and fuzz `headers[N].value`.

3. Run the sweep:

   ```json
   // fuzz_http — IDOR sweep across candidate ids
   {
     "flow_id": "{{target_flow_id}}",
     "positions": [
       {
         "path": "body",
         "payloads": ["{{candidate_ids}}"]
       }
     ],
     "tag": "idor-sweep"
   }
   ```

   Replace `payloads` with the materialised list of variants — one per candidate id, encoded the way the original body is (JSON object, form value, raw path string). For path fuzzing, payloads are full path strings such as `/users/1`, `/users/2`, ..., `/users/999`.

4. Read results sorted by status code:

   ```json
   // query
   {
     "resource": "fuzz_results",
     "fuzz_id": "<fuzz-id-from-step-3>",
     "sort_by": "status_code",
     "limit": 100,
     "fields": ["index", "payloads", "status_code", "duration_ms", "response_length"]
   }
   ```

5. Drill into any 200 OK responses that returned a different user's data:

   ```json
   // query
   {"resource": "flow", "id": "<result-flow-id-of-interest>"}
   ```

## Evaluation

- Another user's data returned with HTTP 200 → IDOR is present. Severity depends on what the object exposes.
- 403 / 404 / 401 on candidate ids → access control is enforced for the tested vector. Consider trying additional vectors (cookie-scoped tenant id, JWT `sub`, query params) before concluding.
- Mixed 200 + identical body for all candidates → the endpoint may be ignoring the id; verify with the captured response body.

## Reporting

When complete, summarise:

1. Vulnerability type and impact scope.
2. Tool calls used (paste exact JSON for reproducibility).
3. Concrete evidence — at least one `flow_id` showing cross-user data exposure.
4. Suggested remediation (server-side authorisation check at the resource-resolution boundary).
