# Verify CSRF Token Validation

Verify whether a recorded HTTP flow validates its CSRF token by replacing or emptying the token and observing whether the server still accepts the request.

## Inputs

- `target_flow_id`: recorded `flow_id` of a state-changing request that includes a CSRF token. Required.
- `token_header_name`: header that carries the CSRF token (e.g. `X-CSRF-Token`, `X-XSRF-Token`). Required.

If any required field is empty, ask the user.

## Plan

1. Inspect the captured flow and locate the token header's index `N` in the `headers[]` array (the typed `fuzz_http` path requires a numeric index, not a header name):

   ```json
   // query
   {"resource": "flow", "id": "{{target_flow_id}}"}
   ```

   Scan `headers[]` for an entry whose `name` (case-insensitive compare) matches `{{token_header_name}}` and remember its index.

2. Fuzz the token value with bad / empty / forged-but-valid-shape values:

   ```json
   // fuzz_http — substitute N below with the index found in step 1
   {
     "flow_id": "{{target_flow_id}}",
     "positions": [
       {
         "path": "headers[N].value",
         "payloads": [
           "",
           "invalid-token-value",
           "00000000-0000-0000-0000-000000000000",
           "AAAAAAAAAAAAAAAAAAAAAA",
           "deadbeef"
         ]
       }
     ],
     "tag": "csrf-token-sweep"
   }
   ```

3. Test the "no header at all" variant separately — `fuzz_http` positions replace a value but cannot delete a header slot. Issue a single `resend_http` call without the token header (build a fresh `headers` array that omits the slot):

   ```json
   // resend_http
   {
     "flow_id": "{{target_flow_id}}",
     "headers": [
       /* copy every header from the recorded flow EXCEPT {{token_header_name}} */
     ],
     "tag": "csrf-no-token"
   }
   ```

4. Read results and look for accepted requests:

   ```json
   // query
   {
     "resource": "fuzz_results",
     "fuzz_id": "<fuzz-id>",
     "sort_by": "status_code",
     "fields": ["index", "payloads", "status_code", "response_length"]
   }
   ```

## Evaluation

- Request succeeds (2xx or 3xx redirect) with invalid / empty / missing token → no CSRF protection. Severity = same as the underlying state-changing action.
- 403 / 400 / 419 (Laravel) → CSRF protection is functioning.

For cookie-based CSRF tokens (double-submit pattern), repeat the same procedure against the `Cookie` header — find that header's index `N`, fuzz its value, and observe whether the body token alone is sufficient to authorise the request.

## Reporting

Record: which token value variants were accepted, the resulting `flow_id`s, and whether the server appears to validate only the cookie, only the header, or neither. Recommend the appropriate CSRF defence (synchroniser token, double-submit cookie + `SameSite=Strict`).
