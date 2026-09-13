# Verify Reflected XSS

Verify reflected Cross-Site Scripting on a recorded HTTP flow. Payloads are harmless markers — no script actually executes; the test only measures whether the input is reflected unescaped.

## Inputs

- `target_flow_id`: recorded `flow_id` of the request that reflects user input into the response. Required.
- `injection_point`: typed `fuzz_http.positions[].path` — usually `raw_query`, `body`, or `headers[N].value`. Required.

If any required field is empty, ask the user.

## Plan

1. Inspect the captured flow to confirm where the input is reflected:

   ```json
   // query
   {"resource": "flow", "id": "{{target_flow_id}}"}
   ```

2. Run the marker sweep — every payload uses the `YP_` prefix so it is identifiable in the response. No script execution occurs.

   ```json
   // fuzz_http — {{YP_TEMPLATE}} / §YP_TEMPLATE§ are literal marker payloads, not placeholders
   {
     "flow_id": "{{target_flow_id}}",
     "positions": [
       {
         "path": "{{injection_point}}",
         "payloads": [
           "YP_NORMAL_TEXT",
           "<YP_TAG>test</YP_TAG>",
           "<img src=x onerror=YP_XSS>",
           "'\"><YP_TAG>",
           "javascript:YP_XSS",
           "<svg/onload=YP_XSS>",
           "{{YP_TEMPLATE}}",
           "§YP_TEMPLATE§"
         ]
       }
     ],
     "tag": "xss-reflected"
   }
   ```

   The last two payloads are template-injection markers, not placeholders that get expanded here. `{{YP_TEMPLATE}}` is not a declared prompt argument, so `prompts/get` leaves it literal. `§YP_TEMPLATE§` targets the macro KV-store syntax: the fuzz engine *does* run `§var§` expansion over payloads, but `YP_TEMPLATE` is never a KV-store key, so the marker reaches the wire literally. Both are looking for a sink that itself interprets the marker syntax.

3. Filter for responses that echoed the marker:

   ```json
   // query
   {
     "resource": "fuzz_results",
     "fuzz_id": "<fuzz-id>",
     "filter": {"body_contains": "<YP_TAG>"}
   }
   ```

4. Inspect the matched flows and check the surrounding context (attribute, raw HTML, JSON string, etc.):

   ```json
   // query
   {"resource": "flow", "id": "<result-flow-id>"}
   ```

## Evaluation

- Response contains `<YP_TAG>` as-is → not escaped, XSS is present.
- Response contains `&lt;YP_TAG&gt;` → properly escaped, not vulnerable at this sink.
- `§YP_TEMPLATE§` appearing literally is expected — that marker tests a different sink (macro template expansion), not browser XSS.
- The `§YP_TEMPLATE§` variant reports `unresolved-tokens: [YP_TEMPLATE]` in its `fuzz_results` `error` field. This is expected and is **not** a failure — it only records that the marker was not a KV-store key (which is the whole point of the probe). Do not retry or abandon the sweep because of it.

## Reporting

Note the exact payload that reflected unescaped, the response context (HTML body, attribute, JavaScript string, ...), and the appropriate output-encoding remediation for that context (HTML-entity escape for body, attribute encoding for attributes, `JSON.stringify` for inline scripts).
