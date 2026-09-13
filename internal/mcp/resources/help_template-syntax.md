# template-syntax

A pointer document. yorishiro-proxy has exactly one variable-substitution syntax, used by the macro engine and by everything built on top of it. This page states the rule and routes to the per-tool reference for each expansion site. It is deliberately **not** an exhaustive reserved-key table.

## The delimiter rule

A variable reference is `§name§` — U+00A7 SECTION SIGN on **both** sides. Nothing else is substituted.

```text
"Cookie: PHPSESSID=§session_cookie§"
```

Values come from the KV Store, which is populated by `params.initial_vars` on `define_macro`, `params.vars` on `run_macro`, earlier steps' `extract[].name` results, and the runtime-reserved keys described below.

Three properties follow from the delimiter choice:

- `{{name}}`, `${name}` and `%name%` are **not** expanded. They ship literally on the wire. U+00A7 was chosen precisely so that Handlebars / Mustache / Angular / SSTI payloads pass through a security tool unmodified.
- An unknown `§name§` is also left literal — expansion never fails on a missing variable. The step result is downgraded to `"warning"` and `warnings[]` names the location.
- An unknown **encoder** in a pipe chain *is* a hard error. Encoders are the one part of the expression that must resolve.

An expression may pipe through encoders: `§name | url_encode | base64§`. Available encoders: `url_encode`, `base64`, `base64_decode`, `hex`, `html_encode`, `lower`, `upper`, `md5`, `sha256`.

## Where expansion happens

| Site | Tool | Reference |
|---|---|---|
| `steps[].override_method` / `override_url` / `override_headers` values / `override_body` | `macro` | `docs(topic="macro", section="Variable substitution syntax")` |
| `pre_macro` / `post_macro` hook steps | `fuzz_http`, `fuzz_ws`, `fuzz_grpc`, `fuzz_raw` | `docs(topic="fuzz_http")` and the matching `fuzz_*` topic |
| The fuzz base request itself (method, path, query, header values, body; raw payload bytes) | `fuzz_http`, `fuzz_raw` | `docs(topic="fuzz_http")`, `docs(topic="fuzz_raw")` |
| `upstream_proxy.url_template` | `proxy_start`, `configure` | `docs(topic="proxy_start")`, `docs(topic="configure")` |

Within a macro step only the four `override_*` fields expand; `extract` and `when` never do, and in `override_headers` only the **values** expand — header names are copied verbatim so wire casing is preserved.

## Reserved keys

Keys beginning with `__` are reserved for runtime-populated state. `internal/macro/reserved.go` (`macro.ReservedKeyPrefix` / `macro.IsReservedKey`) is the authoritative definition of that rule: user-supplied vars, hook results and input maps that would write a `__`-prefixed key are dropped at every merge site, so a macro cannot shadow runtime state such as `§__nonce§`.

The **set** of reserved keys is protocol-divergent, not universal. `fuzz_ws` exposes close-frame keys that `fuzz_http` does not; `fuzz_raw` has chunk/byte-count keys and no `__response_status`; `fuzz_grpc` scopes `__response_status` to the gRPC 0–16 domain and adds `__response_status_message`. Do not assume a key exists because another protocol has it — read the `post_macro` parameter documentation in that protocol's own topic:

- `docs(topic="fuzz_http")`
- `docs(topic="fuzz_ws")`
- `docs(topic="fuzz_grpc")`
- `docs(topic="fuzz_raw")`

`§__nonce§` (per-resolution UUID) and `§__iteration§` (0-based variant index) are the two that behave the same everywhere.

## Not to be confused with

MCP **prompt** playbooks use `{{arg_name}}` double-brace placeholders, expanded server-side at `prompts/get` time. That is a different mechanism at a different layer and never reaches the wire. A playbook body may legitimately contain both syntaxes; when it does, the body says which is which.
