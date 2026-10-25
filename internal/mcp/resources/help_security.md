# security tool

Configure runtime security settings including target scope rules.

This tool is separate from `configure` to allow MCP clients to apply different approval policies (e.g., manual approval for security changes).

## Two-Layer Architecture

Target scope uses a **Policy Layer** and an **Agent Layer**:

- **Policy Layer** (immutable by the agent): Set at startup from `-target-policy-file`, else the config file's `target_scope_policy` section. Defines the upper boundary for what the agent can access. No action of this tool — or of any MCP tool, over stdio or HTTP — can modify it; only the operator can replace it at runtime (see [Reloading the Policy Layer](#reloading-the-policy-layer-operator-only)). Policy rules are validated at startup with the same rules as this tool (`schemes` only `http` / `https`, ports 1-65535, a hostname that can match — no `*`, `host:port` or URL), except that a Policy rule may omit `hostname`; `rate_limits` / `budget` values must be >= 0, and the dedicated policy file must not contain unknown fields. An invalid policy stops the server instead of loading a rule that silently matches nothing.
- **Agent Layer** (mutable): Controlled by this tool. Can further restrict access within the Policy Layer boundaries. Agent allow rules must fall within the Policy allow scope.

### Evaluation Order

1. **Policy denies** -- always block (highest priority)
2. **Agent denies** -- block
3. **Policy allows** (if any) -- target must match at least one, otherwise block
4. **Agent allows** (if any) -- target must match at least one, otherwise block
5. All checks passed -- allow

When neither layer has rules, all targets are permitted (open mode).

### Applicability

Both Policy Layer and Agent Layer `target_scope` rules apply to **all** proxy traffic. There is a single shared `target_scope` evaluator (Policy + Agent rules merged via the order above); every code path that opens or forwards a connection consults it.

| Traffic source | Policy Layer | Agent Layer |
|---|---|---|
| Transparent MITM (HTTP CONNECT tunnel, plain HTTP forward proxy, SOCKS5 tunnel) | Applied | Applied |
| TCP forward (`tcp_forwards`, every `protocol`) | Applied (at `proxy_start` and at every accept, before the target is contacted; see [`tcp_forwards` gate](#tcp_forwards-gate)) | Applied |
| Transparent listener (`proxy_start` `transparent_mode: "redirect"`) | Applied (original destination, SNI and every request's `Host` / `:authority`, before the target is contacted — on TLS MITM connections too; a name may admit an IP that is not allow-listed only if it resolves to it, and an admitting SNI also admits the connection's raw (non-HTTP, non-gRPC) traffic; on an IP-allowed destination name denies are best-effort for traffic not recognised as HTTP / TLS — see `docs(topic="proxy_start")`, "Target scope on a transparent listener") | Applied |
| MCP tool-initiated requests (`resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`, `fuzz_http`, `fuzz_ws`, `fuzz_grpc`, `fuzz_raw`, `macro`) | Applied | Applied |
| Intercepted traffic released from a hold (`intercept` `release` / `modify_and_forward`, timeout auto-release) | Applied | Applied |

This means `set_target_scope` and `update_target_scope` take effect immediately for both AI-agent-driven MCP calls and any client traffic flowing through the proxy (curl, browser, etc.). The same evaluator drives both the live pipeline's `HostScopeStep` / `HTTPScopeStep` and the MCP-tool pre-flight check.

#### Deny manifestation by path

A `target_scope` deny surfaces differently depending on how the request entered the proxy. Operators should read the symptom in context:

| Path | Deny symptom |
|---|---|
| Transparent HTTPS via CONNECT tunnel | Proxy refuses the tunnel with `HTTP/1.1 403 Forbidden` and body `yorishiro-proxy: target blocked by scope`, then closes the connection. No tunnel is opened and the backend is never contacted. |
| Transparent plain-HTTP forward proxy | Proxy returns `HTTP/1.1 403 Forbidden` with body `yorishiro-proxy: target blocked by scope`. |
| MCP tool-initiated request (`resend_*`, `fuzz_*`, `macro`) | MCP error response with the violation reason. |
| Intercept release (`release`, `modify_and_forward`, timeout auto-release) | The `intercept` call itself succeeds. Scope is checked again at release time, with the rules in force then, against the request being forwarded — for `modify_and_forward`, the modified one. A deny added while the request was held (policy reload or this tool) or a rewrite of `authority` / `path` into a denied target blocks it: an HTTP request gets `403 Forbidden` with body `{"error":"blocked by target_scope","blocked_by":"target_scope"}`, a native gRPC call fails with `grpc-status: 7`, a WebSocket / gRPC-Web message is dropped, and the block is recorded as a flow with `blocked_by: target_scope`. |

### Reloading the Policy Layer (operator only)

The operator replaces the running Policy Layer — target scope `allows` / `denies`, `rate_limits` and `budget` together — by editing the policy source and sending the server process `SIGHUP` (Unix only). There is deliberately no MCP tool or action for this: the path is reserved for whoever controls the process, never for the agent.

- **Enabled only with a policy source**: the `SIGHUP` handler is installed only when the server was started with `-target-policy-file` or `-config`. Without either, `SIGHUP` terminates the process as before.
- **When it is safe to signal**: the handler is installed only once the flags are parsed and the boot policy has loaded, so a `SIGHUP` sent earlier in startup still terminates the process. Wait for the Info line `target scope policy reload enabled` before sending `SIGHUP`.
- **Terminal hangup**: closing the terminal that launched the server also sends `SIGHUP`. With a policy source configured this now triggers a reload instead of stopping the server, so the process keeps running and keeps its listening ports. Stop it explicitly with `SIGTERM` or `SIGINT`.
- **Source**: the same one used at startup — `-target-policy-file` when given, otherwise the config file's `target_scope_policy` section (the whole config file is validated as at startup, but only the policy section is applied; other config sections are not reloaded).
- **Full replacement**: reloading is equivalent to starting with that file. A section omitted from the new file (e.g. `rate_limits`) is cleared.
- **Atomic**: the new file is validated completely before anything changes. Malformed JSON, an out-of-vocabulary `schemes` token or a negative limit rejects the whole reload; the previous policy stays in force and an Error line (`target scope policy reload rejected; previous policy retained`) is logged.
- **Unknown fields — prefer `-target-policy-file` for live edits**: only `-target-policy-file` is decoded strictly, so an unknown or misspelled field there (e.g. `denys`) rejects the reload. The `-config` source is decoded leniently, exactly as at startup: a misspelled `target_scope_policy` key, a misspelled key inside it (e.g. `deny` for `denies`), or a file that is just `{}` or `null` is accepted and reloads as "no policy", dropping the rules it was meant to keep. When a reload drops every policy allow and deny rule, a Warn line (`reloaded policy has no allow or deny rules; the previous target scope policy rules were removed`) names the source path and the previous counts. Check for it after every reload.
- **What it applies to**: new connections and new requests, and also work already in flight. Every live connection admitted by the CONNECT, SOCKS5, plain-HTTP-forward or `tcp_forwards` gate — TLS passthrough relays, MITM'd HTTP/1.x / HTTP/2 / WebSocket / SSE / gRPC connections and raw (bytechunk) tunnels alike — is re-evaluated with the same check that admitted it (the CONNECT / SOCKS5 authority, the forward target or the `tcp_forwards` target, never the SNI), and is closed when an identical new connection would no longer be admitted. One Info line (`live connection closed: target no longer in scope`) is logged per closed connection, and the reload's Info line carries `live_conns_closed` (a Warn line is added when it is non-zero). A connection with held intercepts is revoked at once — new requests on it are answered 403 `blocked_by: target_scope` and nothing more is sent to the denied host — but closed only after its holds are released or time out; each held request is then answered and recorded per the release re-check below. Until then, data the denied host sends toward the client (responses of other HTTP/2 streams, SSE events, WebSocket server frames) keeps flowing, bounded by the intercept hold timeout: a revoked connection takes no new holds, so a server message that matches an intercept rule meanwhile is dropped (`blocked_by: target_scope`) instead of held. `live_conns_closed` counts the revoked connections and `live_conns_deferred` the ones whose close was deferred this way (`live connection revoked: close deferred until intercept holds resolve` is logged for each, then the `closed` line once they close). A deny that only names a `path_prefix` closes no connection; it is enforced per request. Running fuzz jobs re-check the scope for every variant they send, and a held intercept re-checks it when released (manually, by timeout auto-release, or via `modify_and_forward`). The same reconciliation runs after `set_target_scope` / `update_target_scope`.
- **Agent Layer on narrowing**: Agent rules are kept unchanged. An agent allow rule the new policy no longer covers simply stops matching (requests to it are blocked with `not in policy allow list`) and a Warn line lists such rules. The agent's restriction is never dropped, so narrowing the policy never widens what the agent can reach.
- **Budget**: the request counter is **not** reset by a reload; the duration limit is re-armed against the new value, measured from the original session start. A budget narrowed below current usage stops the proxy (on the next request, or immediately for the duration limit).
- **Audit**: a successful reload logs `target scope policy reloaded` at Info with the trigger, source path, file `sha256` and `mtime`, rule counts before/after, and the resulting policy and effective rate limits and budget. `get_target_scope` reports `source` and `loaded_at` so the agent can see that the policy changed.
- **Placement**: keep the policy file in a directory that neither the proxy's user nor the agent can write. File permissions alone are not enough — anyone who can write the directory can replace the file by rename, which is how `manage` export writes its files — so never place it where `manage` export can write.

## Listener Exposure

The proxy listener (`proxy_start` `listen_addr`, or the config file's `listen_addr`) defaults to `127.0.0.1:8080` but may bind any IP literal: `0.0.0.0` / `[::]` for every interface, or one specific interface address. `tcp_forwards` listeners inherit their parent listener's bound host, and SOCKS5 shares the listener's port.

- **Address families**: `0.0.0.0` binds IPv4 only (an IPv4-mapped spelling such as `[::ffff:0.0.0.0]` binds the same IPv4 wildcard). `[::]` is the dual-stack wildcard: it accepts IPv4 connections too, so firewall rules for a `[::]` listener must cover both IPv4 and IPv6.
- **No in-proxy client access control**: the proxy has no client authentication (SOCKS5 `socks5_auth` aside) and no client CIDR allow-list. A listener on a non-loopback address is an open proxy for every host that can route to it.
- **Where access control lives**: on the network side (host firewall / nftables, network namespaces) for *who may connect*, and in the target scope Policy Layer for *where connections may go*. Run a non-loopback listener only where both are in place.
- **Operator signal**: binding a non-loopback address logs one Warn line, `proxy listener bound to non-loopback address`, with the listener `name` and the bound `listen_addr`.
- **The MCP HTTP server is different**: it stays loopback-only; this section is about the proxy data-path listener alone.

## Actions

### `set_target_scope`

Replace all Agent Layer allow/deny rules. Use empty arrays to clear rules.

Agent allow rules must fall within the Policy allow boundary. If any agent allow rule is outside the policy scope, the entire operation is rejected with an error.

```json
{
  "action": "set_target_scope",
  "params": {
    "allows": [
      {"hostname": "api.target.com", "ports": [443], "schemes": ["https"]},
      {"hostname": "*.target.com"}
    ],
    "denies": [
      {"hostname": "admin.target.com"}
    ]
  }
}
```

### `update_target_scope`

Apply incremental changes to Agent Layer rules.

- `add_allows` / `remove_allows` -- modify agent allow rules
- `add_denies` / `remove_denies` -- modify agent deny rules
- `add_allows` rules must fall within the Policy allow boundary
- `remove_denies` cannot remove Policy deny rules (returns error)
- Duplicate additions are ignored

```json
{
  "action": "update_target_scope",
  "params": {
    "add_allows": [{"hostname": "new-api.target.com"}],
    "remove_allows": [{"hostname": "old-api.target.com"}],
    "add_denies": [{"hostname": "staging.target.com"}]
  }
}
```

### `get_target_scope`

Returns both Policy and Agent Layer rules with their enforcement mode.

```json
{
  "action": "get_target_scope"
}
```

Response:

```json
{
  "policy": {
    "allows": [{"hostname": "*.target.com"}],
    "denies": [{"hostname": "*.internal.corp"}],
    "source": "policy file",
    "loaded_at": "2026-10-16T09:30:00Z",
    "immutable": true
  },
  "agent": {
    "allows": [{"hostname": "api.target.com"}],
    "denies": [{"hostname": "admin.target.com"}]
  },
  "effective_mode": "enforcing"
}
```

### `test_target`

Check a URL against current rules without making a request (dry run). Reports which layer and rule decided the outcome.

```json
{
  "action": "test_target",
  "params": {
    "url": "https://api.target.com/v1/users"
  }
}
```

Response:

```json
{
  "allowed": true,
  "reason": "",
  "layer": "agent",
  "matched_rule": {"hostname": "api.target.com"},
  "tested_target": {"hostname": "api.target.com", "port": 443, "scheme": "https", "path": "/v1/users"}
}
```

## Target Rule Fields

| Field | Type | Description |
|---|---|---|
| `hostname` | string | Required. Exact match or wildcard `*.example.com`. IPv4 and IPv6 literals are accepted; IPv6 may be bare (`::1`) or bracketed (`[::1]`). Hosts are compared in a canonical form, so every spelling that dials the same host matches the rule: any textual form of an IPv6 address, with or without a zone (`[fe80::1%eth0]` matches `fe80::1`; rules cannot carry a zone); IPv4-mapped IPv6 and its IPv4 address in either direction (`::ffff:10.0.0.5` = `10.0.0.5`); one trailing dot (`db.internal.` matches `db.internal` and `*.internal`); and, in a Host header value, legacy IPv4 spellings (`2130706433`, `0x7f.0.0.1`, `127.1` match `127.0.0.1`, so a deny for `127.0.0.1` blocks `Host: 0x7f.0.0.1`). While any rule is set, a dial target written as an IPv4 address in any form other than dotted decimal (`2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`, `127.0.0.1.`) is blocked, even under an allow for `127.0.0.1`: resolvers disagree on where such a name goes, and some look it up in DNS. Use the dotted-decimal address instead (a Host header value is not affected). While any rule is set, a target host ending in a number that is not a valid IPv4 address (`1.2.3.4.5`) is blocked. While any rule is set, a dial target with an empty host (`:8080`) or an unspecified address (`0.0.0.0`, `[::]`, `::ffff:0.0.0.0`, `0`) is also blocked, because it dials the proxy host itself: use an explicit address such as `127.0.0.1` or `[::1]` instead (a Host header value is not affected). A trailing-dot rule is rejected. A wildcard over an IP literal (`*.10.0.0.1`) is rejected |
| `ports` | int[] | Optional. Match specific ports. Empty = all ports |
| `path_prefix` | string | Optional. Literal, case-sensitive prefix of the request path — not a glob. Must start with `/`; `*`, `?` and `#` are rejected (`/api/` already matches everything under `/api/`; the query and fragment are not part of the path). Matches when either the wire-form path or its percent-decoded form starts with the prefix (`/admin` also matches `/%61dmin`; `/a%20b` matches the wire bytes `/a%20b`); dot-segments and `%2F` are not normalized. Empty = all paths. See "Path-scoped rules" below for which traffic a `path_prefix` rule can cover |
| `schemes` | string[] | Optional. Match transport confidentiality: `http` = plaintext, `https` = TLS. Only these two values are accepted. Empty = both |

All specified fields must match for a rule to apply (AND logic).

### Path-scoped rules

A connection (CONNECT, SOCKS5, plain-HTTP forward, `tcp_forwards`) is admitted
before any request path is known, so a rule with `path_prefix` is applied in two
steps:

- **Allow** `{hostname: X, path_prefix: "/api/"}`: the connection to X is admitted
  when the proxy will check the path of every request on it — HTTP/1.x, HTTP/2
  (including h2c), WebSocket (the upgrade request is path-checked) and gRPC /
  gRPC-Web (each call's path, e.g. `/pkg.Service/Method`). Each request
  is then checked with its path: `/api/x` reaches X, `/other` is answered
  403 `blocked_by: target_scope` (a native gRPC call fails with `grpc-status: 7`).
  Traffic on which no path is ever seen is refused:
  a TLS passthrough target (`tls_passthrough`), a `raw_passthrough_hosts` target,
  `tcp_forwards` with `protocol: raw` (`proxy_start` refuses the entry), and
  non-HTTP bytes inside a tunnel (the connection is closed and a raw Stream is
  recorded with `blocked_by: target_scope`; the upstream connection may already
  have been opened, but receives no client byte and none of its bytes reach the
  client). A raw tunnel that was opened while a
  host-only allow admitted X is closed when the scope is narrowed to the
  path-scoped allow (policy reload or this tool), exactly as a new one would be
  refused; HTTP connections to X stay open and each later request is checked
  with its path.
  `path_prefix: "/"` behaves the same way: it still requires a request path.
- **Deny** `{hostname: X, path_prefix: "/admin"}`: never refuses or closes a
  connection; it is enforced per request. It therefore does not cover TLS
  passthrough or raw traffic to X — deny the host itself for that.
  It matches the literal wire path (and its percent-decoded form) only —
  for HTTP and gRPC / gRPC-Web alike — so aliases a server may route to the
  same resource (`//admin`, `/./admin`, `/x/../admin`, `%2F` spellings) are
  not matched. A path deny is not a hard boundary; to confine traffic to
  some paths, use a path-scoped **allow** instead.

Every request is checked against both the host it names (`Host` / `:authority`)
and the host the connection actually reaches, each with the request path, so
naming another host in `Host` does not escape a path rule on the real target.

### Host headers and allow rules

The names a request carries — its authority (`Host` as parsed, HTTP/2
`:authority`), **every** `Host` header value (all casings, duplicates
included; HTTP/2's regular `host` header too) and, for an HTTP/1.x
absolute-form request-target (`GET http://name/path HTTP/1.1`), the URI's
authority — are checked as well, on live
traffic (gRPC and gRPC-Web calls included: their `:authority` / `Host` and every
`host` metadata value), after an intercept `modify_and_forward` or a Transform rule rewrites the
request, and in `resend_http` / `fuzz_http` (each variant, after positions are
applied). They are checked with a narrower allow rule than the host the
connection dials:

- **Deny rules always apply.** A request naming a denied host in any `Host`
  value is refused (`403`, `blocked_by: target_scope`), whatever it dials.
- **IP-literal allow → name not required in the allow list.** If the dialed host
  was admitted by an allow rule whose `hostname` is an IP address, a `Host` /
  authority naming another (non-denied) virtual host is sent as written. With
  `allows: [{hostname: "10.0.0.5"}]`, a CONNECT to `10.0.0.5:443` carrying
  `Host: intranet.local` is forwarded. This keeps same-IP different-vhost and
  Host-header injection testing possible.
- **Domain allow → name must be allowed too.** With
  `allows: [{hostname: "app.example"}]`, a request to `app.example` carrying
  `Host: other.example` is refused: the allow named hosts, not an address.
- This is evaluated per layer (Policy and Agent separately), so an agent allow
  rule that names domains narrows names even when the policy allows an IP.
- A `Host` value with a port that is not a decimal number in 1–65535
  (`db.internal:abc`) is refused while any rule is set.
- **Absolute-form request-target.** A server that receives
  `GET http://other.example/ HTTP/1.1` routes on `other.example` and ignores
  `Host`, and the proxy forwards the request-target as written — inside a
  CONNECT / SOCKS5 tunnel, or on a later request of a forward-proxy
  keep-alive connection. Its authority (userinfo stripped, the connection's
  transport scheme deciding the default port) is judged like a `Host` value;
  an authority that cannot be parsed, or that has more than one `@`, is
  refused while any rule is set. The request-target is never rewritten.

To stop a vhost from being reached on an allowed address, **deny** its name.


### What `schemes` means

`schemes` is a **transport confidentiality** axis, not an L7 application-protocol
axis. It is spelled with the `http` / `https` tokens because those are the names
operators already use for "plaintext" and "TLS", but it applies to every protocol
the proxy scopes:

- A WebSocket target is matched as `http` (`ws://`) or `https` (`wss://`). Writing
  `"schemes": ["ws"]` is rejected — the rule would never match anything.
- A raw TCP or gRPC target is matched the same way: `https` when the leg is
  TLS-terminated, `http` when it is cleartext.
- A `CONNECT` tunnel is matched as `https` even if it turns out to carry SMTP.

**A `schemes` condition narrows a rule in both directions.** A deny rule carrying
`"schemes": ["https"]` does not block the plaintext dial to the same host, and an
allow rule carrying `"schemes": ["https"]` does not permit one. Omit `schemes` when
you mean "this host, on any transport" — that is the safer default for deny rules.

**SOCKS5 targets are deliberately unmatchable by any `schemes`-bearing rule**: a
SOCKS5 `CONNECT` is scope-checked before the tunnel carries a single byte, so the
proxy does not yet know whether TLS follows. Scope such traffic by `hostname` /
`ports`, or scope the tunneled protocol instead.

The tunneled protocol *is* scoped with a scheme: once a SOCKS5 or `CONNECT`
tunnel carries traffic, the connection-level host check runs on it again with
the scheme of the client-facing leg — including raw TCP that matches no known
protocol (`http` when it is cleartext, `https` when the proxy terminated TLS on
it) and every `tcp_forwards` entry, `protocol: raw` included.

Two live-data-path admission gates do not observe the transport: SOCKS5
(blank scheme) and the `CONNECT` admission gate (always `https`); the tunneled
traffic behind them is re-checked as described above.

For HTTP requests (including WebSocket / SSE upgrade requests and HTTP/2), the
proxy matches `schemes` against the transport of the client's connection — TLS or not — not
a client-declared HTTP/2 `:scheme` (which may be absent or disagree with the
connection) and not a `scheme` set via intercept `modify_and_forward`. The
recorded request still shows the scheme exactly as the client declared it.

### How a deny shows up on the wire

| Traffic | What the client sees | Recorded |
|---|---|---|
| HTTP/1.x, HTTP/2 request | `403` with `X-Blocked-By: target_scope` | Stream with `blocked_by: target_scope`, `state: error` |
| Raw TCP (bytechunk — CONNECT / SOCKS5 tunnels carrying an unknown protocol, `raw_passthrough_hosts`, `tcp_forwards` with `protocol: raw` or an `auto` fallback to raw) | The connection is closed (EOF) when it settles on a raw relay, before any byte is relayed in either direction; none of the client's bytes reach the denied host and none of its bytes reach the client | One raw Stream with `blocked_by: target_scope`, `state: error` |
| Native gRPC call | The call fails with `grpc-status: 7` (PERMISSION_DENIED) and `grpc-message: blocked by target_scope`; the RPC ends, the connection stays open | Stream with `blocked_by: target_scope`, `state: error` |
| WebSocket message | The message is dropped; the connection stays open | Stream with `blocked_by: target_scope` |
| gRPC-Web call denied by the host the connection dials | Every message of the call is dropped; the connection stays open and the client gets no gRPC-Web response | Stream with `blocked_by: target_scope` |
| gRPC-Web call denied by its own request (path, `:authority` / `Host`, `host` metadata) | The call is aborted: its start is dropped, so no request byte reaches the upstream, and the HTTP/1.x connection is closed (HTTP/2: the stream is reset); the client gets no gRPC-Web status. A TCP (and TLS) connection to the dial target the connection was already admitted for may still be opened | Stream with `blocked_by: target_scope` |
| `tcp_forwards` target denied when `proxy_start` runs | `proxy_start` fails with an error naming the scope, port and target; nothing is bound | Nothing |
| `tcp_forwards` target denied when a client connects | Plaintext `protocol: http` / `websocket` / `sse`: `HTTP/1.1 403 Forbidden` with body `yorishiro-proxy: target blocked by scope`, then close. Every other protocol and every `tls: true` entry: the connection is closed with no byte (a TLS client's handshake fails). The target is never contacted | Nothing (Info log) |

A raw connection is closed rather than having single chunks dropped because a
byte stream has no message boundary to drop at: removing some bytes and relaying
the rest would hand the peer a corrupted stream. The check runs once, before the
relay starts, so an upstream that speaks first (an SMTP / FTP / IMAP banner)
delivers nothing to a client that has not written yet.

The check runs when the raw relay starts — for a CONNECT / SOCKS5 tunnel or a
`tcp_forwards` `auto` entry, after the inner bytes were classified — not at
connect time, so the denied host is still *contacted*: the upstream TCP
connection is already open when it runs, and on `raw_passthrough_hosts`, an unrecognised-ALPN
tunnel or a `tcp_forwards` entry with `upstream_tls` the upstream TLS handshake
(SNI included) has already completed too. A CONNECT admitted as `https` and
then denied by an `http`-scheme rule on its inner plaintext is a case that
reaches the denied host this way.

### `tcp_forwards` gate

A `tcp_forwards` entry has a fixed target, so its target is checked before the
proxy contacts it:

- **At `proxy_start`**: an entry whose target the scope denies is refused, and
  the whole `proxy_start` fails (the listener is rolled back) with an error that
  names the forward port, the target and the reason. This check is advisory —
  the scope can change later.
- **At every accept**: each new connection is checked before the client's TLS is
  terminated (`tls: true`) and before the upstream is dialed, on every
  `protocol`. A denied target receives nothing — no TCP connection, no TLS
  ClientHello / SNI, no HTTP/2 preface, no byte. This is the authoritative
  check: a deny added after the forward started (policy reload or this tool)
  refuses new connections while the forward port stays bound.
- **Live connections**: an admitted connection is re-evaluated with the same
  check on every policy reload and every `set_target_scope` /
  `update_target_scope`, and is closed when an identical new connection would
  be refused (see [Reloading the Policy Layer](#reloading-the-policy-layer-operator-only)).

The scheme of this check is the **upstream (dial) leg's**: `https` when
`upstream_tls` is true, `http` otherwise, whatever `tls` is. A `tls: true` forward
with a plaintext upstream therefore egresses as `http` and is refused by a deny
on `schemes: ["http"]`. Each envelope on the connection is still checked by the
connection-level host check with the client-facing leg's scheme (above), so on an
entry whose two legs differ, a deny matching either leg blocks the traffic.

The check uses the literal `target` host (no DNS resolution) and its port, which
must be a decimal number in 1-65535: a target whose port is a service name
(`db.internal:postgresql`), signed or out of range is refused at `proxy_start`
whether or not a scope is set, because the dialer would resolve a service name to
a port the check never saw. A denied connection
is not recorded as a flow; an Info line `tcp forward target blocked by scope` is
logged.

## Rate Limiting

Rate limits use the same two-layer architecture as target scope. The Policy Layer defines upper bounds (set via the policy file or config file; replaceable only by the operator's `SIGHUP` reload); the Agent Layer can set equal or stricter limits at runtime.

Requests that exceed rate limits receive a `429 Too Many Requests` response. At the connection-level gates -- an HTTP CONNECT tunnel request and the plain HTTP forward proxy -- that is `HTTP/1.1 429 Too Many Requests` with body `yorishiro-proxy: target blocked by rate limit`, after which the connection closes; no tunnel is opened and the target is not contacted. Elsewhere the response carries an `X-Blocked-By: rate_limit` header.

**Applicability**: Both Policy Layer and Agent Layer rate limits apply to **all** proxy traffic -- live proxied traffic (HTTP CONNECT tunnel, plain HTTP forward proxy, SOCKS5 tunnel, and every route of a `transparent_mode` listener) and MCP tool-initiated requests (the same list as for `target_scope`). The effective rate (the stricter of policy and agent) is shared across both paths.

**Transparent listener** (`transparent_mode: "redirect"`): the limit is checked once per connection, after the target scope check (a scope-refused connection consumes no token) and before any upstream contact; requests on a kept-alive connection are not re-checked. The per-host key is the **original-destination IP** (the dial target), so virtual hosts or CDN names served from one IP share one per-host bucket, separate from the CONNECT gate's bucket for the same name. A connection over the limit is refused as follows, and every refusal is recorded as an error Stream with `blocked_by: "rate_limit"`, `failure_reason: "rate_limit"`, `tags.route`, `tags.target` (original destination), `tags.rate_limit_type` (`global` / `per_host`) and `tags.rate_limit_effective_rps`, plus an Info log `transparent target blocked by rate limit`:

- Plain HTTP route: the same `HTTP/1.1 429 Too Many Requests` bytes as the CONNECT / forward gates, then the connection closes.
- TLS (both the MITM and the passthrough classes): the connection is reset before any TLS byte is written -- no 429 is sent inside TLS. The Stream is `tls-handshake` with `tags.name` = SNI and the client's JA3 / JA4 on its connection info.
- Other passthrough routes (server-first, opaque, h2c): the connection is reset with no byte written.

### `set_rate_limits`

Set Agent Layer rate limits. Omitted fields reset to 0 (no limit). This is full-replace semantics.

```json
{
  "action": "set_rate_limits",
  "params": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}
```

**Parameters:**
- **max_requests_per_second** (number, optional): Global rate limit in RPS. `0` means no global limit.
- **max_requests_per_host_per_second** (number, optional): Per-host rate limit in RPS. `0` means no per-host limit.

Returns: status, effective (merged Policy+Agent limits), agent (current Agent Layer values).

### `get_rate_limits`

Returns Policy and Agent Layer rate limits with the effective (merged) values.

```json
{
  "action": "get_rate_limits"
}
```

Response:

```json
{
  "policy": {
    "max_requests_per_second": 50,
    "max_requests_per_host_per_second": 20
  },
  "agent": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  },
  "effective": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}
```

## Diagnostic Budget

Diagnostic budgets limit the total number of requests and/or the session duration. When a budget is exhausted, the proxy automatically stops accepting new requests. Like rate limits, budgets use the two-layer architecture.

**Applicability**: Both Policy Layer and Agent Layer budgets apply to **all** proxy traffic -- transparent MITM traffic and MCP tool-initiated requests share the same request counter and duration timer. When the effective budget is exhausted, the proxy stops every listener regardless of how the next request would have arrived.

### `set_budget`

Set Agent Layer budget limits. Omitted fields reset to 0 (no limit). This is full-replace semantics.

```json
{
  "action": "set_budget",
  "params": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}
```

**Parameters:**
- **max_total_requests** (integer, optional): Maximum total requests for the session. `0` means no request count limit.
- **max_duration** (string, optional): Maximum session duration as a Go duration string (e.g. `"30m"`, `"1h"`, `"2h30m"`). `"0s"` means no duration limit.

Returns: status, effective (merged Policy+Agent limits), agent (current Agent Layer values).

### `get_budget`

Returns Policy and Agent Layer budgets with effective values and current usage.

```json
{
  "action": "get_budget"
}
```

Response:

```json
{
  "policy": {
    "max_total_requests": 5000,
    "max_duration": "2h"
  },
  "agent": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  },
  "effective": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  },
  "request_count": 142,
  "stop_reason": ""
}
```

- **request_count**: Number of requests made so far.
- **stop_reason**: Non-empty when the budget has been exhausted (e.g. `"max_total_requests exceeded"`, `"max_duration exceeded"`).

## SafetyFilter (Input Filter)

SafetyFilter is a **Policy Layer** mechanism that prevents destructive payloads from being sent to target systems. It inspects outgoing HTTP requests (body, URL, query string, headers) against a set of regex rules and blocks or logs matches before the request reaches the target.

SafetyFilter rules are **immutable at runtime** — they are defined in the configuration file and cannot be modified by AI agents. This ensures that safety boundaries remain enforced regardless of agent behavior.

**Applicability**: As a Policy Layer mechanism, the Input Filter applies to **all** proxy traffic -- transparent MITM traffic and MCP tool-initiated requests (see the [Applicability](#applicability) table under "Two-Layer Architecture").

### `get_safety_filter`

Returns the current SafetyFilter configuration and compiled rules (read-only).

```json
{
  "action": "get_safety_filter"
}
```

Response:

```json
{
  "enabled": true,
  "input_rules": [
    {
      "id": "destructive-sql:drop",
      "name": "DROP statement",
      "pattern": "(compiled regex)",
      "targets": ["body", "url", "query"],
      "action": "block",
      "category": "destructive-sql"
    }
  ],
  "immutable": true
}
```

- **enabled**: Whether SafetyFilter is active.
- **input_rules**: List of compiled input filter rules currently in effect.
- **immutable**: Always `true` — SafetyFilter rules cannot be changed at runtime.

### Rule Configuration

Rules are defined in the config file under `safety_filter.input`. Each rule can be a preset reference or a custom rule.

#### Presets

Built-in presets provide curated rule sets for common destructive patterns:

| Preset | Rules | Description |
|--------|-------|-------------|
| `destructive-sql` | 6 rules | DROP TABLE/DATABASE/INDEX/VIEW/SCHEMA, TRUNCATE TABLE, DELETE without WHERE, UPDATE WHERE 1=1, ALTER TABLE DROP, xp_ stored procedures |
| `destructive-os-command` | 5 rules | rm -rf, shutdown/reboot/halt/poweroff, mkfs, dd if=, Windows format |

#### Custom Rules

Custom rules require `id`, `pattern`, and `targets` fields. The action is inherited from the section-level `input.action` setting:

```json
{
  "id": "custom-api",
  "name": "Dangerous API endpoint",
  "pattern": "(?i)/api/v[0-9]+/(delete-all|reset)",
  "targets": ["url"]
}
```

### Targets

| Target | Description |
|--------|-------------|
| `body` | Request body content |
| `url` | Full URL string |
| `query` | Query string portion of the URL |
| `header` | Individual header values (use `header:Name` for a specific header) |
| `headers` | All header values concatenated |

### Actions

| Action | Description |
|--------|-------------|
| `block` | Reject the request with 403 status. The response includes `X-Block-Reason: safety_filter` header and a JSON body with violation details |
| `log_only` | Log the match but allow the request through (live proxy traffic and resend / fuzz / macro alike). Every matching rule (not just the first) is recorded on the stream as tag `safety_log_only:<rule_id>`, visible in `query` results — also when a later step (e.g. an intercept drop) blocks the request. Useful for testing rules before enforcement |

### Blocked Response Format

When SafetyFilter blocks a request at the proxy layer:

- **Status**: `403 Forbidden`
- **Header**: `X-Block-Reason: safety_filter`
- **Body**: JSON object with violation details (rule ID, rule name, and match location)

For a native gRPC call the RPC fails with `grpc-status: 7` (PERMISSION_DENIED) and `grpc-message: blocked by safety_filter`; the matched rule IDs travel comma-separated in the `x-yorishiro-matched-rules` trailer (bytes outside visible ASCII, `%`, and `,` inside an ID are percent-encoded). A blocked message in a bidi/client stream ends the whole RPC. gRPC-Web messages are dropped without a status.

When SafetyFilter blocks an MCP tool operation (resend, fuzz, intercept modify_and_forward, macro):

- **MCP error response** with violation details

## SafetyFilter (Output Filter)

The Output Filter is a **Policy Layer** mechanism that prevents sensitive information (PII) from being exposed to AI agents. When one of the MCP tools listed under [How It Works](#how-it-works) returns recorded or freshly fetched traffic to the AI agent, it inspects the covered fields of that tool response against a set of regex rules and masks matching content. Other tools return their data unmasked.

The Output Filter operates **only at the MCP boundary**. It never touches the wire: the proxied client (browser, curl, next hop) receives the upstream response exactly as observed, and the Flow Store always records the original, unmasked bytes. Masking is applied to a copy, only when an MCP tool returns data to the AI agent.

Output Filter rules are **immutable at runtime** -- they are defined in the configuration file and cannot be modified by AI agents.

**Applicability**: The Output Filter protects the AI agent's input boundary, not the upstream server or the proxied client. There is no Receive-direction filtering in the live pipeline: the pipeline's SafetyStep runs the Input Filter on the Send direction only, and response traffic is relayed to the client unmodified. To block destructive payloads bound for the target, use the Input Filter instead.

### How It Works

1. **Live traffic is not masked**: Responses relayed through the proxy reach the client byte-for-byte as received from upstream (HTTP/1.x, HTTPS CONNECT, HTTP/2, gRPC, WebSocket, SSE, raw TCP). The Output Filter is never invoked on the data path.
2. **MCP tool responses are masked**: Before a tool result is serialized for the AI agent, the following are masked:
   - `query` -- flow details (request/response headers, bodies, decoded bodies, raw bytes), `messages` entries, and `intercept_queue` entries (headers / trailers / gRPC metadata, bodies and payloads, and raw bytes; URL components, HTTP status reasons, WebSocket close reasons and `grpc-message` are not masked)
   - `resend_http` -- response headers and body
   - `resend_ws` -- the response frame payload
   - `resend_grpc` -- response DATA message payloads, the response start metadata (`start_metadata`) and the trailers (`end.trailers`), as `query` masks gRPC metadata (header-target rules; names, order and casing preserved); `grpc-message` (`end.message`) is **not** masked
   - `resend_raw` -- `response_bytes`: the concatenated response bytes exactly as received (not decompressed or dechunked), masked before base64 encoding. `response_size` still reports the wire (pre-mask) length
   - `macro` `run_macro` -- `kv_store` values (extracted values, `initial_vars` and `vars` alike; keys are not masked), by `body`-target rules only, whatever `source` the value was extracted from. `header` / `headers`-target rules are not applied, so a header value extracted with `source: header` is masked only if a `body`-target rule also matches it. Only the returned copy is masked: later steps of the macro receive the original values
   - `manage` `export_flows` -- inline export only, and only partially: `body`-target rules scan the serialized JSONL text, so plain-text fields (URL, header values, metadata) can be masked, but bodies and raw bytes are base64-encoded before masking and are effectively **not** masked; `header`-target rules are not applied. Exports written to a file are not masked at all. Use `query` for masked bodies.
3. **Raw Data Preserved**: The Flow Store always contains the original unmasked data for human review via the Web UI

**Coverage notes**:

- Patterns match the bytes exactly as the tool returns them. Content-Encoded (e.g. gzip, br, zstd) bodies are not decoded before masking, so a compressed body is effectively not masked. The exception is `query`'s decoded-body view (`body_decoded` / `request_body_decoded` / `response_body_decoded`), which is decoded first and then masked.
- Tools and fields not listed above return their data unmasked -- for example `manage` `export_flows` written to a file.
- `query` `messages` / `message_preview` `raw_bytes` (the wire bytes of a bodyless message) is masked as recorded, before the `body_max_bytes` cap, by `body`-target rules only. HTTP/1.x request heads are plaintext and are matched; HPACK-encoded HEADERS (HTTP/2, gRPC Start / End), permessage-deflate WebSocket frames, compressed gRPC messages and client-to-server (XOR-masked) WebSocket frames are effectively not masked. `header`-target rules are not applied to raw bytes.
- `resend_raw` truncates `response_bytes` at its response cap before masking, so a match that straddles the cap is cut off and may be returned partially unmasked.

### Output Rule Configuration

Output rules are defined in the config file under `safety_filter.output`. Each rule can be a preset reference or a custom rule.

#### PII Presets

Built-in presets provide curated rule sets for common PII patterns:

| Preset | Rules | Description |
|--------|-------|-------------|
| `credit-card` | 2 rules | Credit card numbers -- separated (1234-5678-9012-3456) and continuous (1234567890123456). Luhn validation is applied to the continuous format only |
| `japan-my-number` | 1 rule | Japanese My Number (12-digit individual number) with check digit validation |
| `email` | 1 rule | Email addresses (user@example.com) |
| `japan-phone` | 2 rules | Japanese phone numbers -- mobile (090-1234-5678) and landline (03-1234-5678) |

#### Validators

Some presets use **Validator** functions for additional verification beyond regex matching, reducing false positives:

- **credit-card (continuous)**: Luhn algorithm check -- only masks digit sequences that pass the Luhn checksum
- **japan-my-number**: Check digit validation -- only masks 12-digit sequences with a valid My Number check digit

Rules with Validators use a **slow path** (individual match validation) instead of the **fast path** (bulk `ReplaceAll`), but provide significantly better precision.

#### Custom Output Rules

Custom rules require `id`, `pattern`, and `targets` fields; `name` and `replacement` are optional. Rules have no per-rule `action` in the config file: the section-level `output.action` (`mask` by default, or `log_only`) applies to every rule in the section. `replacement` is honored per rule -- for a custom rule it is the mask string (an omitted `replacement` replaces matches with the empty string), and on a preset reference it overrides the preset's default replacement.

```json
{
  "id": "custom-api-key",
  "name": "API key pattern",
  "pattern": "(sk-[a-zA-Z0-9]{32,})",
  "targets": ["body"],
  "replacement": "[MASKED:api_key]"
}
```

### Output Filter Actions

| Action | Description |
|--------|-------------|
| `mask` | Replace matched content with the replacement string. This is the primary action for output rules |
| `log_only` | Log the match but return data unmodified. Useful for testing rules before enforcement |

### Replacement Strings

Replacement strings support regex capture group references:

| Syntax | Description |
|--------|-------------|
| `[MASKED:credit_card]` | Static replacement (used by credit-card preset) |
| `$1` | First capture group from the regex pattern |
| `$2` | Second capture group |
| `${name}` | Named capture group |

### Output Filter Targets

Output rules typically use `body` as the target. Header-level masking is also supported:

| Target | Description |
|--------|-------------|
| `body` | Response body content |
| `header` | Individual header values (use `header:Name` for a specific header) |
| `headers` | All header values |

## Protocol Support Matrix

| Protocol | Input Filter | Output Filter | Notes |
|----------|-------------|---------------|-------|
| HTTP/1.x | Supported | Supported | Full support |
| HTTP/2 | Supported | Supported | Full support |
| gRPC | Supported | Supported | Via HTTP/2 |
| WebSocket | Partial | Supported | Input: every client→upstream frame (all opcodes) is checked against `body` (incl. the built-in presets), `payload` and `opcode` rules; `url` / `query` / `headers` rules apply to the Upgrade request (HTTP Input Filter), not per frame; `header` is not evaluated on the live path; fragment bypass possible. Output: masks frame payloads in `query` / `resend_ws` results |
| SOCKS5 | N/A | N/A | Transport layer only (filters apply after HTTP delegation) |
| Raw TCP | N/A | Supported | Binary stream. Output: masks raw bytes in `query` results and `response_bytes` in `resend_raw` results, as received (no decoding) |

## WebSocket Safety Filter

SafetyFilter is applied to WebSocket traffic on a per-frame basis. Every frame is evaluated regardless of opcode (text, binary, continuation, ping, pong and close alike; a close frame's payload includes its 2-byte status code).

- **Upgrade request**: The WebSocket handshake (HTTP/1.1 `Upgrade` request or HTTP/2 extended CONNECT) is an ordinary Send-direction HTTP request, so the HTTP Input Filter evaluates it first -- `url`, `query` and `headers` rules (including the presets' `url` / `query` targets) match here. `header` (bare or `header:Name`) is not evaluated on the live path: bare `header` is accepted by config validation but never matches, and `header:Name` is rejected at startup; bare `header` is only checked for `resend_ws` / `fuzz_ws` (below). With `block` (the default action), a match answers the handshake with `403 Forbidden` and no WebSocket connection is established; with `log_only` the match is logged and the handshake proceeds.
- **Send direction (Input Filter, per frame)**: For each client→upstream frame, `body` and `payload` rules match the frame payload (`body` is an alias of `payload`, as for gRPC, so the built-in presets apply; a violation is reported with target `payload`), and `opcode` rules match the opcode as a hex string (e.g. `0x1` text, `0x8` close). With permessage-deflate, a single-frame compressed message is matched on its decompressed payload; in a fragmented compressed message the non-final fragments are matched on their compressed bytes and the final (FIN) frame on the whole reassembled, decompressed message. If a rule matches with `block` action, only that frame is silently dropped (not forwarded) and the connection remains open; later frames -- including continuation frames of the same fragmented message -- are still evaluated and forwarded on their own.
- **MCP-initiated frames (`resend_ws` / `fuzz_ws`)**: These are checked by the MCP-plane engine, not the per-frame engine above. `body` rules (including the presets) are matched against the frame payload, and `url` / `query` / `header` / `headers` rules against the Upgrade URL and headers; `payload` and `opcode` rules are currently **not** evaluated there. Use `body` (or a preset) for a rule that must cover both live traffic and resend / fuzz.
- **Output Filter (MCP boundary only)**: Frames relayed through the proxy are never masked, in either direction. When a recorded or resent frame is returned to the AI agent (`query`, `resend_ws`), `FilterOutput` masks matching content in the payload copy of that tool response. The original unmasked payload is preserved in the Flow Store.

### Applicable Rule Targets

WebSocket frames do not carry HTTP headers. The applicable rule targets differ between Input Filter and Output Filter:

| Target | Input Filter | Output Filter | Reason |
|--------|-------------|---------------|--------|
| `body` | Yes | Yes | Input Filter: alias of `payload` -- matches the frame payload (live frames and `resend_ws` / `fuzz_ws`). Output Filter: masks the payload copy returned by `query` / `resend_ws` |
| `payload` | Yes (live frames only) | No | Input Filter: matches the frame payload of proxied frames; not evaluated for `resend_ws` / `fuzz_ws`. Not an accepted Output Filter target (config validation rejects it); use `body` |
| `opcode` | Yes (live frames only) | No | Input Filter: matches the opcode as a hex string (`0x0`-`0xA`); not evaluated for `resend_ws` / `fuzz_ws` |
| `url` | Upgrade request only | No | Not evaluated per frame. The HTTP Input Filter matches it on the Upgrade request (403 on match); `resend_ws` / `fuzz_ws` check it against the Upgrade URL |
| `query` | Upgrade request only | No | Same as `url`, for the query string of the Upgrade request URL |
| `headers` | Upgrade request only | No | WebSocket frames have no HTTP headers; matched on the Upgrade request's headers only (live HTTP Input Filter and `resend_ws` / `fuzz_ws`) |
| `header` | `resend_ws` / `fuzz_ws` only | No | Not evaluated on the live path (bare `header` never matches; `header:Name` is rejected at startup). `resend_ws` / `fuzz_ws` check it against the Upgrade headers. Use `headers` for live traffic |

### Known Limitations

1. **Fragment bypass**: Filters are applied per-frame, not per-message. Each frame's payload of an uncompressed fragmented message, including continuation frames (opcode 0x0), is inspected on its own, so a pattern split across frame boundaries (e.g., `DROP` in one frame and ` TABLE` in the next) will not be detected. Fragmented permessage-deflate messages are matched as a whole only on their FIN frame. By then the preceding fragments have already been forwarded, and a block drops only the FIN frame. The proxy then stops tracking the message, so a client can re-send a final continuation frame (matched only on its raw compressed bytes) and complete the blocked message upstream. Do not rely on the Input Filter to stop fragmented compressed messages. A follow-up tracks per-message matching.
2. **Blocking one fragment does not block the message**: Only the matching frame is dropped; the remaining fragments of the same message are forwarded. A follow-up tracks changing this.
3. **No per-frame URL / header matching**: `url`, `query`, `header` and `headers` rules never match individual frames. `url`, `query` and `headers` are enforced once, on the Upgrade request; `header` is not enforced on live traffic at all (bare `header` is checked only for `resend_ws` / `fuzz_ws`).

## Error Handling

- **Policy boundary violation**: Setting agent allows outside policy scope returns an error with the offending hostname and current policy allows.
- **Policy deny removal**: Attempting to remove a policy deny rule via `update_target_scope` returns an error stating that policy rules are immutable.
- **Rate limit boundary violation**: Agent rate limits cannot exceed Policy rate limits. If the policy sets 50 RPS, the agent cannot set 100 RPS.
- **Budget boundary violation**: Agent budget limits cannot exceed Policy budget limits.
- **Enforcement mode**: `"open"` when no rules exist in either layer; `"enforcing"` when any rule is configured.
