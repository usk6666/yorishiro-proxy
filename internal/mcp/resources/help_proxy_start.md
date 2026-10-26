# proxy_start

Start (or initialize) the proxy server with optional configuration. The proxy listens on the specified address and begins intercepting HTTP/HTTPS/SOCKS5 traffic.

**Reset semantics (USK-407)**: each `proxy_start` call fully resets all prior session settings to the values supplied in the request. Fields omitted from the request revert to their defaults — including `capture_scope`, `tls_passthrough`, `intercept_rules`, `auto_transform`, `tcp_forwards`, SOCKS5 auth, TLS fingerprint, and connection/timeout limits. Use `proxy_start` for first-time startup or session initialization. For in-session partial updates to a running listener (adding a single rule, changing one timeout, etc.), use the `configure` tool instead — call `docs(topic="configure")`.

## Parameters

### name (string, optional)
Listener name for multi-listener support. Allows running multiple simultaneous listeners with different names.
- Default: `"default"`

### listen_addr (string, optional)
TCP address the proxy listener (HTTP, HTTPS via CONNECT, and SOCKS5 on the same port) binds to.
- Default: `"127.0.0.1:8080"`
- Format: `"host:port"`. The host must be an IP literal or the literal `localhost`: loopback (`"127.0.0.1:9090"`, `"[::1]:8080"`), all interfaces (`"0.0.0.0:8080"`, `"[::]:8080"`), or one specific interface address (`"10.0.0.5:8080"`, `"[fe80::1%eth0]:8080"`)
- To listen on all interfaces, write `0.0.0.0` or `[::]` explicitly — an empty host (`":8080"`) is rejected
- `0.0.0.0` binds IPv4 only; `[::]` is the dual-stack wildcard and accepts IPv4 as well as IPv6 connections (write firewall rules for both families when using `[::]`). An IPv4-mapped literal such as `[::ffff:0.0.0.0]` is treated as the IPv4 address it maps and binds IPv4 only
- Host names other than `localhost` are rejected (the bound interface must not depend on DNS), as are legacy IPv4 spellings such as `127.1`
- The port must be a decimal number 0-65535 (`0` = kernel-assigned); service names such as `http` are rejected
- **A non-loopback address makes the proxy an open proxy**: there is no client authentication, so any host that can route to the address can use it. Access control is the network side (firewall / nftables) plus the `target_scope` Policy layer — see `docs(topic="security")`, section "Listener Exposure". When the listener binds a non-loopback address the server logs one `Warn` line (`proxy listener bound to non-loopback address`) at start
- `tcp_forwards` listeners inherit this listener's bound host (a `0.0.0.0` listener exposes its forwards on `0.0.0.0` too; a `[::1]` listener puts them on `::1`)
- A bind that overlaps another running listener or forward (same non-zero port, and the same host or either host `0.0.0.0` / `::`) is rejected before binding

### upstream_proxy (string, optional)
Upstream proxy URL to route all outgoing traffic through.
- Supported schemes: `http://host:port` (HTTP CONNECT proxy), `socks5://host:port` (SOCKS5 proxy)
- Authentication: `http://user:pass@host:port`, `socks5://user:pass@host:port`
- If omitted, traffic is sent directly to the target
- Takes precedence over HTTP_PROXY/HTTPS_PROXY environment variables

### tls_passthrough (array of strings, optional)
Domain patterns that bypass TLS interception (no MITM). Useful for certificate-pinned services.
- Exact match: `"pinned-service.com"`
- Wildcard: `"*.googleapis.com"`

### intercept_rules (array of intercept rules, optional)
Rules for intercepting requests/responses. If omitted, no intercept rules are active.

Each intercept rule has:
- **id** (string, required): Unique rule identifier.
- **enabled** (boolean, required): Whether the rule is active.
- **direction** (string, required): `"request"`, `"response"`, or `"both"`.
- **conditions** (object, required): Matching criteria (all conditions are AND-ed):
  - **host_pattern** (string, optional): Regex pattern for hostname matching (port excluded).
  - **path_pattern** (string, optional): Regex pattern for URL path matching.
  - **methods** (array of strings, optional): HTTP method whitelist (case-insensitive).
  - **header_match** (object, optional): Maps header names to regex patterns (AND logic).

Multiple rules use OR logic: a request/response is intercepted if any enabled rule matches.

### tcp_forwards (object, optional)
Maps local listen ports to upstream forwarding configurations for TCP forwarding with protocol detection.

Each entry maps a local port number (string key) to either:
- A **string** value `"upstream_host:port"` (legacy format, treated as raw TCP forwarding)
- A **ForwardConfig object** with the following fields:
  - **target** (string, required): Upstream address in `"host:port"` format (e.g. `"api.example.com:50051"`). The port must be a decimal number in 1-65535; a service name (`"db.internal:postgresql"`) is rejected, so the port the target scope checks is the port that is dialed.
  - **protocol** (string, optional): Expected protocol for L7 parsing. Default: `"auto"` (peek-based detection).
    Valid values: `"auto"`, `"raw"`, `"http"`, `"http2"`, `"grpc"`, `"websocket"`, `"sse"`
    For server-speaks-first targets (SMTP, FTP, MySQL, IMAP, POP3), use `"raw"`: `"auto"` waits up to 5 s for the client's first bytes before falling back to raw, so the server's greeting is delayed by that peek.
  - **tls** (boolean, optional): Enable client-side TLS MITM termination on the forwarded listen port. Default: `false`.
    When true, the proxy presents a dynamically-issued certificate to the local client and terminates TLS before applying L7 parsing.
  - **upstream_tls** (boolean, optional): Enable upstream-dial TLS encryption to `target`. Default: `false`.
    When true, the proxy wraps the upstream-direction connection in TLS (using the global TLS fingerprint, SNI derived from `target`, and the configured verification / client-cert settings).
  - **upstream_insecure_skip_verify** (boolean, optional): Per-entry override: skip upstream TLS certificate verification for this forward. Default: inherits global `insecure_skip_verify`.
    Useful for MITM-debugging local upstreams whose self-signed certs lack SAN entries for the dialled host/IP (e.g. `moul/grpcbin`). Scoped per `tcp_forwards` entry and independent of the CONNECT MITM `tls_passthrough` path.

`tls` and `upstream_tls` are **independent** and are never inferred from `target`'s scheme or port:

| tls   | upstream_tls | Client wire | Upstream wire | Typical use case                              |
|-------|--------------|-------------|---------------|-----------------------------------------------|
| false | false        | plaintext   | plaintext     | Raw L4/L7 forwarding (default)                |
| true  | false        | TLS         | plaintext     | TLS termination only (downstream offload)     |
| false | true         | plaintext   | TLS           | Plaintext client → TLS-only upstream          |
| true  | true         | TLS         | TLS           | Full MITM: terminate then re-encrypt upstream |

- If omitted, TCP forwarding is not configured
- Both legacy string format and structured ForwardConfig can be mixed in the same object
- **Target scope**: every `target` is checked against `target_scope` (Policy and Agent layers). An entry whose target is denied fails the whole `proxy_start` (nothing stays bound). The check repeats on every accepted connection before the target is contacted, and open connections are closed when a scope change denies their target. The scheme checked is the upstream leg's (`https` iff `upstream_tls`). See `docs(topic="security")`, section "`tcp_forwards` gate".

### tls_fingerprint (string, optional)
TLS ClientHello fingerprint profile for upstream connections.
- `"firefox"` (default): Mimic Firefox browser TLS fingerprint (camoufox coherence).
- `"chrome"`: Mimic Chrome browser TLS fingerprint.
- `"safari"`: Mimic Safari browser TLS fingerprint.
- `"edge"`: Mimic Edge browser TLS fingerprint.
- `"random"`: Select a random browser fingerprint per connection.
- `"none"`: Use standard Go crypto/tls (no fingerprint mimicry).

This helps evade JA3/JA4-based bot detection during vulnerability assessments.

### socks5_auth (string, optional)
SOCKS5 authentication method.
- `"none"` (default): SOCKS5 clients connect without authentication.
- `"password"`: Require username/password authentication (RFC 1929).
- When set to `"password"`, `socks5_username` and `socks5_password` are required.

### socks5_username (string, optional)
Username for SOCKS5 password authentication.
- Required when `socks5_auth` is `"password"`.
- Ignored when `socks5_auth` is `"none"`.

### socks5_password (string, optional)
Password for SOCKS5 password authentication.
- Required when `socks5_auth` is `"password"`.
- Ignored when `socks5_auth` is `"none"`.

### client_cert (string, optional)
Path to a PEM-encoded client certificate for mTLS with upstream servers (global).
- Must be used together with `client_key`
- If omitted, no client certificate is presented

### client_key (string, optional)
Path to a PEM-encoded client private key for mTLS with upstream servers (global).
- Must be used together with `client_cert`
- If omitted, no client certificate is presented

### max_connections (integer, optional)
Maximum number of concurrent proxy connections.
- Default: `512`
- Range: 1-100000
- Connections refused at the cap are reported in `query` `status` → `connection_rejections` and as flows with `blocked_by: "capacity"`.
- Each connection costs file descriptors; before raising it (e.g. for a transparent-mode gateway, where every redirected connection counts), see "Connection cap and file descriptors" under "Transparent mode" below.

### max_concurrent_streams (integer, optional)
HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to clients on the inbound (proxy-acting-as-server) Layer.
- Default: `500` (USK-862 bumped 100 → 500 to cover high-multiplexing pages such as 200-parallel image fetches)
- Range: 1-65535
- Omit to inherit the boot-time value set via the `-max-concurrent-streams` CLI flag or `YP_MAX_CONCURRENT_STREAMS` env var; the H2 Layer default of 500 applies when none is set.
- Streams beyond this cap are rejected with `RST_STREAM(REFUSED_STREAM)` per RFC 9113 §5.1.2.
- Applies only to the inbound (client-facing) Layer; the outbound (upstream) Layer continues to honour the peer's advertised limit.

### peek_timeout_ms (integer, optional)
Timeout in milliseconds for protocol detection on new connections.
- Default: `30000` (30 seconds)
- Range: 100-600000

### request_timeout_ms (integer, optional)
Timeout in milliseconds for receiving a client's request head: each HTTP/1.x request line + header section (from the request's first byte, on every keep-alive request), the `CONNECT` request, and the client-side TLS MITM handshake. The request body is not covered. A client that misses it is disconnected without a response (the plain-HTTP forward target peek answers 400); the event is recorded as an error flow with `failure_reason` `request_head_timeout` (HTTP/1.x request head or forward peek), `connect_request_timeout` (CONNECT request) or `client_tls_error` with `tags.phase = "tls_handshake"` (TLS handshake) — see `query`. Idle client keep-alive connections are closed after `client_idle_timeout_ms` (or `request_timeout_ms`, if longer). See `configure` for the full list.
- Default: `60000` (60 seconds)
- Range: `0` (disabled) or 100-600000
- Omitted: the current value is kept (a value set by `configure` survives a restart). Before this change `proxy_start` reset it to 60000.

`0` disables these deadlines (including the inner and forward peeks, which would otherwise fall back to their own 5 s / 30 s defaults) and, on the transparent plain-HTTP route, the fixed 30 s pre-dial read of the first request head. A disabled bound lets a slow or silent client hold its connection slot indefinitely, up to `max_connections`. `peek_timeout_ms` (protocol detection) is separate and stays in force — if you type requests by hand (e.g. `nc`), raise it too. HTTP/2 connections are not covered.

### client_idle_timeout_ms (integer, optional)
How long an HTTP/1.x client keep-alive connection waits for the first byte of the next request before the proxy closes it. Range: `0` (disabled) or 100-600000; default `120000` (120 s).

When `request_timeout_ms` is also enabled the wait is the longer of the two; with only one of them enabled, each bounds only its own phase (this value the wait for the first byte, `request_timeout_ms` the rest of the head). Values below `115000` can race Firefox, which reuses keep-alive connections for up to 115 s: the proxy may close a connection just as the browser sends its next request on it. On an HTTP/2 client connection the same value bounds how long the connection may stay open with no open stream (PING frames do not extend it; an open stream, such as a gRPC stream, SSE response or WebSocket, holds it open indefinitely): the proxy then sends `GOAWAY(NO_ERROR)` and closes the connection. A request racing that GOAWAY is above its last stream id, so the client retries it on a new connection — the Firefox caveat above applies to HTTP/1.x only. Omitted: the current value is kept. Changes apply to the next request (HTTP/2: the next idle period).

**Config file**: both `request_timeout_ms` and `client_idle_timeout_ms` can also be set at the top level of the `-config` file, with the same meaning and range (`0` = disabled, omitted = the default). An out-of-range value stops the server at startup. The file sets the value the server boots with — `query` `status` reports it before the first `proxy_start` — and it applies to every listener (including `tcp_forwards`) until `configure` or `proxy_start` changes it; nothing re-applies the file afterwards (a `proxy_start` that omits the field keeps the current value, and a `SIGHUP` policy reload does not apply it). Restart the process to return to the file's value.

### transparent_mode (string, optional)
Listener mode.
- `none` (default when nothing is configured): the explicit proxy (CONNECT / SOCKS5 / plain-HTTP forward).
- `redirect`: a transparent egress gateway. The listener accepts TCP connections an nftables / iptables `REDIRECT` rule diverted to it and relays each one to its **original destination** (`getsockopt SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`). Linux only; elsewhere `proxy_start` fails. See "Transparent mode (egress gateway)" below.
- Omitted: inherits the config-file `transparent_mode`.
- Cannot be combined with `tcp_forwards` or `socks5_auth: "password"`.

### transparent_peek_timeout_ms (integer, optional)
Transparent mode only: how long the listener waits for the client's first bytes before treating the connection as server-first (SMTP / FTP / MySQL banner) and relaying it.
- Default: `1000`
- Range: 100-600000

### auto_transform (array of transform rules, optional)
Auto-transform rules for automatic request/response modification at startup. Same format as the `configure` tool's auto_transform rules.
- If omitted, no auto-transform rules are active

### capture_scope (object, optional)
Recording-only observability filter. Limits which flows are persisted to the flow store **without altering wire transmission** — out-of-scope traffic is still proxied normally, it is just not stored.

Use `capture_scope` to suppress noise from third-party CDNs / analytics / fonts during browser-driven sessions, keeping the flow store and AI-agent context window focused on the assets under test. Distinct from `target_scope` (transmission gate, configured via the `security` tool): blocking with `target_scope` would break page rendering whenever a tested page also fetches from out-of-scope hosts.

Each rule is AND-evaluated across `hostname` / `url_prefix` / `method`; at least one field per rule must be non-empty. `excludes` are evaluated before `includes`. Empty `includes` means "all flows are eligible". `*.example.com` wildcard matches subdomains but NOT the apex `example.com`.

Per-protocol matching of `url_prefix` / `method`:

- **HTTP/1.x and HTTP/2 envelopes** — method and path are matched directly against the request line / `:path`.
- **gRPC envelopes** — the request-side `GRPCStart` envelope carries the HTTP/2 `:path` value (`/Service/Method`) and an implicit `:method = POST`, so `url_prefix` and `method` rules match against gRPC streams. Example: `{"url_prefix": "/hello.HelloService/"}` in `excludes` will skip every RPC under that service while still recording other RPCs on the same connection. A malformed `:path` that leaves Service or Method empty does not synthesize a partial path, so `/Service/` cannot spuriously prefix-match.
- **WebSocket frame envelopes and SSE event envelopes** — individual frames / events carry no method/path, so `url_prefix` and `method` rules do not match against them. The initial HTTP upgrade envelope IS subject to those rules, and the recording decision is cached per-stream and applied to subsequent frames — set the rule on the upgrade request to capture an entire WS / SSE stream.
- **Raw TCP envelopes** — no method/path; `url_prefix` and `method` rules never match. Use `hostname` (resolved from the CONNECT/SOCKS5 target or TLS SNI) to scope raw TCP recording.

Blocked flows (target_scope deny / rate_limit / safety_filter blocks) are recorded by their respective recorder paths; capture_scope governs only the normal Pipeline-Record code path.

Example:
```json
{
  "capture_scope": {
    "includes": [
      {"hostname": "api.target.com"},
      {"hostname": "*.target.com", "url_prefix": "/api/"}
    ],
    "excludes": [
      {"hostname": "static.target.com"},
      {"url_prefix": "/healthz"}
    ]
  }
}
```

## Transparent mode (egress gateway)

`transparent_mode: "redirect"` makes the listener the egress gateway of the Worker hosts an agent operates, so all of their TCP traffic is audited. nftables decides at SYN time, before any byte is known, so **all TCP** is redirected and the proxy routes each connection by its first bytes:

| First client bytes (within `transparent_peek_timeout_ms`) | Route | Recorded |
|---|---|---|
| A complete HTTP/1.x request line start (`GET `, `POST `, ...) | L7 HTTP/1 (full Pipeline: scope, safety, plugins, intercept, transform) | Full flows incl. raw bytes. Upstream = original destination, never the `Host` header. |
| `0x16` (TLS ClientHello) offering ALPN `h2` and/or `http/1.1` | TLS MITM under the SNI → L7 HTTP/1 or HTTP/2 (full Pipeline) | Full flows incl. decrypted raw bytes, `tags.sni`, TLS snapshot incl. JA3 / JA4 |
| `0x16` with no ALPN extension | TLS MITM; then the decrypted bytes decide: the client sends an HTTP/1.x request → L7 HTTP/1, anything else (server speaks first, opaque) → raw | Full flows / decrypted raw bytes |
| `0x16` offering only other ALPN values (`imap`, `acme-tls/1`, ...), or a ClientHello the proxy cannot parse (over 4096 bytes, split across records, malformed) | Passthrough (no MITM) | Metadata: SNI, ALPN offers (wire order), JA3, JA4 |
| Nothing (server speaks first) | Passthrough | Metadata; if the client's first byte after the deadline is `0x16`, SNI / ALPN / JA3 / JA4 are recorded with `route: late_tls` |
| HTTP/2 prior-knowledge preface | Passthrough (`route: h2c`) | Metadata |
| Anything else | Passthrough (`route: opaque`) | Metadata |

Each client connection gets exactly one upstream connection to its original destination, dialled only after the route and the scope decision; through an `upstream_proxy` the proxy sends `CONNECT <original-dst-ip>:<port>`.

**Every transparent Stream carries `tags.original_dst`** — the original destination as `ip:port` (`[ipv6]:port` for IPv6) — on every route: L7 HTTP/1 and HTTP/2, TLS MITM (next to `tags.sni`, which may name something else), raw, passthrough, and refusal / dial-failure / proxy-closed request-head audit Streams. The one exception is a `max_connections` capacity rejection (`blocked_by` `capacity`), which does not carry `tags.original_dst`. `server_addr` is the upstream socket's peer, so through an `upstream_proxy` it is the proxy's address and `tags.original_dst` is the only place the real destination is recorded. `query` `filter.host` matches it.

**TLS MITM**: the upstream is dialled at the original destination IP:port with the client's SNI as the TLS name; the client's ALPN offer is forwarded upstream verbatim (wire order) and the client is advertised the upstream's pick — a no-ALPN client stays no-ALPN on both legs (that upstream leg is dialled with standard Go crypto/tls, not the `tls_fingerprint` profile, whose browser ClientHello would carry its own ALPN offer). The Worker must trust the proxy CA. The port does not matter (HTTPS on any port is decrypted). Without SNI the MITM certificate carries the destination IP as an IP SAN and no SNI is sent upstream (an upstream certificate without that IP SAN then fails verification unless upstream verification is off). A client that rejects the MITM certificate (certificate pinning, CA not installed) fails — there is no automatic passthrough fallback — and leaves a `tls-handshake` Stream with `failure_reason: "client_tls_error"`, `tags.name` = SNI, `tags.error`, and the client's JA3 / JA4 on its connection info; an upstream TLS failure is recorded the same way as `upstream_tls_error`. An upstream TCP dial failure resets the client (`transparent_dial_failed`). SNIs on the TLS passthrough list are passed through; `raw_passthrough_hosts` (matched against the SNI) are MITM'd as raw bytes. Connections to the same IP with different SNIs never share an upstream connection (the HTTP/2 pool is keyed by the TLS name too). Known limitations: a no-ALPN client's upstream ClientHello therefore has Go's fingerprint, not the `tls_fingerprint` profile's; when that HTTP/1 upstream connection is closed between requests, the replacement connection offers `http/1.1` with the `tls_fingerprint` profile; an IP-literal SNI sent by the client is not forwarded upstream; an ECH client presents its outer (public) SNI and fails as `client_tls_error`.

**Passthrough records no payload bytes** — one Stream per connection (`protocol` `raw` or `tls-handshake`, `tags.transparent: "passthrough"`, `tags.route`, `tags.target` and `tags.original_dst` = original destination) with one metadata flow (`bytes_client_to_upstream`, `bytes_upstream_to_client`, `sni`, `alpn_offers`, `client_ja3`, `client_ja4`, `outcome`). Use a packet capture for the bytes. The Pipeline and the plugin payload hooks do **not** run on passthrough connections; only `connection.on_connect` / `on_disconnect` fire. STARTTLS and TLS that starts after the peek deadline are relayed without decryption.

**Rejected connections**: a connection whose original destination cannot be read (no conntrack entry) or is the listener's own address (a client that dialled the proxy directly) is closed with a Warn log (at most one per 10 s per listener; the rest at Debug), and so is the proxy's own upstream dial when it is REDIRECTed back (`transparent loop`). Raise `max_connections` (up to 100000) for a gateway; the default 512 applies. Rate limits (`set_rate_limits` / Policy Layer) apply per connection on every route, keyed by the original-destination IP: plain HTTP over the limit gets a `429`, every other route (TLS included) is reset; the refusal is recorded with `blocked_by: "rate_limit"` (see the security help's "Rate Limiting").

**Connection cap and file descriptors**: `max_connections` is checked right after `accept`, before the route is known, so every transparent route (L7 HTTP/1, TLS MITM, passthrough, h2c, opaque) shares the one per-listener cap, and a passthrough connection holds its slot for the whole relay. Over the cap, plain HTTP/1 gets a `503` and every other route is closed; the refusal is counted in `query` `status` → `connection_rejections` and, for a target inside `capture_scope`, recorded as an error Stream with `blocked_by: "capacity"` (at most about 10 per second, bursts of 100; the rest are only counted, see the query help's `connection_rejections`). Size the cap against the process's open-file limit (`RLIMIT_NOFILE`):

- Each admitted connection uses about 2 file descriptors (client + upstream; a pooled HTTP/2 upstream may be shared, and an HTTP/1 upstream redial briefly adds one). A body spilled to disk adds a temp file while it is live. A refused connection holds 1 for up to about 1 s (up to about 6 s if its `503` write blocks) and does not count against the cap, so a refusal burst can hold many at once. The process itself needs a few dozen (listeners, the flow database and its WAL files, logs, the MCP HTTP server).
- The Go runtime raises the soft limit to the hard limit at startup, so raise the **hard** limit: systemd `LimitNOFILE=`, `docker run --ulimit nofile=<soft>:<hard>`, or `/etc/security/limits.conf` (applies only when the proxy is started from a PAM login session, not to systemd services or containers; check with `cat /proc/<pid>/limits`).
- The cap applies separately to every listener and every TCP forward, all sharing the one process limit, so keep `max_connections` ≤ (hard limit − 1024) / (2 × (listeners + TCP forwards)) — for example a hard limit of 65536 with one listener allows about 32000; 1048576 allows the 100000 maximum for up to 5 listeners and forwards. The 1024 headroom must also cover in-flight refusals and concurrently spilled bodies (one temp file per spilled body, per stream on HTTP/2, where `max_concurrent_streams` defaults to 500 per connection); leave more margin if you expect bursts.
- Running out of file descriptors currently stops the listener from accepting, silently and until the proxy is restarted, so keep the cap below the budget rather than relying on it. `configure` `max_connections` changes the cap live.

### Target scope on a transparent listener

`target_scope` is checked at three points: the original destination (when the route is known, before any upstream contact), the TLS SNI (after the ClientHello, before the dial), and every HTTP request's `Host` / `:authority` / absolute-form authority (on plain HTTP the first request's before the dial; on TLS MITM, and for later requests, before they are forwarded). Deny rules on any of them always block (HTTP gets a `403`, other routes are closed; the refusal is recorded with `blocked_by: "target_scope"`). Allow rules:

- An allow rule matching the original destination's IP admits the connection; SNI / `Host` are then deny-only.
- Otherwise a **name** may admit it: the SNI (TLS) or every request's `Host` (HTTP) must match an allow rule **and** resolve, via the proxy host's DNS, to the original destination IP (`failure_reason` `name_not_bound_to_original_dst` / `name_resolution_failed` when not). The Worker controls SNI / `Host`; the DNS binding stops it from naming an allowed host to reach an arbitrary IP. Wildcard rules work because the observed name is resolved. Run the proxy host on the same DNS server the Worker is allowed to use — CDN, geo or round-robin answers can otherwise differ and deny; IP allow rules avoid that. With an `upstream_proxy` the binding still uses the proxy host's resolver. A failed lookup denies.
- A TLS MITM connection admitted by its SNI still checks every HTTP / WebSocket request's and every gRPC / gRPC-Web call's `Host` / `:authority` the same way (allowed **and** bound; a refused native gRPC call fails with `grpc-status: 7`). Its raw traffic (a no-ALPN TLS connection relayed as raw) carries no request name, so the admitting SNI admits it: the SNI is re-checked against the allow / deny rules and its DNS binding for every message, and a deny on the destination or the SNI always blocks. A path-scoped allow on the destination admits a MITM'd HTTP connection provisionally (the path is checked per request) but not its raw traffic; a path-scoped allow on the SNI's hostname does not admit the connection.
- Routes without a name (server-first, opaque, h2c, late TLS) need an IP allow. A late ClientHello's SNI is still a deny-only name: a denied SNI closes the connection before the ClientHello reaches the upstream (recorded on the `late_tls` Stream with `blocked_by: "target_scope"`).

**Known limitation — name denies on an IP-allowed destination are best-effort.** The IP allow is the authoritative admission; SNI / `Host` deny rules are applied only to traffic the proxy recognises as TLS or HTTP. Traffic it does not recognise is relayed as `opaque` and its names are never checked — for example plain HTTP that does not start with a known method followed by a space (a leading CRLF, or a method such as `PROPFIND`), or a ClientHello padded beyond the 4096-byte peek or split across TLS records (the SNI then reads as empty, and the IP allow alone admits it). The bytes are relayed unchanged; the proxy does not normalise them to find a name. Where a name must never be reached, also deny its IP addresses (or do not allow-list them).

### nftables conventions (operator example)

```
table inet gw {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    iifname "wg-workers" meta l4proto tcp redirect to :8080
  }
  chain output {
    type nat hook output priority -100;
    # Only needed if locally generated traffic is redirected too: the
    # proxy's own traffic (UID or cgroup) must never be redirected back
    # to it (loop prevention).
    meta skuid "yorishiro" return
    meta l4proto tcp redirect to :8080
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "wg-workers" udp dport 53 ip daddr 10.0.0.53 accept   # the Worker's DNS server only
    iifname "wg-workers" udp dport 123 ip daddr 10.0.0.123 accept # the Worker's NTP server only
    iifname "wg-workers" meta l4proto udp reject                  # REJECT: QUIC falls back to TCP fast
  }
}
```

- Redirect **all** TCP from the Worker-side interface in PREROUTING; exclude the proxy's own traffic by UID / cgroup.
- Drop UDP by default and allow only the specific DNS (UDP 53) / NTP (UDP 123) servers the Worker uses — arbitrary-destination 53 / 123 is a DNS-tunnel style escape. QUIC is an audit gap; `REJECT` (rather than DROP) makes clients fall back to TCP quickly.
- TCP ACLs can be enforced both in nftables and with `target_scope`.
- **Port scans**: the proxy's kernel answers every REDIRECTed SYN with a SYN-ACK, so closed ports look open; this cannot be changed from user space. Run port scans from a dedicated Runner whose traffic is recorded by packet capture only.

## Common Misuse: proxy_start as a partial-update tool

`proxy_start` is **not** a delta-apply tool. Calling it repeatedly to "add one more intercept rule" wipes every other setting that was previously established for the listener.

### Anti-pattern (do NOT do this)

```json
// Step 1: set up the session.
{ "method": "proxy_start", "params": {
    "listen_addr": "127.0.0.1:8080",
    "capture_scope": { "includes": [{ "hostname": "api.target.com" }] },
    "tls_passthrough": ["*.googleapis.com"]
}}

// Step 2 (WRONG): adding an intercept rule by re-calling proxy_start.
//   This RESETS capture_scope back to "capture all" and clears tls_passthrough,
//   because both fields are omitted from this second request.
{ "method": "proxy_start", "params": {
    "listen_addr": "127.0.0.1:8080",
    "intercept_rules": [
      { "id": "r1", "enabled": true, "direction": "request",
        "http": { "host_pattern": "api\\.target\\.com" } }
    ]
}}
```

### Recommended pattern: initialize with `proxy_start`, update with `configure`

```json
// Step 1: one-shot initialization.
{ "method": "proxy_start", "params": {
    "listen_addr": "127.0.0.1:8080",
    "capture_scope": { "includes": [{ "hostname": "api.target.com" }] },
    "tls_passthrough": ["*.googleapis.com"]
}}

// Step 2: in-session update — add an intercept rule without touching the rest.
{ "method": "configure", "params": {
    "operation": "merge",
    "intercept_rules": { "add": [
      { "id": "r1", "enabled": true, "direction": "request",
        "http": { "host_pattern": "api\\.target\\.com" } }
    ]}
}}
```

Call `docs(topic="configure")` for the full merge / replace surface (add, remove, enable, disable per rule ID, or full-section replacement).

## Usage Examples

### Start with defaults
```json
{}
```

### Start on custom port
```json
{
  "listen_addr": "127.0.0.1:9090"
}
```

### Start with TLS passthrough
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_passthrough": ["*.googleapis.com", "accounts.google.com"]
}
```

### Start with TCP forwards (legacy string format)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "3306": "db.example.com:3306",
    "6379": "redis.example.com:6379"
  }
}
```

### Start with TCP forwards (structured ForwardConfig)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "50051": {
      "target": "api.example.com:50051",
      "protocol": "grpc"
    },
    "8443": {
      "target": "secure.example.com:443",
      "protocol": "http2",
      "tls": true
    },
    "3306": "db.example.com:3306"
  }
}
```

### Start with TCP forward to TLS-only upstream (HTTP → HTTPS bridge)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "8081": {
      "target": "api.example.com:443",
      "protocol": "http",
      "upstream_tls": true
    }
  }
}
```

### Start with TCP forward — full MITM (TLS terminate + re-encrypt upstream)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "8443": {
      "target": "api.example.com:443",
      "protocol": "http",
      "tls": true,
      "upstream_tls": true
    }
  }
}
```

### Start with SOCKS5 password authentication
```json
{
  "listen_addr": "127.0.0.1:8080",
  "socks5_auth": "password",
  "socks5_username": "proxyuser",
  "socks5_password": "proxypass"
}
```

### Start with SOCKS5 via proxychains
```json
{
  "listen_addr": "127.0.0.1:1080"
}
```
Then configure proxychains (`/etc/proxychains.conf`):
```
socks5 127.0.0.1 1080
```

### Start with TLS fingerprint
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_fingerprint": "firefox"
}
```

### Start with standard TLS (no fingerprint)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_fingerprint": "none"
}
```

### Start with intercept rules
```json
{
  "intercept_rules": [
    {
      "id": "target-host",
      "enabled": true,
      "direction": "request",
      "conditions": {
        "host_pattern": "httpbin\\.org"
      }
    },
    {
      "id": "admin-api",
      "enabled": true,
      "direction": "request",
      "conditions": {
        "host_pattern": "api\\.target\\.com",
        "path_pattern": "/api/admin.*",
        "methods": ["POST", "PUT", "DELETE"],
        "header_match": {"Content-Type": "application/json"}
      }
    }
  ]
}
```

### Start with upstream proxy
```json
{
  "listen_addr": "127.0.0.1:8080",
  "upstream_proxy": "http://upstream:3128"
}
```

### Start with named listener
```json
{
  "name": "api-proxy",
  "listen_addr": "127.0.0.1:9090"
}
```

### Start with mTLS client certificate
```json
{
  "listen_addr": "127.0.0.1:8080",
  "client_cert": "/path/to/client.crt",
  "client_key": "/path/to/client.key"
}
```
