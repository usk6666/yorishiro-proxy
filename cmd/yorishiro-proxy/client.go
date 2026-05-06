package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

// clientToolHelp maps tool names to their hardcoded parameter descriptions.
// This allows `client <tool> --help` to work without a server connection.
var clientToolHelp = map[string]string{
	"query": `query: Unified information query tool.

Parameters (key=value):
  resource=<resource>     Resource to query (required)
    flows                 List recorded flows
    flow                  Get a single flow detail (requires id=<id>)
    messages              Get messages for a flow (requires id=<id>)
    status                Get proxy status
    config                Get current configuration
    ca_cert               Get CA certificate
    intercept_queue       Get intercept queue
    macros                List macro definitions
    macro                 Get a single macro (requires id=<name>)
    fuzz_jobs             List fuzz jobs
    fuzz_results          Get fuzz results (requires fuzz_id=<id>)
    technologies          Get technology stack detections
  id=<id>                 Flow ID or macro name (required for flow/messages/macro)
  fuzz_id=<id>            Fuzz job ID (required for fuzz_results)
  limit=<n>               Maximum number of results (default: 50, max: 1000)
  offset=<n>              Pagination offset
  sort_by=<field>         Sort field (timestamp, duration_ms, etc.)

Filter options (dot-notation):
  filter.protocol=<proto>   Protocol filter (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP)
  filter.host=<host>        Host filter
  filter.method=<method>    HTTP method filter (GET, POST, etc.)
  filter.url_pattern=<pat>  URL substring search
  filter.status_code=<n>    HTTP status code filter
  filter.state=<state>      State filter (active, complete, error)
  filter.direction=<dir>    Message direction (send, receive) — for messages resource

Examples:
  yorishiro-proxy client query resource=flows limit=10
  yorishiro-proxy client query resource=flow id=abc123
  yorishiro-proxy client query resource=flows filter.protocol=HTTPS filter.method=POST
  yorishiro-proxy client query resource=status`,

	"proxy_start": `proxy_start: Start a proxy listener.

Parameters (key=value):
  name=<name>             Listener name (default: "default")
  listen_addr=<host:port> Listen address (default: 127.0.0.1:8080)
  upstream_proxy=<url>    Upstream proxy URL
  tls_fingerprint=<prof>  TLS fingerprint profile (chrome, firefox, safari, edge, random, none)
  max_connections=<n>     Max concurrent connections (default: 128)
  peek_timeout_ms=<n>     Protocol detection timeout in ms (default: 30000)
  request_timeout_ms=<n>  HTTP request timeout in ms (default: 60000)

Examples:
  yorishiro-proxy client proxy_start listen_addr=127.0.0.1:8080
  yorishiro-proxy client proxy_start name=secondary listen_addr=127.0.0.1:9090`,

	"proxy_stop": `proxy_stop: Stop proxy listener(s).

Parameters (key=value):
  name=<name>             Listener name to stop. Omit to stop all.

Examples:
  yorishiro-proxy client proxy_stop
  yorishiro-proxy client proxy_stop name=secondary`,

	"configure": `configure: Configure runtime proxy settings.

Parameters (key=value):
  operation=merge|replace       Operation mode (default: merge)
  upstream_proxy=<url>          Upstream proxy URL (empty string to disable)
  tls_fingerprint=<profile>     TLS fingerprint profile (chrome, firefox, safari, edge, random, none)
  max_connections=<n>           Max concurrent connections
  peek_timeout_ms=<n>           Protocol detection timeout in ms
  request_timeout_ms=<n>        HTTP request timeout in ms

TLS passthrough (dot-notation):
  tls_passthrough.add=<hosts>       (merge) Comma-separated patterns to add
  tls_passthrough.remove=<hosts>    (merge) Comma-separated patterns to remove
  tls_passthrough.patterns=<hosts>  (replace) Full comma-separated pattern list

Examples:
  yorishiro-proxy client configure upstream_proxy=http://proxy:8888
  yorishiro-proxy client configure tls_passthrough.add=example.com,*.internal
  yorishiro-proxy client configure tls_fingerprint=chrome`,

	"intercept": `intercept: Act on intercepted requests in the intercept queue.

Parameters (key=value):
  action=<action>                   Action to take (required)
    release                         Forward the request/response unmodified
    modify_and_forward              Modify and forward
    drop                            Drop the request/response
  params.intercept_id=<id>          Intercept item ID (required)
  params.override_method=<method>   HTTP method override (request phase)
  params.override_url=<url>         URL override (request phase)
  params.override_body=<body>       Body override (request phase)
  params.override_status=<code>     Status code override (response phase)
  params.override_response_body=<b> Response body override (response phase)
  params.mode=structured|raw        Forwarding mode (default: structured)

Examples:
  yorishiro-proxy client intercept action=release params.intercept_id=abc123
  yorishiro-proxy client intercept action=drop params.intercept_id=abc123
  yorishiro-proxy client intercept action=modify_and_forward params.intercept_id=abc123 params.override_body='{"new":"data"}'`,

	"resend_http": `resend_http: Resend or construct an HTTP request through the proxy stack.

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded HTTP stream id; when set, omitted fields inherit from the recorded send
  method=<method>          HTTP method (GET, POST, ...); required when flow_id is empty
  scheme=<http|https>      Required when flow_id is empty
  authority=<host[:port]>  Host header / :authority value; required when flow_id is empty
  path=<path>              Request path including leading slash; required when flow_id is empty
  raw_query=<query>        Raw query string without the leading '?'
  body=<text|base64>       Request body interpreted per body_encoding
  body_encoding=<enc>      text|base64; default text
  body_set=true            Set true to override body to empty; otherwise omitting body inherits the original
  override_host=<host:port> Redirect dial target while preserving the request's Host/:authority
  follow_redirects=<bool>  Unsupported; setting true returns an error
  timeout_ms=<n>           Per-request timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  tag=<tag>                Tag stored on the new flow's Tags map

Note: headers ([{name, value}] ordered list) and body_patches require JSON input — use the MCP
      client (or pass the parameter as a JSON string) for full structured definitions.

Examples:
  yorishiro-proxy client resend_http flow_id=abc123
  yorishiro-proxy client resend_http flow_id=abc123 method=POST body='{"x":1}' body_encoding=text
  yorishiro-proxy client resend_http method=GET scheme=https authority=example.com path=/api`,

	"resend_ws": `resend_ws: Resend a single WebSocket frame on a freshly dialled upstream connection.

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded WebSocket stream id; when set, the upgrade dance inherits URL/headers/extensions
  target_addr=<host:port>  Upstream host:port. Required when flow_id is empty (overrides dial target with flow_id)
  scheme=<ws|wss>          Required when flow_id is empty (defaults to ws)
  path=<path>              Upgrade request path; required when flow_id is empty
  raw_query=<query>        Upgrade request raw query string without the leading '?'
  opcode=<text|binary|close|ping|pong>  Frame opcode (REQUIRED)
  fin=<bool>               FIN bit; defaults to true
  payload=<text|base64>    Frame payload interpreted per body_encoding
  body_encoding=<enc>      text|base64; defaults to text
  payload_set=true         Set true to send an empty payload; otherwise empty is treated as no override
  masked=<bool>            Informational; the layer auto-masks per RFC 6455 §5.3
  mask=<hex|b64>           Informational 4-byte mask key; ignored on Send
  close_code=<n>           RFC 6455 status code for Close frames
  close_reason=<text>      Optional UTF-8 reason for Close frames
  compressed=<bool>        Per-message-deflate (RFC 7692); requires negotiation via flow_id
  timeout_ms=<n>           Per-call timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  tag=<tag>                Tag stored on the new flow's Tags map

Examples:
  yorishiro-proxy client resend_ws flow_id=abc123 opcode=text payload=hello
  yorishiro-proxy client resend_ws target_addr=127.0.0.1:8080 scheme=ws path=/socket opcode=ping`,

	"resend_grpc": `resend_grpc: Resend a gRPC unary RPC on a freshly dialled HTTP/2 upstream.

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded gRPC stream id; when set, omitted Start fields inherit from the original RPC
  target_addr=<host:port>  Upstream host:port. Required when flow_id is empty
  scheme=<http|https>      Defaults to https. http selects plaintext h2c
  service=<service>        gRPC service name (e.g. pkg.Greeter); required when flow_id is empty
  method=<name>            gRPC method name (e.g. SayHello); required when flow_id is empty
  encoding=<enc>           grpc-encoding for outgoing messages (identity or gzip)
  accept_encoding=<list>   grpc-accept-encoding list (e.g. gzip,identity)
  timeout_ms=<n>           Per-call timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  tag=<tag>                Tag stored on the new flow's Tags map

Note: messages ([{payload, body_encoding, compressed}]) and metadata / trailer_metadata
      ([{name, value}] lists) require JSON input — use the MCP client for full definitions.
      messages requires at least one element.

Examples:
  yorishiro-proxy client resend_grpc flow_id=abc123
  yorishiro-proxy client resend_grpc target_addr=127.0.0.1:50051 service=pkg.Greeter method=SayHello`,

	"resend_raw": `resend_raw: Resend a recorded raw byte payload on a freshly dialled TCP/TLS upstream.

Parameters (key=value or --key=value):
  flow_id=<id>                       Recorded raw stream id (REQUIRED — use fuzz_raw for ad-hoc injection)
  target_addr=<host:port>            Upstream host:port (REQUIRED, explicit port required)
  use_tls=<bool>                     True to upgrade the dialed connection to TLS
  sni=<name>                         SNI server name; defaults to target_addr host when use_tls=true
  override_bytes=<text|base64>       Replacement payload (mutually exclusive with patches)
  override_bytes_encoding=<enc>      text|base64; defaults to text
  override_bytes_set=true            Set true to replace with empty bytes
  insecure_skip_verify=<bool>        Skip TLS server certificate verification when use_tls=true
  tls_fingerprint=<prof>             Informational v1; per-call selection deferred
  timeout_ms=<n>                     Per-call timeout in milliseconds (default: 30000)
  tag=<tag>                          Tag stored on the new flow's Tags map

Note: patches ([{offset, data, data_encoding}]) requires JSON input — use the MCP client
      for full definitions. Wire bytes are NEVER normalized — they reach the wire verbatim,
      making this the smuggling/anomaly-test surface.

Examples:
  yorishiro-proxy client resend_raw flow_id=abc123 target_addr=127.0.0.1:8080
  yorishiro-proxy client resend_raw flow_id=abc123 target_addr=example.com:443 use_tls=true`,

	"manage": `manage: Manage flow data and CA certificates.

Parameters (key=value):
  action=<action>                   Action to perform (required)
    delete_flows                    Delete flow(s)
    export_flows                    Export flows
    import_flows                    Import flows
    regenerate_ca_cert              Regenerate CA certificate
  params.flow_id=<id>               Flow ID for single-flow deletion
  params.older_than_days=<n>        Delete flows older than N days
  params.protocol=<proto>           Protocol filter for delete_flows
  params.confirm=true               Confirm bulk deletion (required for bulk ops)
  params.format=jsonl|har           Export format (default: jsonl)
  params.output_path=<path>         File path for export output
  params.input_path=<path>          File path for import input
  params.on_conflict=skip|replace   Import conflict policy (default: skip)

Examples:
  yorishiro-proxy client manage action=delete_flows params.flow_id=abc123
  yorishiro-proxy client manage action=delete_flows params.older_than_days=7 params.confirm=true
  yorishiro-proxy client manage action=export_flows params.format=har params.output_path=export.har
  yorishiro-proxy client manage action=regenerate_ca_cert`,

	"security": `security: Configure runtime security settings.

Parameters (key=value):
  action=<action>                          Action to perform (required)
    set_target_scope                       Replace all target scope rules
    update_target_scope                    Merge delta into target scope
    get_target_scope                       Get current target scope
    test_target                            Dry-run URL check against scope
    set_rate_limits                        Set rate limits
    get_rate_limits                        Get current rate limits
    set_budget                             Set session budget
    get_budget                             Get current budget
    get_safety_filter                      Get safety filter status
  params.url=<url>                         URL to test (for test_target)
  params.max_requests_per_second=<n>       Global rate limit (for set_rate_limits)
  params.max_requests_per_host_per_second=<n>  Per-host rate limit
  params.max_total_requests=<n>            Max total requests (for set_budget)
  params.max_duration=<dur>                Max duration e.g. 30m (for set_budget)

Examples:
  yorishiro-proxy client security action=get_target_scope
  yorishiro-proxy client security action=test_target params.url=https://example.com
  yorishiro-proxy client security action=set_rate_limits params.max_requests_per_second=100`,

	"macro": `macro: Define and execute macro workflows.

Parameters (key=value):
  action=<action>                   Action to perform (required)
    define_macro                    Define a new macro
    run_macro                       Execute a macro
    delete_macro                    Delete a macro
  params.name=<name>                Macro name (required for all actions)
  params.description=<desc>         Macro description (for define_macro)
  params.macro_timeout_ms=<n>       Overall macro timeout in ms (default: 300000)

Note: define_macro requires complex 'steps' array — use JSON input or MCP client for full definitions.
      Use 'query resource=macros' to list macros, 'query resource=macro id=<name>' to inspect.

Examples:
  yorishiro-proxy client macro action=run_macro params.name=my_macro
  yorishiro-proxy client macro action=delete_macro params.name=my_macro`,

	"fuzz_http": `fuzz_http: Synchronously fuzz an HTTP request (cartesian product, capped at 1000 variants).

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded HTTP stream id; when set, omitted base fields are inherited
  method=<method>          HTTP method base; required when flow_id is empty
  scheme=<http|https>      Required when flow_id is empty
  authority=<host[:port]>  Host / :authority; required when flow_id is empty
  path=<path>              Request path; required when flow_id is empty
  raw_query=<query>        Raw query string without leading '?'
  body=<text|base64>       Base body interpreted per body_encoding
  body_encoding=<enc>      text|base64; default text
  body_set=true            Set true to override body to empty
  override_host=<host:port> Redirect dial target while preserving the request's Host/:authority
  timeout_ms=<n>           Per-variant timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  stop_on_5xx=<bool>       Abort remaining variants once a variant returns 5xx
  tag=<tag>                Tag stored on every variant Stream's Tags map

Note: positions[] is REQUIRED — each is {path, payloads[], encoding}. Supported paths:
      method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value
      Use JSON input or MCP client for the positions / headers / body_patches arrays.

Examples:
  yorishiro-proxy client fuzz_http flow_id=abc123  (positions supplied via JSON)
  yorishiro-proxy client fuzz_http flow_id=abc123 stop_on_5xx=true tag=path-fuzz`,

	"fuzz_ws": `fuzz_ws: Synchronously fuzz a WebSocket frame (cartesian product, capped at 1000 variants).

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded WebSocket stream id
  target_addr=<host:port>  Upstream host:port; required when flow_id is empty
  scheme=<ws|wss>          Required when flow_id is empty (defaults to ws)
  path=<path>              Upgrade request path; required when flow_id is empty
  raw_query=<query>        Upgrade request raw query string without leading '?'
  opcode=<text|binary|close|ping|pong>  Frame opcode (REQUIRED)
  fin=<bool>               FIN bit; defaults to true
  payload=<text|base64>    Base frame payload
  body_encoding=<enc>      text|base64; defaults to text
  payload_set=true         Set true to send an empty base payload
  masked=<bool>            Informational; layer auto-masks per RFC 6455 §5.3
  mask=<base64>            Informational 4-byte mask key; ignored on Send
  close_code=<n>           RFC 6455 status code for Close frames
  close_reason=<text>      Base UTF-8 reason for Close frames
  compressed=<bool>        Per-message-deflate; requires negotiation via flow_id
  timeout_ms=<n>           Per-variant timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  stop_on_close=<bool>     Abort remaining variants once a variant receives a Close frame
  tag=<tag>                Tag stored on every variant Stream's Tags map

Note: positions[] is REQUIRED — each is {path, payloads[], encoding}. Supported paths:
      payload | close_reason. Use JSON input or MCP client for the positions array.

Examples:
  yorishiro-proxy client fuzz_ws flow_id=abc123 opcode=text  (positions supplied via JSON)`,

	"fuzz_grpc": `fuzz_grpc: Synchronously fuzz a gRPC unary RPC (cartesian product, capped at 1000 variants).

Parameters (key=value or --key=value):
  flow_id=<id>             Recorded gRPC stream id
  target_addr=<host:port>  Upstream host:port; required when flow_id is empty
  scheme=<http|https>      Defaults to https; http selects plaintext h2c
  service=<service>        gRPC service name; required when flow_id is empty
  method=<name>            gRPC method name; required when flow_id is empty
  encoding=<enc>           grpc-encoding for outgoing messages (identity or gzip)
  accept_encoding=<list>   grpc-accept-encoding list (e.g. gzip,identity)
  timeout_ms=<n>           Per-variant timeout in milliseconds (default: 30000)
  tls_fingerprint=<prof>   Informational v1; per-call selection deferred
  stop_on_non_ok=<bool>    Abort remaining variants on first non-OK gRPC status
  tag=<tag>                Tag stored on every variant Stream's Tags map

Note: positions[] is REQUIRED — each is {path, payloads[], encoding}. Supported paths:
      service | method | metadata[N].name | metadata[N].value | messages[N].payload
      messages / metadata / trailer_metadata / positions arrays require JSON input —
      use the MCP client for full definitions. messages requires at least one element.

Examples:
  yorishiro-proxy client fuzz_grpc flow_id=abc123  (positions supplied via JSON)`,

	"fuzz_raw": `fuzz_raw: Synchronously fuzz a raw byte payload (HTTP smuggling surface, capped at 1000 variants).

Parameters (key=value or --key=value):
  flow_id=<id>                       Recorded raw stream id (OPTIONAL)
  target_addr=<host:port>            Upstream host:port (REQUIRED, explicit port)
  use_tls=<bool>                     True to upgrade the dialed connection to TLS
  sni=<name>                         SNI server name; defaults to target_addr host when use_tls=true
  override_bytes=<text|base64>       Replacement base payload (mutually exclusive with patches)
  override_bytes_encoding=<enc>      text|base64; defaults to text
  override_bytes_set=true            Set true to replace with empty bytes
  insecure_skip_verify=<bool>        Skip TLS server certificate verification when use_tls=true
  tls_fingerprint=<prof>             Informational v1; per-call selection deferred
  timeout_ms=<n>                     Per-variant timeout in milliseconds (default: 30000)
  stop_on_error=<bool>               Abort remaining variants on first failure (network error, timeout, drop)
  tag=<tag>                          Tag stored on every variant Stream's Tags map

Note: positions[] is REQUIRED — each is {path, payloads[], encoding}. Supported paths:
      payload | patches[N].data. patches[] (the base) and positions[] arrays require JSON
      input — use the MCP client for full definitions.
      Wire bytes are NEVER normalized — they reach the wire verbatim.

Examples:
  yorishiro-proxy client fuzz_raw flow_id=abc123 target_addr=127.0.0.1:8080  (positions via JSON)`,

	"plugin_introspect": `plugin_introspect: List loaded Starlark plugins with their hook registrations.

Parameters: none.

Returns one entry per loaded pluginv2 plugin: name, path, enabled flag, the list of
(protocol, event, phase) hook registrations the plugin made via register_hook, and
the redacted PluginConfig.Vars map (RedactKeys substitute "<redacted>"; large values truncated).

Examples:
  yorishiro-proxy client plugin_introspect`,
}

// clientToolList is the ordered list of available MCP tools for help display.
// The list MUST stay in sync with the server's registerTools() in
// internal/mcp/server.go. The TestRegression_ClientToolList_MatchesServer e2e
// test boots a real MCP server and asserts set equality both directions —
// adding a new server tool without updating this list (or vice versa) fails
// that test.
var clientToolList = []string{
	"query",
	"proxy_start",
	"proxy_stop",
	"configure",
	"intercept",
	"resend_http",
	"resend_ws",
	"resend_grpc",
	"resend_raw",
	"manage",
	"security",
	"macro",
	"fuzz_http",
	"fuzz_ws",
	"fuzz_grpc",
	"fuzz_raw",
	"plugin_introspect",
}

// clientToolDescriptions maps tool names to their short descriptions for list display.
var clientToolDescriptions = map[string]string{
	"query":             "Unified query for flows, status, config, etc.",
	"proxy_start":       "Start a proxy listener",
	"proxy_stop":        "Stop proxy listener(s)",
	"configure":         "Configure runtime proxy settings",
	"intercept":         "Act on intercepted requests in the queue",
	"resend_http":       "Resend or construct an HTTP request",
	"resend_ws":         "Resend a single WebSocket frame",
	"resend_grpc":       "Resend a gRPC unary RPC",
	"resend_raw":        "Resend a recorded raw byte payload",
	"manage":            "Manage flow data and CA certificates",
	"security":          "Configure runtime security settings",
	"macro":             "Define and execute macro workflows",
	"fuzz_http":         "Synchronously fuzz an HTTP request",
	"fuzz_ws":           "Synchronously fuzz a WebSocket frame",
	"fuzz_grpc":         "Synchronously fuzz a gRPC unary RPC",
	"fuzz_raw":          "Synchronously fuzz a raw byte payload",
	"plugin_introspect": "List loaded Starlark plugins and hook registrations",
}

// runClient is the entry point for the "client" subcommand.
// It handles: list-servers, --help, <tool> --help, and tool invocations.
func runClient(ctx context.Context, args []string) error {
	// Handle the case where no arguments are given.
	if len(args) == 0 {
		printClientUsage(os.Stdout)
		return nil
	}

	first := args[0]

	// Handle --help / -help / -h before anything else (no server connection needed).
	if first == "--help" || first == "-help" || first == "-h" {
		printClientUsage(os.Stdout)
		return nil
	}

	// Handle list-servers subcommand (reads server.json, no MCP connection needed).
	if first == "list-servers" {
		return runListServers(os.Stdout, args[1:])
	}

	// Everything else is a tool invocation: <tool> [key=value ...] [flags]
	toolName := first
	toolArgs := args[1:]

	// Handle <tool> --help / -help / -h (no server connection needed).
	for _, a := range toolArgs {
		if a == "--help" || a == "-help" || a == "-h" {
			return printToolHelp(os.Stdout, toolName)
		}
	}

	return runClientTool(ctx, toolName, toolArgs)
}

// printClientUsage prints the usage message for the client subcommand.
func printClientUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: yorishiro-proxy client <command> [parameters]\n\n")
	fmt.Fprintf(w, "A CLI client for the yorishiro-proxy MCP server.\n")
	fmt.Fprintf(w, "Connects to the running proxy via the Streamable HTTP MCP endpoint.\n\n")
	fmt.Fprintf(w, "Commands:\n")
	fmt.Fprintf(w, "  list-servers            List running proxy server instances\n\n")
	fmt.Fprintf(w, "MCP Tools:\n")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, name := range clientToolList {
		fmt.Fprintf(tw, "  %s\t%s\n", name, clientToolDescriptions[name])
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\nFlags:\n")
	fmt.Fprintf(w, "  -server-addr <host:port>  Connect to specific server address\n")
	fmt.Fprintf(w, "                            (env: YP_CLIENT_ADDR, default: auto-detect from server.json)\n")
	fmt.Fprintf(w, "  --token <token>           Bearer token for authentication\n")
	fmt.Fprintf(w, "                            (env: YP_CLIENT_TOKEN, default: auto-detect from server.json)\n")
	fmt.Fprintf(w, "                            WARNING: --token exposes the token in process listings (ps aux).\n")
	fmt.Fprintf(w, "                            Prefer YP_CLIENT_TOKEN env var in sensitive environments.\n")
	fmt.Fprintf(w, "  --format json|table|raw   Output format (env: YP_CLIENT_FORMAT, default: json or raw when piped)\n")
	fmt.Fprintf(w, "  --raw                     Compact JSON output without indentation (for pipes/scripts)\n")
	fmt.Fprintf(w, "  -q, --quiet               Suppress output on success (for scripting)\n\n")
	fmt.Fprintf(w, "Tool parameters are passed as key=value pairs:\n")
	fmt.Fprintf(w, "  yorishiro-proxy client query resource=flows limit=10\n\n")
	fmt.Fprintf(w, "Run 'yorishiro-proxy client <tool> --help' for tool-specific parameters.\n")
}

// printToolHelp prints the hardcoded help for a specific tool.
func printToolHelp(w io.Writer, toolName string) error {
	help, ok := clientToolHelp[toolName]
	if !ok {
		return fmt.Errorf("unknown tool %q: run 'yorishiro-proxy client --help' to see available tools", toolName)
	}
	fmt.Fprintln(w, help)
	return nil
}

// listServersEntry is an entry in the list-servers output.
type listServersEntry struct {
	Addr      string    `json:"addr"`
	Token     string    `json:"token"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
}

// runListServers handles the "client list-servers" subcommand.
func runListServers(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("list-servers", flag.ContinueOnError)
	var format string
	fs.StringVar(&format, "format", "json", "output format: json or table")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: yorishiro-proxy client list-servers [--format json|table]\n\n")
		fmt.Fprintf(fs.Output(), "List running yorishiro-proxy server instances from server.json.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	path, err := mcpserver.ServerJSONPath()
	if err != nil {
		return fmt.Errorf("resolve server.json path: %w", err)
	}

	entries, err := mcpserver.ReadServerJSONSlice(path)
	if err != nil {
		return fmt.Errorf("read server.json: %w", err)
	}

	// Build output entries with liveness status.
	result := make([]listServersEntry, 0, len(entries))
	for _, e := range entries {
		status := "active"
		if !mcpserver.IsProcessAlive(e.PID) {
			status = "stale"
		}
		result = append(result, listServersEntry{
			Addr:      e.Addr,
			Token:     e.Token,
			PID:       e.PID,
			StartedAt: e.StartedAt,
			Status:    status,
		})
	}

	switch format {
	case "json":
		return printListServersJSON(w, result)
	case "table":
		return printListServersTable(w, result)
	default:
		return fmt.Errorf("unsupported format %q: must be \"json\" or \"table\"", format)
	}
}

// printListServersJSON outputs the server list as JSON.
func printListServersJSON(w io.Writer, entries []listServersEntry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Fprintln(w, string(b))
	return nil
}

// printListServersTable outputs the server list as a human-readable table.
// The Token column is truncated to the first 8 characters followed by "..."
// to keep the table compact; use --format json to retrieve the full token.
func printListServersTable(w io.Writer, entries []listServersEntry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDR\tTOKEN\tPID\tSTARTED\tSTATUS")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
			e.Addr,
			truncateTokenForTable(e.Token),
			e.PID,
			e.StartedAt.UTC().Format(time.RFC3339),
			e.Status,
		)
	}
	return tw.Flush()
}

// truncateTokenForTable returns a short visual representation of a Bearer
// token suitable for the table output. Empty tokens render as the empty
// string. Tokens of 8 or more characters are truncated to the first 8
// characters followed by "...". Shorter non-empty tokens are returned as-is.
func truncateTokenForTable(token string) string {
	if token == "" {
		return ""
	}
	if len(token) >= 8 {
		return token[:8] + "..."
	}
	return token
}

// resolveClientConn resolves the server address and Bearer token for the MCP client.
// Priority: flags > environment variables > server.json.
func resolveClientConn(flagAddr, flagToken string) (addr, token string, err error) {
	// Start with env vars.
	addr = os.Getenv("YP_CLIENT_ADDR")
	token = os.Getenv("YP_CLIENT_TOKEN")

	// Flags override env vars.
	if flagAddr != "" {
		addr = flagAddr
	}
	if flagToken != "" {
		token = flagToken
	}

	// If either is still missing, try server.json.
	if addr == "" || token == "" {
		addr, token = fillFromServerJSON(addr, token)
	}

	if addr == "" {
		return "", "", fmt.Errorf("no server address found: start a server with 'yorishiro-proxy server', or specify -server-addr")
	}

	return addr, token, nil
}

// fillFromServerJSON fills missing addr/token from a live server.json entry.
// When addr is already known, only tokens from entries with a matching Addr are accepted.
func fillFromServerJSON(addr, token string) (string, string) {
	path, pathErr := mcpserver.ServerJSONPath()
	if pathErr != nil {
		return addr, token
	}
	entries, readErr := mcpserver.ReadServerJSONSlice(path)
	if readErr != nil {
		return addr, token
	}
	for _, e := range entries {
		if !mcpserver.IsProcessAlive(e.PID) {
			continue
		}
		if addr != "" && token == "" {
			// addr is already known: only accept token from a matching entry.
			if e.Addr == addr {
				token = e.Token
			}
			continue
		}
		// addr not yet known: use first live entry.
		if addr == "" {
			addr = e.Addr
		}
		if token == "" {
			token = e.Token
		}
		break
	}
	// Warn if no live entry could supply an addr.
	if addr == "" && len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "warning: server.json contains stale entries (dead PIDs); no live server found\n")
	}
	return addr, token
}

// bearerRoundTripper is an http.RoundTripper that adds a Bearer token to every request.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		// Clone the request to avoid mutating the original.
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", "Bearer "+t.token)
		req = r
	}
	return t.base.RoundTrip(req)
}

// splitClientToolArgs partitions args into connection flags (--server-addr, --token, --format, etc.) and tool parameter args.
func splitClientToolArgs(args []string) (connFlagArgs, toolParamArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		stripped := a
		if strings.HasPrefix(stripped, "--") {
			stripped = stripped[2:]
		} else if strings.HasPrefix(stripped, "-") {
			stripped = stripped[1:]
		} else {
			toolParamArgs = append(toolParamArgs, a)
			continue
		}
		// Check if this is a known connection flag.
		name := stripped
		if idx := strings.IndexByte(name, '='); idx >= 0 {
			name = name[:idx]
		}
		switch name {
		case "server-addr", "token", "format":
			connFlagArgs = append(connFlagArgs, a)
			// If no '=' in the flag (space-separated value), grab the next arg as value.
			if !strings.Contains(stripped, "=") && i+1 < len(args) {
				i++
				connFlagArgs = append(connFlagArgs, args[i])
			}
		case "quiet", "q", "raw":
			connFlagArgs = append(connFlagArgs, a)
		default:
			toolParamArgs = append(toolParamArgs, a)
		}
	}
	return connFlagArgs, toolParamArgs
}

// runClientTool connects to the MCP server and calls the given tool.
func runClientTool(ctx context.Context, toolName string, args []string) error {
	// Parse connection flags from args. Flags may appear anywhere in args.
	fs := flag.NewFlagSet("client-tool", flag.ContinueOnError)
	var flagAddr, flagToken string
	var flagFormat string
	var flagQuiet bool
	var flagRaw bool
	fs.StringVar(&flagAddr, "server-addr", "", "server address (host:port)")
	fs.StringVar(&flagToken, "token", "", "bearer token (prefer YP_CLIENT_TOKEN env var to avoid token appearing in process list)")
	fs.StringVar(&flagFormat, "format", "", "output format: json, table, or raw (env: YP_CLIENT_FORMAT)")
	fs.BoolVar(&flagQuiet, "quiet", false, "suppress output on success")
	fs.BoolVar(&flagQuiet, "q", false, "suppress output on success")
	fs.BoolVar(&flagRaw, "raw", false, "raw JSON output without indentation")
	fs.Usage = func() {} // suppress default usage on error

	// Separate connection flags from tool parameters.
	connFlagArgs, toolParamArgs := splitClientToolArgs(args)

	if err := fs.Parse(connFlagArgs); err != nil {
		return err
	}

	addr, token, err := resolveClientConn(flagAddr, flagToken)
	if err != nil {
		return err
	}

	// Validate addr format before URL construction (S-3/F-5).
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid server address %q: %w", addr, err)
	}

	// Build MCP endpoint URL.
	endpoint := "http://" + addr + "/mcp"

	// Build HTTP client with Bearer auth transport and timeout (S-1).
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &bearerRoundTripper{
			token: token,
			base:  http.DefaultTransport,
		},
	}

	// Create MCP client and connect.
	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "yorishiro-proxy-cli",
		Version: buildVersion(),
	}, nil)

	transport := &gomcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}

	// Derive a context with a 60-second deadline for MCP operations (S-1/S-4).
	mcpCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	session, err := client.Connect(mcpCtx, transport, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hint: run 'yorishiro-proxy server' to start the server\n")
		return fmt.Errorf("connect to MCP server at %s: %w", addr, err)
	}
	defer session.Close()

	// Fetch tool schema for type inference and validation.
	schema := fetchToolSchema(mcpCtx, session, toolName)

	// Build tool parameters with type inference and positional arg support.
	params, err := buildToolParams(toolName, toolParamArgs, schema, os.Stderr)
	if err != nil {
		return fmt.Errorf("invalid parameters: %w", err)
	}

	// Call the tool.
	result, err := session.CallTool(mcpCtx, &gomcp.CallToolParams{
		Name:      toolName,
		Arguments: params,
	})
	if err != nil {
		return fmt.Errorf("call tool %q: %w", toolName, err)
	}

	// Resolve effective format and output the result.
	format := resolveFormat(flagFormat)
	return printToolResult(os.Stdout, toolName, result, format, flagQuiet, flagRaw)
}

// fetchToolSchema calls tools/list on the session and returns the parsed schema for toolName.
// Returns nil if the list call fails or the tool is not found.
func fetchToolSchema(ctx context.Context, session *gomcp.ClientSession, toolName string) *toolSchema {
	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil || toolsResult == nil {
		return nil
	}
	for _, t := range toolsResult.Tools {
		if t.Name == toolName {
			return parseToolSchema(t.InputSchema)
		}
	}
	return nil
}
