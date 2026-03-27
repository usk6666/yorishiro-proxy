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

	"resend": `resend: Resend and replay recorded proxy requests.

Parameters (key=value):
  action=<action>                   Action to perform (required)
    resend                          Resend an HTTP request
    resend_raw                      Resend raw bytes
    tcp_replay                      Replay TCP connection
    compare                         Compare two flows
  params.flow_id=<id>               Flow ID (required for resend/resend_raw/tcp_replay)
  params.override_method=<method>   HTTP method override
  params.override_url=<url>         URL override
  params.override_body=<body>       Body override (text)
  params.override_host=<host:port>  Connection target override
  params.follow_redirects=true      Follow HTTP redirects (default: false)
  params.timeout_ms=<n>             Request timeout in ms (default: 30000)
  params.dry_run=true               Preview without sending
  params.tag=<tag>                  Tag for result flow
  params.flow_id_a=<id>             First flow ID (for compare)
  params.flow_id_b=<id>             Second flow ID (for compare)

Examples:
  yorishiro-proxy client resend action=resend params.flow_id=abc123
  yorishiro-proxy client resend action=resend params.flow_id=abc123 params.override_method=POST
  yorishiro-proxy client resend action=compare params.flow_id_a=abc params.flow_id_b=def`,

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

	"fuzz": `fuzz: Execute fuzz testing campaigns.

Parameters (key=value):
  action=<action>                   Action to perform (required)
    fuzz                            Start a fuzz job
    fuzz_pause                      Pause a running fuzz job
    fuzz_resume                     Resume a paused fuzz job
    fuzz_cancel                     Cancel a fuzz job
  params.flow_id=<id>               Template flow ID (required for fuzz)
  params.fuzz_id=<id>               Fuzz job ID (required for pause/resume/cancel)
  params.concurrency=<n>            Concurrent workers (default: 1, max: 100)
  params.rate_limit_rps=<n>         Requests per second limit (0=unlimited)
  params.delay_ms=<n>               Delay between requests in ms
  params.timeout_ms=<n>             Request timeout in ms (default: 30000)
  params.tag=<tag>                  Tag for the fuzz job

Note: fuzz action requires 'positions' and 'payload_sets' — use JSON input or MCP client for full definitions.
      Use 'query resource=fuzz_jobs' to list jobs, 'query resource=fuzz_results fuzz_id=<id>' for results.

Examples:
  yorishiro-proxy client fuzz action=fuzz_pause params.fuzz_id=xyz789
  yorishiro-proxy client fuzz action=fuzz_cancel params.fuzz_id=xyz789`,

	"plugin": `plugin: Manage Starlark plugins.

Parameters (key=value):
  action=<action>                   Action to perform (required)
    list                            List all registered plugins
    reload                          Reload a plugin (or all if name omitted)
    enable                          Enable a disabled plugin
    disable                         Disable a plugin
  params.name=<name>                Plugin name (required for enable/disable, optional for reload)

Examples:
  yorishiro-proxy client plugin action=list
  yorishiro-proxy client plugin action=reload params.name=myplugin
  yorishiro-proxy client plugin action=enable params.name=myplugin
  yorishiro-proxy client plugin action=disable params.name=myplugin`,
}

// clientToolList is the ordered list of available MCP tools for help display.
var clientToolList = []string{
	"query",
	"proxy_start",
	"proxy_stop",
	"configure",
	"intercept",
	"resend",
	"manage",
	"security",
	"macro",
	"fuzz",
	"plugin",
}

// clientToolDescriptions maps tool names to their short descriptions for list display.
var clientToolDescriptions = map[string]string{
	"query":       "Unified query for flows, status, config, etc.",
	"proxy_start": "Start a proxy listener",
	"proxy_stop":  "Stop proxy listener(s)",
	"configure":   "Configure runtime proxy settings",
	"intercept":   "Act on intercepted requests in the queue",
	"resend":      "Resend/replay recorded proxy requests",
	"manage":      "Manage flow data and CA certificates",
	"security":    "Configure runtime security settings",
	"macro":       "Define and execute macro workflows",
	"fuzz":        "Execute fuzz testing campaigns",
	"plugin":      "Manage Starlark plugins",
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

	path, err := serverJSONPath()
	if err != nil {
		return fmt.Errorf("resolve server.json path: %w", err)
	}

	entries, err := readServerJSONSlice(path)
	if err != nil {
		return fmt.Errorf("read server.json: %w", err)
	}

	// Build output entries with liveness status.
	result := make([]listServersEntry, 0, len(entries))
	for _, e := range entries {
		status := "active"
		if !isProcessAlive(e.PID) {
			status = "stale"
		}
		result = append(result, listServersEntry{
			Addr:      e.Addr,
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
func printListServersTable(w io.Writer, entries []listServersEntry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDR\tPID\tSTARTED\tSTATUS")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n",
			e.Addr,
			e.PID,
			e.StartedAt.UTC().Format(time.RFC3339),
			e.Status,
		)
	}
	return tw.Flush()
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
	path, pathErr := serverJSONPath()
	if pathErr != nil {
		return addr, token
	}
	entries, readErr := readServerJSONSlice(path)
	if readErr != nil {
		return addr, token
	}
	for _, e := range entries {
		if !isProcessAlive(e.PID) {
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
