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
  resource=flows          List recorded flows
  resource=flow           Get a single flow detail (requires flow_id=<id>)
  resource=messages       Get messages for a flow (requires flow_id=<id>)
  resource=status         Get proxy status
  resource=config         Get current configuration
  resource=ca_cert        Get CA certificate
  resource=intercept_queue  Get intercept queue
  resource=macros         List macro definitions
  resource=fuzz_results   Get fuzz results
  resource=technologies   Get technology stack detections
  flow_id=<id>            Flow ID (required for flow/messages resources)
  limit=<n>               Maximum number of results (default: 50)
  offset=<n>              Pagination offset
  protocol=<proto>        Filter by protocol (http, https, h2, grpc, ws, tcp)

Examples:
  yorishiro-proxy client query resource=flows limit=10
  yorishiro-proxy client query resource=flow flow_id=abc123
  yorishiro-proxy client query resource=status`,

	"proxy_start": `proxy_start: Start a proxy listener.

Parameters (key=value):
  name=<name>             Listener name (default: "default")
  addr=<host:port>        Listen address (default: 127.0.0.1:8080)
  protocol=<proto>        Protocol hint (http, socks5, tcp)

Examples:
  yorishiro-proxy client proxy_start addr=127.0.0.1:8080
  yorishiro-proxy client proxy_start name=secondary addr=127.0.0.1:8081`,

	"proxy_stop": `proxy_stop: Stop proxy listener(s).

Parameters (key=value):
  name=<name>             Listener name to stop. Omit to stop all.

Examples:
  yorishiro-proxy client proxy_stop
  yorishiro-proxy client proxy_stop name=secondary`,

	"configure": `configure: Configure runtime proxy settings.

Parameters (key=value):
  operation=merge|replace   Operation mode (default: merge)
  upstream_proxy=<url>      Upstream proxy URL
  passthrough=<hosts>       Comma-separated TLS passthrough hosts
  tls_fingerprint=<profile> TLS fingerprint profile

Examples:
  yorishiro-proxy client configure upstream_proxy=http://proxy:8888
  yorishiro-proxy client configure passthrough=example.com,*.internal`,

	"intercept": `intercept: Act on intercepted requests in the intercept queue.

Parameters (key=value):
  id=<id>                 Intercept item ID (required)
  action=forward|drop|modify  Action to take (required)
  body=<body>             Modified body (for action=modify)

Examples:
  yorishiro-proxy client intercept id=abc123 action=forward
  yorishiro-proxy client intercept id=abc123 action=drop`,

	"resend": `resend: Resend and replay recorded proxy requests.

Parameters (key=value):
  action=resend|compare   Action to perform (required)
  flow_id=<id>            Flow ID to resend (required for resend)
  flow_id_a=<id>          First flow ID (required for compare)
  flow_id_b=<id>          Second flow ID (required for compare)

Examples:
  yorishiro-proxy client resend action=resend flow_id=abc123
  yorishiro-proxy client resend action=compare flow_id_a=abc flow_id_b=def`,

	"manage": `manage: Manage flow data and CA certificates.

Parameters (key=value):
  action=delete_flows|export_har|get_ca_cert  Action to perform (required)
  flow_ids=<id1,id2>      Flow IDs for delete/export (comma-separated)
  format=har              Export format

Examples:
  yorishiro-proxy client manage action=delete_flows flow_ids=abc123,def456
  yorishiro-proxy client manage action=export_har flow_ids=abc123
  yorishiro-proxy client manage action=get_ca_cert`,

	"security": `security: Configure runtime security settings.

Parameters (key=value):
  action=configure        Action to perform
  rate_limit=<n>          Request rate limit per second
  budget=<n>              Security diagnostic budget

Examples:
  yorishiro-proxy client security action=configure rate_limit=100`,

	"macro": `macro: Define and execute macro workflows.

Parameters (key=value):
  action=define|execute|list|delete  Action to perform (required)
  name=<name>             Macro name
  script=<starlark>       Starlark script (for define)

Examples:
  yorishiro-proxy client macro action=list
  yorishiro-proxy client macro action=execute name=my_macro`,

	"fuzz": `fuzz: Execute fuzz testing campaigns.

Parameters (key=value):
  action=start|stop|status|results  Action to perform (required)
  flow_id=<id>            Flow ID to fuzz (required for start)
  campaign_id=<id>        Campaign ID (required for stop/status/results)

Examples:
  yorishiro-proxy client fuzz action=start flow_id=abc123
  yorishiro-proxy client fuzz action=results campaign_id=xyz789`,

	"plugin": `plugin: Manage Starlark plugins.

Parameters (key=value):
  action=load|unload|list|reload  Action to perform (required)
  name=<name>             Plugin name
  path=<path>             Plugin file path (for load)

Examples:
  yorishiro-proxy client plugin action=list
  yorishiro-proxy client plugin action=load name=myplugin path=/path/to/plugin.star`,
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
