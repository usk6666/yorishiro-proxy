package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
		return runListServers(args[1:])
	}

	// Everything else is a tool invocation: <tool> [key=value ...] [flags]
	toolName := first
	toolArgs := args[1:]

	// Handle <tool> --help / -help / -h (no server connection needed).
	for _, a := range toolArgs {
		if a == "--help" || a == "-help" || a == "-h" {
			return printToolHelp(toolName)
		}
	}

	return runClientTool(ctx, toolName, toolArgs)
}

// printClientUsage prints the usage message for the client subcommand.
func printClientUsage(w *os.File) {
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
	fmt.Fprintf(w, "  --format table|json       Output format (default: json)\n\n")
	fmt.Fprintf(w, "Tool parameters are passed as key=value pairs:\n")
	fmt.Fprintf(w, "  yorishiro-proxy client query resource=flows limit=10\n\n")
	fmt.Fprintf(w, "Run 'yorishiro-proxy client <tool> --help' for tool-specific parameters.\n")
}

// printToolHelp prints the hardcoded help for a specific tool.
func printToolHelp(toolName string) error {
	help, ok := clientToolHelp[toolName]
	if !ok {
		return fmt.Errorf("unknown tool %q: run 'yorishiro-proxy client --help' to see available tools", toolName)
	}
	fmt.Fprintln(os.Stdout, help)
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
func runListServers(args []string) error {
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
	case "table":
		return printListServersTable(result)
	default:
		return printListServersJSON(result)
	}
}

// printListServersJSON outputs the server list as JSON.
func printListServersJSON(entries []listServersEntry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

// printListServersTable outputs the server list as a human-readable table.
func printListServersTable(entries []listServersEntry) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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
		path, pathErr := serverJSONPath()
		if pathErr == nil {
			entries, readErr := readServerJSONSlice(path)
			if readErr == nil {
				// Use the first live entry.
				for _, e := range entries {
					if isProcessAlive(e.PID) {
						if addr == "" {
							addr = e.Addr
						}
						if token == "" {
							token = e.Token
						}
						break
					}
				}
				// Warn if any matching PID is dead (stale entry exists).
				if addr == "" && len(entries) > 0 {
					fmt.Fprintf(os.Stderr, "warning: server.json contains stale entries (dead PIDs); no live server found\n")
				}
			}
		}
	}

	if addr == "" {
		return "", "", fmt.Errorf("no server address found: start a server with 'yorishiro-proxy server', or specify -server-addr")
	}

	return addr, token, nil
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

// parseToolArgs parses key=value or --key=value pairs from args into a map.
// Both "key=value" and "--key=value" formats are supported.
func parseToolArgs(args []string) map[string]any {
	result := make(map[string]any)
	for _, arg := range args {
		// Strip leading "--" or "-" if present.
		stripped := arg
		if strings.HasPrefix(stripped, "--") {
			stripped = stripped[2:]
		} else if strings.HasPrefix(stripped, "-") {
			stripped = stripped[1:]
		}

		idx := strings.IndexByte(stripped, '=')
		if idx < 0 {
			// Bare flag: treat as boolean true.
			result[stripped] = true
			continue
		}
		key := stripped[:idx]
		value := stripped[idx+1:]
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// runClientTool connects to the MCP server and calls the given tool.
func runClientTool(ctx context.Context, toolName string, args []string) error {
	// Parse connection flags from args. Flags may appear anywhere in args.
	fs := flag.NewFlagSet("client-tool", flag.ContinueOnError)
	var flagAddr, flagToken, flagFormat string
	fs.StringVar(&flagAddr, "server-addr", "", "server address (host:port)")
	fs.StringVar(&flagToken, "token", "", "Bearer token")
	fs.StringVar(&flagFormat, "format", "json", "output format: json or table")
	fs.Usage = func() {} // suppress default usage on error

	// Separate connection flags from tool parameters.
	var connFlagArgs []string
	var toolParamArgs []string
	for _, a := range args {
		stripped := a
		if strings.HasPrefix(stripped, "--") {
			stripped = stripped[2:]
		} else if strings.HasPrefix(stripped, "-") && !strings.HasPrefix(stripped, "--") {
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
		default:
			toolParamArgs = append(toolParamArgs, a)
		}
	}

	if err := fs.Parse(connFlagArgs); err != nil {
		return err
	}

	addr, token, err := resolveClientConn(flagAddr, flagToken)
	if err != nil {
		return err
	}

	// Parse tool parameters from remaining args.
	params := parseToolArgs(toolParamArgs)

	// Build MCP endpoint URL.
	endpoint := "http://" + addr + "/mcp"

	// Build HTTP client with Bearer auth transport.
	httpClient := &http.Client{
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

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect to MCP server at %s: %w\n\nhint: start the server with 'yorishiro-proxy server'", addr, err)
	}
	defer session.Close()

	// Call the tool.
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name:      toolName,
		Arguments: params,
	})
	if err != nil {
		return fmt.Errorf("call tool %q: %w", toolName, err)
	}

	// Output result as JSON.
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Println(string(b))
	return nil
}
