package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// Check for subcommands before parsing flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "server":
			return runServer(ctx, flag.CommandLine, os.Args[2:])
		case "client":
			return runClient(ctx, os.Args[2:])
		case "install":
			return runInstall(ctx, os.Args[2:])
		case "upgrade":
			return runUpgrade(ctx, os.Args[2:])
		case "version":
			fmt.Println(buildVersion())
			return nil
		}
	}
	// No subcommand: backward-compatible, behave like "server".
	return runServer(ctx, flag.CommandLine, os.Args[1:])
}

// runServer wires the CLI usage banner onto fs and delegates to
// mcpserver.Run, the production assembly entry point. mcpserver.Run owns
// the registration of every server-mode flag, so this wrapper only adds
// presentation concerns (Usage / version).
func runServer(ctx context.Context, fs *flag.FlagSet, args []string) error {
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "yorishiro-proxy %s\n\n", buildVersion())
		fmt.Fprintf(fs.Output(), "Usage: yorishiro-proxy [subcommand] [flags]\n\n")
		fmt.Fprintf(fs.Output(), "yorishiro-proxy is an AI agent network proxy (MCP server).\n")
		fmt.Fprintf(fs.Output(), "By default it starts an HTTP MCP server on a random loopback port\n")
		fmt.Fprintf(fs.Output(), "and writes the address and token to ~/.yorishiro-proxy/server.json.\n\n")
		fmt.Fprintf(fs.Output(), "Subcommands:\n")
		fmt.Fprintf(fs.Output(), "  server   Start the proxy server (default when no subcommand given)\n")
		fmt.Fprintf(fs.Output(), "  client   Call MCP tools via CLI\n")
		fmt.Fprintf(fs.Output(), "  install  Install and configure components (MCP, CA, Playwright)\n")
		fmt.Fprintf(fs.Output(), "  upgrade  Check for and install updates from GitHub Releases\n")
		fmt.Fprintf(fs.Output(), "  version  Print version information\n\n")
		fmt.Fprintf(fs.Output(), "Server flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment variables:\n")
		fmt.Fprintf(fs.Output(), "  All flags accept a YP_ prefixed environment variable as fallback.\n")
		fmt.Fprintf(fs.Output(), "  Priority: CLI flag > environment variable > config file > default value.\n")
		fmt.Fprintf(fs.Output(), "  Naming: replace hyphens with underscores, uppercase (e.g. -log-level -> YP_LOG_LEVEL).\n")
		fmt.Fprintf(fs.Output(), "\nExamples:\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy server                           # HTTP MCP on random port (default)\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy server -stdio-mcp                # HTTP MCP + stdio MCP\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy server -no-http-mcp -stdio-mcp   # stdio MCP only\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy server -mcp-http-addr 127.0.0.1:3000  # fixed port\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy server -open-browser             # open WebUI on start\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install                          # install all components\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install mcp                      # register MCP config only\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy install ca --trust               # generate CA + register in OS\n")
		fmt.Fprintf(fs.Output(), "  yorishiro-proxy -db pentest-2026                 # project DB: ~/.yorishiro-proxy/pentest-2026.db\n")
		fmt.Fprintf(fs.Output(), "  YP_DB=client-audit yorishiro-proxy               # project name via env var\n")
		fmt.Fprintf(fs.Output(), "  YP_INSECURE=true yorishiro-proxy                  # skip TLS verification\n")
	}
	return mcpserver.Run(ctx, fs, args, mcpserver.RunOptions{
		Version: version,
	})
}
