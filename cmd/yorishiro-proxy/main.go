package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	name, rest, err := routeCommand(args)
	if err != nil {
		return err
	}
	switch name {
	case "client":
		return runClient(ctx, rest)
	case "docs":
		return runDocs(os.Stdout, rest)
	case "install":
		return runInstall(ctx, rest)
	case "upgrade":
		return runUpgrade(ctx, rest)
	case "version":
		fmt.Println(buildVersion())
		return nil
	default:
		return runServer(ctx, flag.CommandLine, rest)
	}
}

// subcommandNames is the ordered list of top-level subcommands.
var subcommandNames = []string{"server", "client", "docs", "install", "upgrade", "version", "help"}

// routeCommand picks the subcommand for args (os.Args[1:]) and returns the
// arguments that subcommand receives. It is pure so every routing branch is
// unit-testable without starting a server.
func routeCommand(args []string) (name string, rest []string, err error) {
	if len(args) > 0 {
		switch args[0] {
		case "server", "client", "docs", "install", "upgrade", "version":
			return args[0], args[1:], nil
		}
	}
	// No subcommand: backward-compatible, behave like "server".
	return "server", args, nil
}

// runServer wires the CLI usage banner onto fs and delegates to
// mcpserver.Run, the production assembly entry point. mcpserver.Run owns
// the registration of every server-mode flag, so this wrapper only adds
// presentation concerns (Usage / version).
func runServer(ctx context.Context, fs *flag.FlagSet, args []string) error {
	fs.Usage = func() { printServerUsage(fs.Output(), fs) }
	return mcpserver.Run(ctx, fs, args, mcpserver.RunOptions{
		Version:      version,
		PolicyReload: sighupPolicyReload,
	})
}

// printServerUsage writes the top-level usage banner (the -h output) to w.
// fs supplies the server flag defaults; mcpserver.Run registers them before
// fs.Usage can fire.
func printServerUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "yorishiro-proxy %s\n\n", buildVersion())
	fmt.Fprintf(w, "Usage: yorishiro-proxy [subcommand] [flags]\n\n")
	fmt.Fprintf(w, "yorishiro-proxy is an AI agent network proxy (MCP server).\n")
	fmt.Fprintf(w, "By default it starts an HTTP MCP server on a random loopback port\n")
	fmt.Fprintf(w, "and writes the address and token to ~/.yorishiro-proxy/server.json.\n\n")
	fmt.Fprintf(w, "Subcommands:\n")
	fmt.Fprintf(w, "  server   Start the proxy server (default when no subcommand given)\n")
	fmt.Fprintf(w, "  client   Call MCP tools via CLI\n")
	fmt.Fprintf(w, "  docs     Show tool documentation (works offline)\n")
	fmt.Fprintf(w, "  install  Install and configure components (MCP, CA, Playwright)\n")
	fmt.Fprintf(w, "  upgrade  Check for and install updates from GitHub Releases\n")
	fmt.Fprintf(w, "  version  Print version information\n\n")
	fmt.Fprintf(w, "Server flags:\n")
	out := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(out)
	fmt.Fprintf(w, "\nEnvironment variables:\n")
	fmt.Fprintf(w, "  All flags accept a YP_ prefixed environment variable as fallback.\n")
	fmt.Fprintf(w, "  Priority: CLI flag > environment variable > config file > default value.\n")
	fmt.Fprintf(w, "  Naming: replace hyphens with underscores, uppercase (e.g. -log-level -> YP_LOG_LEVEL).\n")
	fmt.Fprintf(w, "\nSignals (Unix):\n")
	fmt.Fprintf(w, "  SIGHUP  re-read the target scope policy (-target-policy-file, else -config) and\n")
	fmt.Fprintf(w, "          replace the running Policy Layer; an invalid file is rejected and the\n")
	fmt.Fprintf(w, "          current policy kept. Without either flag SIGHUP terminates as before.\n")
	fmt.Fprintf(w, "          The handler is installed once the boot policy loads (log line \"target\n")
	fmt.Fprintf(w, "          scope policy reload enabled\"); with it, closing the launching terminal\n")
	fmt.Fprintf(w, "          reloads instead of stopping the server.\n")
	fmt.Fprintf(w, "\nExamples:\n")
	fmt.Fprintf(w, "  yorishiro-proxy server                           # HTTP MCP on random port (default)\n")
	fmt.Fprintf(w, "  yorishiro-proxy server -stdio-mcp                # HTTP MCP + stdio MCP\n")
	fmt.Fprintf(w, "  yorishiro-proxy server -no-http-mcp -stdio-mcp   # stdio MCP only\n")
	fmt.Fprintf(w, "  yorishiro-proxy server -mcp-http-addr 127.0.0.1:3000  # fixed port\n")
	fmt.Fprintf(w, "  yorishiro-proxy server -open-browser             # open WebUI on start\n")
	fmt.Fprintf(w, "  yorishiro-proxy install                          # install all components\n")
	fmt.Fprintf(w, "  yorishiro-proxy install mcp                      # register MCP config only\n")
	fmt.Fprintf(w, "  yorishiro-proxy install ca --trust               # generate CA + register in OS\n")
	fmt.Fprintf(w, "  yorishiro-proxy docs macro                       # print a reference (no server needed)\n")
	fmt.Fprintf(w, "  yorishiro-proxy -db pentest-2026                 # project DB: ~/.yorishiro-proxy/pentest-2026.db\n")
	fmt.Fprintf(w, "  YP_DB=client-audit yorishiro-proxy               # project name via env var\n")
	fmt.Fprintf(w, "  YP_INSECURE=true yorishiro-proxy                  # skip TLS verification\n")
}
