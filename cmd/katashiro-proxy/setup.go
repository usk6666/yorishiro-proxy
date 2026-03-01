package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/usk6666/katashiro-proxy/internal/setup"
)

// runSetup handles the "setup" subcommand.
func runSetup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)

	var opts setup.Options
	opts.ListenAddr = "127.0.0.1:8080" // default

	fs.StringVar(&opts.Scope, "scope", "", "MCP config scope: project (.mcp.json) or user (~/.claude/settings.json)")
	fs.StringVar(&opts.ListenAddr, "listen-addr", opts.ListenAddr, "proxy listen address")
	fs.BoolVar(&opts.NonInteractive, "non-interactive", false, "run without interactive prompts, using defaults")
	fs.BoolVar(&opts.SkipPlaywright, "skip-playwright", false, "skip playwright-cli integration")
	fs.BoolVar(&opts.SkipSkills, "skip-skills", false, "skip skill installation")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: katashiro-proxy setup [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Interactive setup wizard for Claude Code integration.\n")
		fmt.Fprintf(fs.Output(), "Configures MCP server, CA certificate, and optional integrations.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate scope if provided.
	if opts.Scope != "" && opts.Scope != "project" && opts.Scope != "user" {
		return fmt.Errorf("invalid --scope value %q: must be \"project\" or \"user\"", opts.Scope)
	}

	prompter := setup.NewStdinPrompter(os.Stdin, os.Stderr)
	runner := setup.NewRunner(opts, prompter, os.Stderr)

	return runner.Run(ctx)
}
