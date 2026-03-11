package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/usk6666/yorishiro-proxy/internal/setup"
)

// validInstallTargets lists the recognized install sub-targets.
var validInstallTargets = map[string]setup.Target{
	"mcp":        setup.TargetMCP,
	"ca":         setup.TargetCA,
	"skills":     setup.TargetSkills,
	"playwright": setup.TargetPlaywright,
}

// runInstall handles the "install" subcommand.
func runInstall(ctx context.Context, args []string) error {
	// Determine target before parsing flags.
	// install [target] [flags] — target is the first non-flag argument.
	target, flagArgs, err := parseInstallTarget(args)
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("install", flag.ContinueOnError)

	var opts setup.Options
	opts.Target = target
	opts.ListenAddr = "127.0.0.1:8080" // default

	// Common flags.
	fs.BoolVar(&opts.Interactive, "interactive", false, "enable interactive prompts (wizard mode)")

	// MCP / all target flags.
	var userScope bool
	fs.BoolVar(&userScope, "user-scope", false, "register in user scope (~/.claude/settings.json) instead of project (.mcp.json)")
	fs.StringVar(&opts.ListenAddr, "listen-addr", opts.ListenAddr, "proxy listen address")

	// CA target flags.
	fs.BoolVar(&opts.Trust, "trust", false, "register CA in OS trust store (requires sudo)")
	fs.StringVar(&opts.CADir, "ca-dir", "", "CA certificate output directory")

	// Skills target flags.
	fs.StringVar(&opts.SkillsDir, "skills-dir", "", "skills installation directory")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: yorishiro-proxy install [target] [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Install and configure yorishiro-proxy components.\n\n")
		fmt.Fprintf(fs.Output(), "Targets:\n")
		fmt.Fprintf(fs.Output(), "  (none)       Install all components (MCP + CA + Skills)\n")
		fmt.Fprintf(fs.Output(), "  mcp          Register MCP configuration only\n")
		fmt.Fprintf(fs.Output(), "  ca           Generate CA certificate only\n")
		fmt.Fprintf(fs.Output(), "  skills       Install skills only\n")
		fmt.Fprintf(fs.Output(), "  playwright   Configure Playwright integration only\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fmt.Fprintf(fs.Output(), "  --interactive     Enable interactive prompts (wizard mode)\n")
		fmt.Fprintf(fs.Output(), "  --user-scope      Register in user scope (~/.claude/settings.json)\n")
		fmt.Fprintf(fs.Output(), "  --listen-addr     Proxy listen address (default: 127.0.0.1:8080)\n")
		fmt.Fprintf(fs.Output(), "  --trust           Register CA in OS trust store (requires sudo)\n")
		fmt.Fprintf(fs.Output(), "  --ca-dir          CA certificate output directory\n")
		fmt.Fprintf(fs.Output(), "  --skills-dir      Skills installation directory\n")
	}

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	// Handle --user-scope flag: set scope to "user".
	if userScope {
		opts.Scope = "user"
	}

	// Validate target-specific flags.
	if opts.Trust && opts.Target != setup.TargetCA && opts.Target != setup.TargetAll {
		return fmt.Errorf("--trust is only valid with the 'ca' target or no target (all)")
	}

	prompter := setup.NewStdinPrompter(os.Stdin, os.Stderr)
	runner := setup.NewRunner(opts, prompter, os.Stderr)

	return runner.Install(ctx)
}

// parseInstallTarget extracts the target from args, returning the target
// and the remaining args for flag parsing.
func parseInstallTarget(args []string) (setup.Target, []string, error) {
	if len(args) == 0 {
		return setup.TargetAll, args, nil
	}

	first := args[0]

	// If it starts with "-", it's a flag, not a target.
	if len(first) > 0 && first[0] == '-' {
		return setup.TargetAll, args, nil
	}

	target, ok := validInstallTargets[first]
	if !ok {
		return "", nil, fmt.Errorf("unknown install target %q: valid targets are mcp, ca, skills, playwright", first)
	}

	return target, args[1:], nil
}
