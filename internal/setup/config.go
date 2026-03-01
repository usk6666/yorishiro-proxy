package setup

// Options holds configuration for the setup command.
type Options struct {
	// Scope controls where MCP configuration is written.
	// "project" writes to .mcp.json in the current directory.
	// "user" writes to ~/.claude/settings.json.
	// Empty means the user should be prompted (interactive mode).
	Scope string

	// ListenAddr is the proxy listen address for MCP configuration.
	ListenAddr string

	// NonInteractive disables interactive prompts and uses defaults.
	NonInteractive bool

	// SkipPlaywright skips playwright-cli integration.
	SkipPlaywright bool

	// SkipSkills skips yorishiro skill installation.
	SkipSkills bool

	// BinaryPath overrides the auto-detected binary path for testing.
	BinaryPath string
}
