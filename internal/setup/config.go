package setup

// Target represents a specific install target.
type Target string

const (
	// TargetAll runs all install targets.
	TargetAll Target = ""
	// TargetMCP installs MCP configuration only.
	TargetMCP Target = "mcp"
	// TargetCA generates CA certificate only.
	TargetCA Target = "ca"
	// TargetSkills installs skills only.
	TargetSkills Target = "skills"
	// TargetPlaywright configures Playwright integration only.
	TargetPlaywright Target = "playwright"
)

// Options holds configuration for the install command.
type Options struct {
	// Target selects which install target to run.
	// Empty string means all targets.
	Target Target

	// Scope controls where MCP configuration is written.
	// "project" writes to .mcp.json in the current directory.
	// "user" writes to ~/.claude/settings.json.
	// Empty means project scope (default for non-interactive).
	Scope string

	// ListenAddr is the proxy listen address for MCP configuration.
	ListenAddr string

	// Interactive enables interactive prompts.
	Interactive bool

	// Trust enables OS trust store registration for the CA certificate.
	Trust bool

	// CADir overrides the CA certificate output directory.
	CADir string

	// SkillsDir overrides the skills installation directory.
	SkillsDir string

	// BinaryPath overrides the auto-detected binary path for testing.
	BinaryPath string

}
