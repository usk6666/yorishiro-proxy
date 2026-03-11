package setup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Prompter reads user input for interactive prompts.
type Prompter interface {
	// Prompt displays a message and returns the user's input.
	Prompt(message string) (string, error)
}

// StdinPrompter reads input from stdin.
type StdinPrompter struct {
	reader *bufio.Reader
	writer io.Writer
}

// NewStdinPrompter creates a prompter that reads from stdin and writes to the given writer.
func NewStdinPrompter(r io.Reader, w io.Writer) *StdinPrompter {
	return &StdinPrompter{
		reader: bufio.NewReader(r),
		writer: w,
	}
}

// Prompt displays a message and reads a line from stdin.
func (p *StdinPrompter) Prompt(message string) (string, error) {
	fmt.Fprint(p.writer, message)
	line, err := p.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Runner orchestrates the setup/install process.
type Runner struct {
	opts     Options
	prompter Prompter
	out      io.Writer
	now      func() time.Time
}

// NewRunner creates a new setup runner.
func NewRunner(opts Options, prompter Prompter, out io.Writer) *Runner {
	return &Runner{
		opts:     opts,
		prompter: prompter,
		out:      out,
		now:      time.Now,
	}
}

// SetNowFunc overrides the time function for testing.
func (r *Runner) SetNowFunc(fn func() time.Time) {
	r.now = fn
}

// Run executes the full setup flow (legacy interactive mode).
func (r *Runner) Run(ctx context.Context) error {
	r.printf("\n=== yorishiro-proxy setup ===\n\n")

	// Resolve binary path.
	binaryPath := r.opts.BinaryPath
	if binaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve binary path: %w", err)
		}
		binaryPath = exe
	}
	r.printf("Binary: %s\n\n", binaryPath)

	// Step 1: MCP configuration (optional).
	if !r.opts.SkipMCPConfig {
		if err := r.stepMCPConfig(binaryPath); err != nil {
			return fmt.Errorf("MCP config: %w", err)
		}
	} else {
		r.printf("--- Step 1: MCP configuration (skipped) ---\n\n")
	}

	// Step 2: CA certificate.
	caInfo, err := r.stepCACert()
	if err != nil {
		return fmt.Errorf("CA cert: %w", err)
	}

	// Step 3: Playwright integration (optional).
	if !r.opts.SkipPlaywright {
		if err := r.stepPlaywright(caInfo); err != nil {
			return fmt.Errorf("playwright: %w", err)
		}
	} else {
		r.printf("--- Step 3: playwright-cli integration (skipped) ---\n\n")
	}

	// Step 4: Skills installation (optional).
	if !r.opts.SkipSkills {
		if err := r.stepSkills(); err != nil {
			return fmt.Errorf("skills: %w", err)
		}
	} else {
		r.printf("--- Step 4: Skill installation (skipped) ---\n\n")
	}

	// Step 5: Verification.
	if err := r.stepVerify(ctx, binaryPath); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	r.printf("=== Setup complete! ===\n")
	r.printf("Restart Claude Code to activate the yorishiro-proxy MCP server.\n\n")

	return nil
}

// Install executes the install flow for a specific target or all targets.
func (r *Runner) Install(ctx context.Context) error {
	r.printf("\n=== yorishiro-proxy install ===\n\n")

	// Resolve binary path.
	binaryPath := r.opts.BinaryPath
	if binaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve binary path: %w", err)
		}
		binaryPath = exe
	}
	r.printf("Binary: %s\n\n", binaryPath)

	switch r.opts.Target {
	case TargetMCP:
		return r.installMCP(binaryPath)
	case TargetCA:
		return r.installCA()
	case TargetSkills:
		return r.installSkills()
	case TargetPlaywright:
		return r.installPlaywright()
	default:
		return r.installAll(ctx, binaryPath)
	}
}

// installAll runs all install targets sequentially.
func (r *Runner) installAll(ctx context.Context, binaryPath string) error {
	// MCP configuration.
	if err := r.installMCP(binaryPath); err != nil {
		return fmt.Errorf("MCP config: %w", err)
	}

	// CA certificate.
	if err := r.installCA(); err != nil {
		return fmt.Errorf("CA cert: %w", err)
	}

	// Skills installation.
	if err := r.installSkills(); err != nil {
		return fmt.Errorf("skills: %w", err)
	}

	// Verification.
	r.printf("--- Verification ---\n\n")
	r.printf("  Testing MCP server startup...")
	if err := VerifyMCPServer(ctx, binaryPath); err != nil {
		r.printf(" FAILED\n")
		r.printf("  Warning: %v\n", err)
		r.printf("  The MCP server may not start correctly. Check the binary path and logs.\n\n")
	} else {
		r.printf(" OK\n\n")
	}

	r.printf("=== Install complete! ===\n")
	r.printf("Restart Claude Code to activate the yorishiro-proxy MCP server.\n\n")

	return nil
}

// installMCP installs MCP configuration.
func (r *Runner) installMCP(binaryPath string) error {
	r.printf("--- MCP configuration ---\n\n")

	scope := r.opts.Scope
	if scope == "" {
		if r.opts.Interactive {
			answer, err := r.prompter.Prompt("MCP config scope - (1) project (.mcp.json) (2) user (~/.claude/settings.json)? [1]: ")
			if err != nil {
				return fmt.Errorf("prompt scope: %w", err)
			}
			switch strings.TrimSpace(answer) {
			case "2", "user":
				scope = "user"
			default:
				scope = "project"
			}
		} else {
			scope = "project"
		}
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	configPath, err := MCPConfigPath(scope, projectDir)
	if err != nil {
		return err
	}

	backupPath, err := WriteMCPConfig(configPath, binaryPath, r.now())
	if err != nil {
		return err
	}

	r.printf("  Wrote: %s\n", configPath)
	if backupPath != "" {
		r.printf("  Backup: %s\n", backupPath)
	}
	r.printf("\n")

	return nil
}

// installCA generates or loads the CA certificate.
func (r *Runner) installCA() error {
	r.printf("--- CA certificate ---\n\n")

	caDir := r.opts.CADir
	caInfo, err := EnsureCA(caDir)
	if err != nil {
		return err
	}

	if caInfo.Generated {
		r.printf("  Generated new CA certificate.\n")
	} else {
		r.printf("  CA certificate already exists.\n")
	}
	r.printf("  Path: %s\n", caInfo.CertPath)
	r.printf("  Fingerprint (SHA-256): %s\n\n", caInfo.Fingerprint)

	if r.opts.Trust {
		r.printf("  Registering CA in OS trust store...\n")
		if err := TrustCA(caInfo.CertPath); err != nil {
			return fmt.Errorf("trust CA: %w", err)
		}
		r.printf("  CA certificate registered in OS trust store.\n\n")
	} else {
		r.printf("%s\n", CAInstallInstructions(caInfo.CertPath))
	}

	return nil
}

// installSkills installs skill files.
func (r *Runner) installSkills() error {
	r.printf("--- Skills installation ---\n\n")

	if r.opts.Interactive {
		answer, err := r.prompter.Prompt("  Install yorishiro skills to .claude/skills/yorishiro/? [Y/n]: ")
		if err != nil {
			return fmt.Errorf("prompt skills: %w", err)
		}
		if strings.ToLower(strings.TrimSpace(answer)) == "n" {
			r.printf("  Skipping skill installation.\n\n")
			return nil
		}
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	skillsDir := projectDir
	if r.opts.SkillsDir != "" {
		skillsDir = r.opts.SkillsDir
	}

	installed, backupPath, err := InstallSkills(skillsDir, r.now())
	if err != nil {
		return err
	}

	if backupPath != "" {
		r.printf("  Backed up existing skills to: %s\n", backupPath)
	}
	for _, f := range installed {
		r.printf("  Installed: .claude/skills/yorishiro/%s\n", f)
	}
	r.printf("\n")

	return nil
}

// installPlaywright configures Playwright integration.
func (r *Runner) installPlaywright() error {
	r.printf("--- Playwright integration ---\n\n")

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if !DetectPlaywright(projectDir) {
		r.printf("  playwright-cli not detected. Skipping.\n\n")
		return nil
	}

	r.printf("  playwright-cli detected.\n")

	httpsOption := r.resolvePlaywrightHTTPSOption()

	if httpsOption == PlaywrightHTTPSSkip {
		r.printf("  Skipping playwright HTTPS configuration.\n\n")
		return nil
	}

	if httpsOption == PlaywrightHTTPSCA || httpsOption == PlaywrightHTTPSBoth {
		caInfo, err := EnsureCA(r.opts.CADir)
		if err != nil {
			return fmt.Errorf("ensure CA for playwright: %w", err)
		}
		r.printf("\n%s\n", CAInstallInstructions(caInfo.CertPath))
	}

	if httpsOption == PlaywrightHTTPSIgnore || httpsOption == PlaywrightHTTPSBoth {
		if err := r.writePlaywrightConfigFile(projectDir, httpsOption); err != nil {
			return err
		}
	}

	r.printf("\n")
	return nil
}

// resolvePlaywrightHTTPSOption determines the HTTPS handling option for Playwright.
// In non-interactive mode, defaults to PlaywrightHTTPSIgnore.
func (r *Runner) resolvePlaywrightHTTPSOption() PlaywrightHTTPSOption {
	if !r.opts.Interactive {
		return PlaywrightHTTPSIgnore
	}
	answer, err := r.prompter.Prompt("  HTTPS error handling:\n  (1) ignoreHTTPSErrors: true\n  (2) CA certificate install guide\n  (3) Both\n  (4) Skip\n  Choice [1]: ")
	if err != nil {
		return PlaywrightHTTPSIgnore
	}
	switch strings.TrimSpace(answer) {
	case "2":
		return PlaywrightHTTPSCA
	case "3":
		return PlaywrightHTTPSBoth
	case "4":
		return PlaywrightHTTPSSkip
	default:
		return PlaywrightHTTPSIgnore
	}
}

// writePlaywrightConfigFile writes the Playwright configuration and reports the result.
func (r *Runner) writePlaywrightConfigFile(projectDir string, httpsOption PlaywrightHTTPSOption) error {
	backupPath, err := WritePlaywrightConfig(projectDir, r.opts.ListenAddr, httpsOption, r.now())
	if err != nil {
		return err
	}
	configPath := PlaywrightConfigPath(projectDir)
	r.printf("  Wrote: %s\n", configPath)
	if backupPath != "" {
		r.printf("  Backup: %s\n", backupPath)
	}
	return nil
}

// --- Legacy step methods (used by Run/setup wizard) ---

func (r *Runner) stepMCPConfig(binaryPath string) error {
	r.printf("--- Step 1: MCP configuration ---\n\n")

	scope := r.opts.Scope
	if scope == "" {
		if r.opts.NonInteractive {
			scope = "project"
		} else {
			answer, err := r.prompter.Prompt("MCP config scope - (1) project (.mcp.json) (2) user (~/.claude/settings.json) (3) skip? [1]: ")
			if err != nil {
				return fmt.Errorf("prompt scope: %w", err)
			}
			switch strings.TrimSpace(answer) {
			case "2", "user":
				scope = "user"
			case "3", "skip":
				r.printf("  Skipping MCP configuration.\n\n")
				return nil
			default:
				scope = "project"
			}
		}
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	configPath, err := MCPConfigPath(scope, projectDir)
	if err != nil {
		return err
	}

	backupPath, err := WriteMCPConfig(configPath, binaryPath, r.now())
	if err != nil {
		return err
	}

	r.printf("  Wrote: %s\n", configPath)
	if backupPath != "" {
		r.printf("  Backup: %s\n", backupPath)
	}
	r.printf("\n")

	return nil
}

func (r *Runner) stepCACert() (*CAInfo, error) {
	r.printf("--- Step 2: CA certificate ---\n\n")

	caInfo, err := EnsureCA("")
	if err != nil {
		return nil, err
	}

	if caInfo.Generated {
		r.printf("  Generated new CA certificate.\n")
	} else {
		r.printf("  CA certificate already exists.\n")
	}
	r.printf("  Path: %s\n", caInfo.CertPath)
	r.printf("  Fingerprint (SHA-256): %s\n\n", caInfo.Fingerprint)

	r.printf("%s\n", CAInstallInstructions(caInfo.CertPath))

	return caInfo, nil
}

func (r *Runner) stepPlaywright(caInfo *CAInfo) error {
	r.printf("--- Step 3: playwright-cli integration ---\n\n")

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if !DetectPlaywright(projectDir) {
		r.printf("  playwright-cli not detected. Skipping.\n\n")
		return nil
	}

	r.printf("  playwright-cli detected.\n")

	// Determine HTTPS handling option.
	httpsOption := PlaywrightHTTPSIgnore // default
	if !r.opts.NonInteractive {
		answer, err := r.prompter.Prompt("  HTTPS error handling:\n  (1) ignoreHTTPSErrors: true\n  (2) CA certificate install guide\n  (3) Both\n  (4) Skip\n  Choice [1]: ")
		if err != nil {
			return fmt.Errorf("prompt HTTPS option: %w", err)
		}
		switch strings.TrimSpace(answer) {
		case "2":
			httpsOption = PlaywrightHTTPSCA
		case "3":
			httpsOption = PlaywrightHTTPSBoth
		case "4":
			httpsOption = PlaywrightHTTPSSkip
		default:
			httpsOption = PlaywrightHTTPSIgnore
		}
	}

	if httpsOption == PlaywrightHTTPSSkip {
		r.printf("  Skipping playwright HTTPS configuration.\n\n")
		return nil
	}

	if httpsOption == PlaywrightHTTPSCA || httpsOption == PlaywrightHTTPSBoth {
		r.printf("\n%s\n", CAInstallInstructions(caInfo.CertPath))
	}

	if httpsOption == PlaywrightHTTPSIgnore || httpsOption == PlaywrightHTTPSBoth {
		backupPath, err := WritePlaywrightConfig(projectDir, r.opts.ListenAddr, httpsOption, r.now())
		if err != nil {
			return err
		}
		configPath := PlaywrightConfigPath(projectDir)
		r.printf("  Wrote: %s\n", configPath)
		if backupPath != "" {
			r.printf("  Backup: %s\n", backupPath)
		}
	}

	r.printf("\n")
	return nil
}

func (r *Runner) stepSkills() error {
	r.printf("--- Step 4: Skill installation ---\n\n")

	if !r.opts.NonInteractive {
		answer, err := r.prompter.Prompt("  Install yorishiro skills to .claude/skills/yorishiro/? [Y/n]: ")
		if err != nil {
			return fmt.Errorf("prompt skills: %w", err)
		}
		if strings.ToLower(strings.TrimSpace(answer)) == "n" {
			r.printf("  Skipping skill installation.\n\n")
			return nil
		}
	}

	projectDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	installed, backupPath, err := InstallSkills(projectDir, r.now())
	if err != nil {
		return err
	}

	if backupPath != "" {
		r.printf("  Backed up existing skills to: %s\n", backupPath)
	}
	for _, f := range installed {
		r.printf("  Installed: .claude/skills/yorishiro/%s\n", f)
	}
	r.printf("\n")

	return nil
}

func (r *Runner) stepVerify(ctx context.Context, binaryPath string) error {
	r.printf("--- Step 5: Verification ---\n\n")

	r.printf("  Testing MCP server startup...")
	if err := VerifyMCPServer(ctx, binaryPath); err != nil {
		r.printf(" FAILED\n")
		r.printf("  Warning: %v\n", err)
		r.printf("  The MCP server may not start correctly. Check the binary path and logs.\n\n")
		// Don't fail setup for verification issues.
		return nil
	}
	r.printf(" OK\n\n")

	return nil
}

func (r *Runner) printf(format string, args ...any) {
	fmt.Fprintf(r.out, format, args...)
}
