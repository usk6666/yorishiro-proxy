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

// Runner orchestrates the setup process.
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

// Run executes the full setup flow.
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
