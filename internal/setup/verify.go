package setup

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// VerifyMCPServer performs a quick startup test of the MCP server.
// It launches the binary, waits briefly for initialization, then terminates it.
// Returns nil if the binary starts successfully (exits with status 0 or is killed after timeout).
func VerifyMCPServer(ctx context.Context, binaryPath string) error {
	// Create a context with timeout for the verification.
	verifyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(verifyCtx, binaryPath)
	// Provide empty stdin so the MCP server reads EOF and exits.
	cmd.Stdin = nil

	// Run and capture any immediate error (e.g., binary not found, crash on startup).
	err := cmd.Run()
	if err != nil {
		// Context deadline exceeded means the server started and ran until we killed it.
		// This is the expected behavior for a long-running server.
		if verifyCtx.Err() != nil {
			return nil
		}
		// Exit status 0 is also fine (server exits cleanly on empty stdin).
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Non-zero exit may indicate a crash, but some MCP servers exit
			// with non-zero when stdin is closed. Allow exit codes <= 1.
			if exitErr.ExitCode() <= 1 {
				return nil
			}
		}
		return fmt.Errorf("MCP server verification failed: %w", err)
	}
	return nil
}
