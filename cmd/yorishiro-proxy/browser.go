package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowser opens the given URL in the user's default browser.
// It uses a platform-specific command (open, xdg-open, or cmd /c start)
// and runs it asynchronously via exec.Command().Start() so it does not
// block the caller. Errors are returned but should be treated as
// best-effort (logged as warning, not fatal).
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
