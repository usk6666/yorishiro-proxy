package setup

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// browserDetection holds the result of browser auto-detection.
type browserDetection struct {
	// browserName is the Playwright browser name ("chromium" or "firefox").
	browserName string
	// channel is the Playwright channel (e.g., "chromium", "chrome"), empty for Firefox.
	channel string
	// isChromium indicates whether the detected browser is Chromium-based.
	isChromium bool
	// installTarget is the argument to pass to `npx playwright install`.
	installTarget string
}

// browserCandidate represents a known browser binary and its metadata.
type browserCandidate struct {
	name          string // e.g., "chromium", "firefox", "chrome"
	browserName   string // Playwright browserName
	channel       string // Playwright channel (empty for firefox)
	isChromium    bool
	installTarget string // npx playwright install <target>
	paths         map[string][]string
}

var defaultCandidates = []browserCandidate{
	{
		name:          "chromium",
		browserName:   "chromium",
		channel:       "chromium",
		isChromium:    true,
		installTarget: "chromium",
		paths: map[string][]string{
			"linux":   {"/usr/bin/chromium", "/usr/bin/chromium-browser"},
			"darwin":  {"/Applications/Chromium.app/Contents/MacOS/Chromium"},
			"windows": {},
		},
	},
	{
		name:          "firefox",
		browserName:   "firefox",
		channel:       "",
		isChromium:    false,
		installTarget: "firefox",
		paths: map[string][]string{
			"linux":   {"/usr/bin/firefox"},
			"darwin":  {"/Applications/Firefox.app/Contents/MacOS/firefox"},
			"windows": {`C:\Program Files\Mozilla Firefox\firefox.exe`},
		},
	},
	{
		name:          "chrome",
		browserName:   "chromium",
		channel:       "chrome",
		isChromium:    true,
		installTarget: "chrome",
		paths: map[string][]string{
			"linux":   {"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"},
			"darwin":  {"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
			"windows": {`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`},
		},
	},
}

// fileExistsFunc is the function used to check file existence.
// Replaceable for testing.
var fileExistsFunc = fileExists

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// detectBrowserChannel scans known browser paths and returns the best match.
// Priority: chromium > firefox > chrome.
func detectBrowserChannel() browserDetection {
	goos := runtime.GOOS
	for _, c := range defaultCandidates {
		paths := c.paths[goos]
		for _, p := range paths {
			if fileExistsFunc(p) {
				slog.Debug("detected browser", "browser", c.name, "path", p)
				return browserDetection{
					browserName:   c.browserName,
					channel:       c.channel,
					isChromium:    c.isChromium,
					installTarget: c.installTarget,
				}
			}
		}
	}
	// Default: chromium (not found, will be installed)
	slog.Debug("no browser detected, defaulting to chromium")
	return browserDetection{
		browserName:   "chromium",
		channel:       "",
		isChromium:    true,
		installTarget: "chromium",
	}
}

// containerCheckFunc is the function used to check container indicators.
// Replaceable for testing.
var containerCheckFunc = defaultContainerCheck

type containerCheck struct {
	hasDockerenv bool
	envVars      map[string]string
	cgroupData   string
}

func defaultContainerCheck() containerCheck {
	envKeys := []string{"REMOTE_CONTAINERS", "CODESPACES", "GITPOD_WORKSPACE_ID"}
	envVars := make(map[string]string)
	for _, key := range envKeys {
		if v, ok := os.LookupEnv(key); ok {
			envVars[key] = v
		}
	}

	hasDockerenv := fileExists("/.dockerenv")

	var cgroupData string
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		cgroupData = string(data)
	}

	return containerCheck{
		hasDockerenv: hasDockerenv,
		envVars:      envVars,
		cgroupData:   cgroupData,
	}
}

// isContainerEnvironment detects if the process is running inside a container.
func isContainerEnvironment() bool {
	check := containerCheckFunc()

	if check.hasDockerenv {
		slog.Debug("container detected via /.dockerenv")
		return true
	}

	for key := range check.envVars {
		slog.Debug("container detected via env", "key", key)
		return true
	}

	if strings.Contains(check.cgroupData, "docker") || strings.Contains(check.cgroupData, "containerd") {
		slog.Debug("container detected via cgroup")
		return true
	}

	return false
}

// applyNoSandbox adds --no-sandbox to launchOptions.args if the browser is Chromium-based
// and the environment is a container. Preserves existing args and avoids duplicates.
func applyNoSandbox(browser map[string]json.RawMessage, isChromium bool) error {
	if !isChromium || !isContainerEnvironment() {
		return nil
	}

	launchOptions, err := unmarshalJSONSection(browser, "launchOptions")
	if err != nil {
		return fmt.Errorf("parse launchOptions for no-sandbox: %w", err)
	}

	var args []string
	if raw, ok := launchOptions["args"]; ok {
		if err := json.Unmarshal(raw, &args); err != nil {
			return fmt.Errorf("parse launchOptions.args: %w", err)
		}
	}

	// Check for duplicates.
	for _, arg := range args {
		if arg == "--no-sandbox" {
			return nil // Already present.
		}
	}

	args = append(args, "--no-sandbox")
	argsJSON, _ := json.Marshal(args)
	launchOptions["args"] = argsJSON

	launchOptionsJSON, _ := json.Marshal(launchOptions)
	browser["launchOptions"] = launchOptionsJSON

	slog.Debug("added --no-sandbox to launchOptions.args")
	return nil
}

// extractChannel extracts the channel value from a config JSON bytes.
// Returns empty string if channel is not set or on parse error.
func extractChannel(configData []byte) string {
	if len(configData) == 0 {
		return ""
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return ""
	}

	browserRaw, ok := cfg["browser"]
	if !ok {
		return ""
	}

	var browser map[string]json.RawMessage
	if err := json.Unmarshal(browserRaw, &browser); err != nil {
		return ""
	}

	loRaw, ok := browser["launchOptions"]
	if !ok {
		return ""
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(loRaw, &lo); err != nil {
		return ""
	}

	chRaw, ok := lo["channel"]
	if !ok {
		return ""
	}

	var ch string
	if err := json.Unmarshal(chRaw, &ch); err != nil {
		return ""
	}
	return ch
}

// detectionFromChannel creates a browserDetection from a channel string.
// This is used when the config already has a channel set.
func detectionFromChannel(channel string) browserDetection {
	for _, c := range defaultCandidates {
		if c.channel == channel || c.installTarget == channel {
			return browserDetection{
				browserName:   c.browserName,
				channel:       c.channel,
				isChromium:    c.isChromium,
				installTarget: c.installTarget,
			}
		}
	}
	// Default to chromium if channel is unknown.
	return browserDetection{
		browserName:   "chromium",
		channel:       channel,
		isChromium:    true,
		installTarget: "chromium",
	}
}

// isBrowserInstalled checks if a browser binary is available for the given detection result.
func isBrowserInstalled(det browserDetection) bool {
	goos := runtime.GOOS
	for _, c := range defaultCandidates {
		if c.installTarget != det.installTarget {
			continue
		}
		paths := c.paths[goos]
		for _, p := range paths {
			if fileExistsFunc(p) {
				return true
			}
		}
	}
	return false
}

// EnsureBrowserInstalled checks if the browser is installed and runs
// `npx playwright install <browser>` if not. Returns an error message for
// display purposes only; callers should not treat this as a hard error.
func EnsureBrowserInstalled(det browserDetection) error {
	if isBrowserInstalled(det) {
		slog.Debug("browser already installed", "target", det.installTarget)
		return nil
	}

	npxPath, err := exec.LookPath("npx")
	if err != nil {
		return fmt.Errorf("npx not found in PATH. Please install the browser manually:\n  npx playwright install %s", det.installTarget)
	}

	slog.Info("installing browser via playwright", "target", det.installTarget)
	cmd := exec.Command(npxPath, "playwright", "install", det.installTarget)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("playwright install failed: %w\n  Please install the browser manually:\n  npx playwright install %s", err, det.installTarget)
	}

	return nil
}
