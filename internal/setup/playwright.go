package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// PlaywrightHTTPSOption represents the user's choice for handling HTTPS errors
// when using playwright-cli through the proxy.
type PlaywrightHTTPSOption int

const (
	// PlaywrightHTTPSIgnore sets ignoreHTTPSErrors: true.
	PlaywrightHTTPSIgnore PlaywrightHTTPSOption = iota + 1
	// PlaywrightHTTPSCA shows CA certificate install instructions.
	PlaywrightHTTPSCA
	// PlaywrightHTTPSBoth sets ignoreHTTPSErrors and shows CA install instructions.
	PlaywrightHTTPSBoth
	// PlaywrightHTTPSSkip skips HTTPS error handling configuration.
	PlaywrightHTTPSSkip
)

// PlaywrightConfigPath returns the path to the playwright-cli configuration file.
func PlaywrightConfigPath(projectDir string) string {
	return filepath.Join(projectDir, ".playwright", "cli.config.json")
}

// DetectPlaywright checks if playwright-cli is available.
// It checks both the PATH (via `which`) and the local .playwright/ directory.
func DetectPlaywright(projectDir string) bool {
	// Check if playwright-cli is in PATH.
	if _, err := exec.LookPath("playwright-cli"); err == nil {
		return true
	}

	// Check if .playwright/ directory exists.
	playwrightDir := filepath.Join(projectDir, ".playwright")
	if info, err := os.Stat(playwrightDir); err == nil && info.IsDir() {
		return true
	}

	return false
}

// WritePlaywrightConfig writes or updates the playwright-cli configuration file
// with proxy settings. If the file exists, it creates a backup and merges settings.
func WritePlaywrightConfig(projectDir, listenAddr string, httpsOption PlaywrightHTTPSOption, now time.Time) (backupPath string, err error) {
	configPath := PlaywrightConfigPath(projectDir)

	// Ensure .playwright directory exists.
	playwrightDir := filepath.Dir(configPath)
	if err := os.MkdirAll(playwrightDir, 0755); err != nil {
		return "", fmt.Errorf("create .playwright directory: %w", err)
	}

	existing, backupPath, err := readExistingConfig(configPath, now)
	if err != nil {
		return backupPath, err
	}

	browser, err := unmarshalJSONSection(existing, "browser")
	if err != nil {
		return backupPath, fmt.Errorf("parse browser config: %w", err)
	}

	det := detectBrowserChannel()

	// Set browserName if not already set.
	if _, ok := browser["browserName"]; !ok {
		browser["browserName"] = json.RawMessage(fmt.Sprintf("%q", det.browserName))
	}

	if err := applyProxySettings(browser, listenAddr, det); err != nil {
		return backupPath, err
	}

	if err := applyHTTPSOption(browser, httpsOption); err != nil {
		return backupPath, err
	}

	// Determine if the browser is Chromium-based for --no-sandbox.
	// Derive from the effective browserName in the merged config: only "chromium"
	// is Chromium-based; all others (firefox, webkit, etc.) are not.
	isChromium := det.isChromium
	if raw, ok := browser["browserName"]; ok {
		var bn string
		if json.Unmarshal(raw, &bn) == nil && bn != "" {
			isChromium = (bn == "chromium")
		}
	}

	if err := applyNoSandbox(browser, isChromium); err != nil {
		return backupPath, err
	}

	browserJSON, _ := json.Marshal(browser)
	existing["browser"] = browserJSON

	return backupPath, writeConfig(configPath, existing)
}

// readExistingConfig reads and parses an existing config file, creating a backup if it exists.
// Returns the parsed config (or an empty map), the backup path, and any error.
func readExistingConfig(configPath string, now time.Time) (map[string]json.RawMessage, string, error) {
	existingData, readErr := os.ReadFile(configPath)
	if os.IsNotExist(readErr) {
		return make(map[string]json.RawMessage), "", nil
	}
	if readErr != nil {
		return nil, "", fmt.Errorf("read existing playwright config: %w", readErr)
	}

	// File exists — back it up.
	backupPath, bErr := CreateBackup(configPath, now)
	if bErr != nil {
		return nil, "", fmt.Errorf("backup existing config: %w", bErr)
	}

	var existing map[string]json.RawMessage
	if err := json.Unmarshal(existingData, &existing); err != nil {
		return nil, backupPath, fmt.Errorf("parse existing playwright config: %w", err)
	}

	return existing, backupPath, nil
}

// unmarshalJSONSection extracts and unmarshals a nested JSON object from a parent map.
// If the key is missing, returns an empty map.
func unmarshalJSONSection(parent map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	result := make(map[string]json.RawMessage)
	raw, ok := parent[key]
	if !ok {
		return result, nil
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// applyProxySettings adds proxy configuration to the browser's launchOptions.
// The det parameter provides auto-detected browser defaults for channel.
func applyProxySettings(browser map[string]json.RawMessage, listenAddr string, det browserDetection) error {
	launchOptions, err := unmarshalJSONSection(browser, "launchOptions")
	if err != nil {
		return fmt.Errorf("parse launchOptions: %w", err)
	}

	// Set channel based on detected browser if not already set.
	// Only inject a Chromium channel when the effective browserName is "chromium";
	// non-Chromium browsers (firefox, webkit, etc.) do not use channels.
	effectiveIsChromium := true
	if raw, ok := browser["browserName"]; ok {
		var bn string
		if json.Unmarshal(raw, &bn) == nil && bn != "" {
			effectiveIsChromium = (bn == "chromium")
		}
	}
	if _, ok := launchOptions["channel"]; !ok && det.channel != "" && effectiveIsChromium {
		launchOptions["channel"] = json.RawMessage(fmt.Sprintf("%q", det.channel))
	}

	proxyServer := fmt.Sprintf("http://%s", listenAddr)
	proxyConfig := map[string]string{"server": proxyServer}
	proxyJSON, _ := json.Marshal(proxyConfig)
	launchOptions["proxy"] = proxyJSON

	launchOptionsJSON, _ := json.Marshal(launchOptions)
	browser["launchOptions"] = launchOptionsJSON
	return nil
}

// applyHTTPSOption configures contextOptions.ignoreHTTPSErrors if the HTTPS option requires it.
func applyHTTPSOption(browser map[string]json.RawMessage, httpsOption PlaywrightHTTPSOption) error {
	if httpsOption != PlaywrightHTTPSIgnore && httpsOption != PlaywrightHTTPSBoth {
		return nil
	}

	contextOptions, err := unmarshalJSONSection(browser, "contextOptions")
	if err != nil {
		return fmt.Errorf("parse contextOptions: %w", err)
	}
	contextOptions["ignoreHTTPSErrors"] = json.RawMessage(`true`)

	contextOptionsJSON, _ := json.Marshal(contextOptions)
	browser["contextOptions"] = contextOptionsJSON
	return nil
}

// writeConfig marshals and writes the configuration to disk.
func writeConfig(configPath string, config map[string]json.RawMessage) error {
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal playwright config: %w", err)
	}
	output = append(output, '\n')

	if err := os.WriteFile(configPath, output, 0644); err != nil {
		return fmt.Errorf("write playwright config: %w", err)
	}
	return nil
}
