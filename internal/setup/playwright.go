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

	// Read existing config if present.
	existingData, readErr := os.ReadFile(configPath)
	var existing map[string]json.RawMessage

	if readErr == nil {
		// File exists — back it up.
		bp, bErr := CreateBackup(configPath, now)
		if bErr != nil {
			return "", fmt.Errorf("backup existing config: %w", bErr)
		}
		backupPath = bp

		if err := json.Unmarshal(existingData, &existing); err != nil {
			return backupPath, fmt.Errorf("parse existing playwright config: %w", err)
		}
	} else if !os.IsNotExist(readErr) {
		return "", fmt.Errorf("read existing playwright config: %w", readErr)
	}

	if existing == nil {
		existing = make(map[string]json.RawMessage)
	}

	// Build/update browser section.
	var browser map[string]json.RawMessage
	if raw, ok := existing["browser"]; ok {
		if err := json.Unmarshal(raw, &browser); err != nil {
			return backupPath, fmt.Errorf("parse browser config: %w", err)
		}
	}
	if browser == nil {
		browser = make(map[string]json.RawMessage)
	}

	// Set browserName if not already set.
	if _, ok := browser["browserName"]; !ok {
		browser["browserName"] = json.RawMessage(`"chromium"`)
	}

	// Build/update launchOptions with proxy.
	var launchOptions map[string]json.RawMessage
	if raw, ok := browser["launchOptions"]; ok {
		if err := json.Unmarshal(raw, &launchOptions); err != nil {
			return backupPath, fmt.Errorf("parse launchOptions: %w", err)
		}
	}
	if launchOptions == nil {
		launchOptions = make(map[string]json.RawMessage)
	}

	proxyServer := fmt.Sprintf("http://%s", listenAddr)
	proxyConfig := map[string]string{"server": proxyServer}
	proxyJSON, _ := json.Marshal(proxyConfig)
	launchOptions["proxy"] = proxyJSON

	launchOptionsJSON, _ := json.Marshal(launchOptions)
	browser["launchOptions"] = launchOptionsJSON

	// Handle HTTPS option.
	if httpsOption == PlaywrightHTTPSIgnore || httpsOption == PlaywrightHTTPSBoth {
		var contextOptions map[string]json.RawMessage
		if raw, ok := browser["contextOptions"]; ok {
			if err := json.Unmarshal(raw, &contextOptions); err != nil {
				return backupPath, fmt.Errorf("parse contextOptions: %w", err)
			}
		}
		if contextOptions == nil {
			contextOptions = make(map[string]json.RawMessage)
		}
		contextOptions["ignoreHTTPSErrors"] = json.RawMessage(`true`)

		contextOptionsJSON, _ := json.Marshal(contextOptions)
		browser["contextOptions"] = contextOptionsJSON
	}

	browserJSON, _ := json.Marshal(browser)
	existing["browser"] = browserJSON

	// Write the config.
	output, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return backupPath, fmt.Errorf("marshal playwright config: %w", err)
	}
	output = append(output, '\n')

	if err := os.WriteFile(configPath, output, 0644); err != nil {
		return backupPath, fmt.Errorf("write playwright config: %w", err)
	}

	return backupPath, nil
}
