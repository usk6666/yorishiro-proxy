package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPlaywrightConfigPath(t *testing.T) {
	got := PlaywrightConfigPath("/my/project")
	want := filepath.Join("/my/project", ".playwright", "cli.config.json")
	if got != want {
		t.Errorf("PlaywrightConfigPath() = %q, want %q", got, want)
	}
}

func TestDetectPlaywright(t *testing.T) {
	t.Run("detects .playwright directory", func(t *testing.T) {
		dir := t.TempDir()
		playwrightDir := filepath.Join(dir, ".playwright")
		if err := os.MkdirAll(playwrightDir, 0755); err != nil {
			t.Fatalf("create .playwright dir: %v", err)
		}

		if !DetectPlaywright(dir) {
			t.Error("expected DetectPlaywright to return true when .playwright/ exists")
		}
	})

	t.Run("returns false when nothing exists and cli not in PATH", func(t *testing.T) {
		dir := t.TempDir()
		// Override PATH to exclude playwright-cli for this test.
		t.Setenv("PATH", dir)
		if DetectPlaywright(dir) {
			t.Error("expected DetectPlaywright to return false when .playwright/ and cli are absent")
		}
	})
}

func TestWritePlaywrightConfig_NewFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	backupPath, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSIgnore, now)
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	if backupPath != "" {
		t.Errorf("expected empty backup path for new file, got %q", backupPath)
	}

	configPath := PlaywrightConfigPath(dir)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// Parse and verify structure.
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	// Check browserName.
	var browserName string
	if err := json.Unmarshal(browser["browserName"], &browserName); err != nil {
		t.Fatalf("parse browserName: %v", err)
	}
	if browserName != "chromium" {
		t.Errorf("browserName = %q, want %q", browserName, "chromium")
	}

	// Check launchOptions.
	var launchOptions map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &launchOptions); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}

	// Check launchOptions.channel defaults to "chromium".
	var channel string
	if err := json.Unmarshal(launchOptions["channel"], &channel); err != nil {
		t.Fatalf("parse channel: %v", err)
	}
	if channel != "chromium" {
		t.Errorf("launchOptions.channel = %q, want %q", channel, "chromium")
	}

	// Check launchOptions.proxy.
	var proxyConfig map[string]string
	if err := json.Unmarshal(launchOptions["proxy"], &proxyConfig); err != nil {
		t.Fatalf("parse proxy: %v", err)
	}
	if proxyConfig["server"] != "http://127.0.0.1:8080" {
		t.Errorf("proxy.server = %q, want %q", proxyConfig["server"], "http://127.0.0.1:8080")
	}

	// Check contextOptions.ignoreHTTPSErrors (should be set for PlaywrightHTTPSIgnore).
	var contextOptions map[string]json.RawMessage
	if err := json.Unmarshal(browser["contextOptions"], &contextOptions); err != nil {
		t.Fatalf("parse contextOptions: %v", err)
	}
	var ignoreHTTPS bool
	if err := json.Unmarshal(contextOptions["ignoreHTTPSErrors"], &ignoreHTTPS); err != nil {
		t.Fatalf("parse ignoreHTTPSErrors: %v", err)
	}
	if !ignoreHTTPS {
		t.Error("expected ignoreHTTPSErrors to be true")
	}
}

func TestWritePlaywrightConfig_ExistingFile_PreservesSettings(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with extra settings.
	playwrightDir := filepath.Join(dir, ".playwright")
	if err := os.MkdirAll(playwrightDir, 0755); err != nil {
		t.Fatalf("create .playwright dir: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	existing := `{
  "browser": {
    "browserName": "firefox",
    "launchOptions": {
      "headless": true
    }
  },
  "extraField": "preserved"
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	backupPath, err := WritePlaywrightConfig(dir, "127.0.0.1:9090", PlaywrightHTTPSIgnore, now)
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	// Should have backup.
	if backupPath == "" {
		t.Error("expected non-empty backup path for existing file")
	}

	// Read and verify.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	// Extra field should be preserved.
	if _, ok := cfg["extraField"]; !ok {
		t.Error("extraField was lost from config")
	}

	// browserName should be preserved (firefox, not overwritten to chromium).
	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	var browserName string
	if err := json.Unmarshal(browser["browserName"], &browserName); err != nil {
		t.Fatalf("parse browserName: %v", err)
	}
	if browserName != "firefox" {
		t.Errorf("browserName = %q, want %q (should preserve existing)", browserName, "firefox")
	}

	// launchOptions should have both headless and proxy.
	var launchOptions map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &launchOptions); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	if _, ok := launchOptions["headless"]; !ok {
		t.Error("existing headless option was lost")
	}
	if _, ok := launchOptions["proxy"]; !ok {
		t.Error("proxy option not added")
	}

	// Verify proxy server has the new address.
	var proxyConfig map[string]string
	if err := json.Unmarshal(launchOptions["proxy"], &proxyConfig); err != nil {
		t.Fatalf("parse proxy: %v", err)
	}
	if proxyConfig["server"] != "http://127.0.0.1:9090" {
		t.Errorf("proxy.server = %q, want %q", proxyConfig["server"], "http://127.0.0.1:9090")
	}
}

func TestWritePlaywrightConfig_BothHTTPSOption(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	_, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSBoth, now)
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	// contextOptions.ignoreHTTPSErrors should be set.
	var contextOptions map[string]json.RawMessage
	if err := json.Unmarshal(browser["contextOptions"], &contextOptions); err != nil {
		t.Fatalf("parse contextOptions: %v", err)
	}
	var ignoreHTTPS bool
	if err := json.Unmarshal(contextOptions["ignoreHTTPSErrors"], &ignoreHTTPS); err != nil {
		t.Fatalf("parse ignoreHTTPSErrors: %v", err)
	}
	if !ignoreHTTPS {
		t.Error("expected ignoreHTTPSErrors to be true with PlaywrightHTTPSBoth")
	}
}

func TestWritePlaywrightConfig_ExistingChannel_Preserved(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with a custom channel.
	playwrightDir := filepath.Join(dir, ".playwright")
	if err := os.MkdirAll(playwrightDir, 0755); err != nil {
		t.Fatalf("create .playwright dir: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	existing := `{
  "browser": {
    "browserName": "chromium",
    "launchOptions": {
      "channel": "chrome"
    }
  }
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	_, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSSkip, now)
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	var launchOptions map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &launchOptions); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}

	var channel string
	if err := json.Unmarshal(launchOptions["channel"], &channel); err != nil {
		t.Fatalf("parse channel: %v", err)
	}
	if channel != "chrome" {
		t.Errorf("launchOptions.channel = %q, want %q (should preserve existing)", channel, "chrome")
	}
}

func TestWritePlaywrightConfig_SkipHTTPSOption_NoContextOptions(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	_, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSSkip, now)
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	// contextOptions should not be present when skipping HTTPS.
	if _, ok := browser["contextOptions"]; ok {
		t.Error("expected no contextOptions when HTTPS option is Skip")
	}
}
