package setup

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestDetectBrowserChannel(t *testing.T) {
	tests := []struct {
		name          string
		existingFiles map[string]bool
		wantBrowser   string
		wantChannel   string
		wantChromium  bool
		wantInstall   string
	}{
		{
			name:          "chromium found",
			existingFiles: map[string]bool{"/usr/bin/chromium": true},
			wantBrowser:   "chromium",
			wantChannel:   "chromium",
			wantChromium:  true,
			wantInstall:   "chromium",
		},
		{
			name:          "firefox found",
			existingFiles: map[string]bool{"/usr/bin/firefox": true},
			wantBrowser:   "firefox",
			wantChannel:   "",
			wantChromium:  false,
			wantInstall:   "firefox",
		},
		{
			name:          "chrome found",
			existingFiles: map[string]bool{"/usr/bin/google-chrome": true},
			wantBrowser:   "chromium",
			wantChannel:   "chrome",
			wantChromium:  true,
			wantInstall:   "chrome",
		},
		{
			name:          "chromium takes priority over firefox",
			existingFiles: map[string]bool{"/usr/bin/chromium": true, "/usr/bin/firefox": true},
			wantBrowser:   "chromium",
			wantChannel:   "chromium",
			wantChromium:  true,
			wantInstall:   "chromium",
		},
		{
			name:          "firefox takes priority over chrome",
			existingFiles: map[string]bool{"/usr/bin/firefox": true, "/usr/bin/google-chrome": true},
			wantBrowser:   "firefox",
			wantChannel:   "",
			wantChromium:  false,
			wantInstall:   "firefox",
		},
		{
			name:          "nothing found defaults to chromium",
			existingFiles: map[string]bool{},
			wantBrowser:   "chromium",
			wantChannel:   "",
			wantChromium:  true,
			wantInstall:   "chromium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := fileExistsFunc
			defer func() { fileExistsFunc = orig }()
			fileExistsFunc = func(path string) bool {
				return tt.existingFiles[path]
			}

			det := detectBrowserChannel()
			if det.browserName != tt.wantBrowser {
				t.Errorf("browserName = %q, want %q", det.browserName, tt.wantBrowser)
			}
			if det.channel != tt.wantChannel {
				t.Errorf("channel = %q, want %q", det.channel, tt.wantChannel)
			}
			if det.isChromium != tt.wantChromium {
				t.Errorf("isChromium = %v, want %v", det.isChromium, tt.wantChromium)
			}
			if det.installTarget != tt.wantInstall {
				t.Errorf("installTarget = %q, want %q", det.installTarget, tt.wantInstall)
			}
		})
	}
}

func TestApplyNoSandbox_AddsFlag(t *testing.T) {
	orig := containerCheckFunc
	defer func() { containerCheckFunc = orig }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	browser := make(map[string]json.RawMessage)
	browser["launchOptions"] = json.RawMessage(`{}`)

	if err := applyNoSandbox(browser, true); err != nil {
		t.Fatalf("applyNoSandbox error: %v", err)
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	var args []string
	if err := json.Unmarshal(lo["args"], &args); err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if len(args) != 1 || args[0] != "--no-sandbox" {
		t.Errorf("args = %v, want [--no-sandbox]", args)
	}
}

func TestApplyNoSandbox_NoDuplicate(t *testing.T) {
	orig := containerCheckFunc
	defer func() { containerCheckFunc = orig }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	browser := make(map[string]json.RawMessage)
	browser["launchOptions"] = json.RawMessage(`{"args":["--no-sandbox"]}`)

	if err := applyNoSandbox(browser, true); err != nil {
		t.Fatalf("applyNoSandbox error: %v", err)
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	var args []string
	if err := json.Unmarshal(lo["args"], &args); err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d: %v", len(args), args)
	}
}

func TestApplyNoSandbox_PreservesExisting(t *testing.T) {
	orig := containerCheckFunc
	defer func() { containerCheckFunc = orig }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	browser := make(map[string]json.RawMessage)
	browser["launchOptions"] = json.RawMessage(`{"args":["--disable-gpu"]}`)

	if err := applyNoSandbox(browser, true); err != nil {
		t.Fatalf("applyNoSandbox error: %v", err)
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	var args []string
	if err := json.Unmarshal(lo["args"], &args); err != nil {
		t.Fatalf("parse args: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d: %v", len(args), args)
	}
	if args[0] != "--disable-gpu" {
		t.Errorf("args[0] = %q, want --disable-gpu", args[0])
	}
	if args[1] != "--no-sandbox" {
		t.Errorf("args[1] = %q, want --no-sandbox", args[1])
	}
}

func TestApplyNoSandbox_SkipsFirefox(t *testing.T) {
	orig := containerCheckFunc
	defer func() { containerCheckFunc = orig }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	browser := make(map[string]json.RawMessage)
	browser["launchOptions"] = json.RawMessage(`{}`)

	if err := applyNoSandbox(browser, false); err != nil {
		t.Fatalf("applyNoSandbox error: %v", err)
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	if _, ok := lo["args"]; ok {
		t.Error("expected no args for Firefox")
	}
}

func TestApplyNoSandbox_SkipsNonContainer(t *testing.T) {
	orig := containerCheckFunc
	defer func() { containerCheckFunc = orig }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: false}
	}

	browser := make(map[string]json.RawMessage)
	browser["launchOptions"] = json.RawMessage(`{}`)

	if err := applyNoSandbox(browser, true); err != nil {
		t.Fatalf("applyNoSandbox error: %v", err)
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	if _, ok := lo["args"]; ok {
		t.Error("expected no args in non-container environment")
	}
}

func TestExtractChannel(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "channel present",
			data: []byte(`{"browser":{"launchOptions":{"channel":"chrome"}}}`),
			want: "chrome",
		},
		{
			name: "channel absent",
			data: []byte(`{"browser":{"launchOptions":{}}}`),
			want: "",
		},
		{
			name: "invalid JSON",
			data: []byte(`{invalid`),
			want: "",
		},
		{
			name: "empty config",
			data: []byte{},
			want: "",
		},
		{
			name: "no browser section",
			data: []byte(`{"other":"value"}`),
			want: "",
		},
		{
			name: "no launchOptions",
			data: []byte(`{"browser":{"browserName":"chromium"}}`),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractChannel(tt.data)
			if got != tt.want {
				t.Errorf("extractChannel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsContainerEnvironment(t *testing.T) {
	tests := []struct {
		name  string
		check containerCheck
		want  bool
	}{
		{
			name:  "dockerenv present",
			check: containerCheck{hasDockerenv: true},
			want:  true,
		},
		{
			name:  "CODESPACES env set",
			check: containerCheck{envVars: map[string]string{"CODESPACES": "true"}},
			want:  true,
		},
		{
			name:  "REMOTE_CONTAINERS env set",
			check: containerCheck{envVars: map[string]string{"REMOTE_CONTAINERS": "1"}},
			want:  true,
		},
		{
			name:  "GITPOD_WORKSPACE_ID env set",
			check: containerCheck{envVars: map[string]string{"GITPOD_WORKSPACE_ID": "abc"}},
			want:  true,
		},
		{
			name:  "docker in cgroup",
			check: containerCheck{cgroupData: "12:memory:/docker/abc123"},
			want:  true,
		},
		{
			name:  "containerd in cgroup",
			check: containerCheck{cgroupData: "12:memory:/containerd/abc123"},
			want:  true,
		},
		{
			name:  "not container",
			check: containerCheck{hasDockerenv: false, envVars: map[string]string{}, cgroupData: ""},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := containerCheckFunc
			defer func() { containerCheckFunc = orig }()
			containerCheckFunc = func() containerCheck {
				return tt.check
			}

			got := isContainerEnvironment()
			if got != tt.want {
				t.Errorf("isContainerEnvironment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWritePlaywrightConfig_ContainerAddsNoSandbox(t *testing.T) {
	// Mock container environment.
	origContainer := containerCheckFunc
	defer func() { containerCheckFunc = origContainer }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	// Mock chromium as detected browser.
	origFile := fileExistsFunc
	defer func() { fileExistsFunc = origFile }()
	fileExistsFunc = func(path string) bool {
		return path == "/usr/bin/chromium"
	}

	dir := t.TempDir()
	_, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSSkip, fixedTime())
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	data, readErr := readFileBytes(t, configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}

	// Parse config and check for --no-sandbox.
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}
	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}
	var args []string
	if err := json.Unmarshal(lo["args"], &args); err != nil {
		t.Fatalf("parse args: %v", err)
	}

	found := false
	for _, a := range args {
		if a == "--no-sandbox" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected --no-sandbox in args, got %v", args)
	}
}

func TestWritePlaywrightConfig_ContainerFirefoxNoSandboxSkipped(t *testing.T) {
	// Mock container environment.
	origContainer := containerCheckFunc
	defer func() { containerCheckFunc = origContainer }()
	containerCheckFunc = func() containerCheck {
		return containerCheck{hasDockerenv: true}
	}

	// Mock firefox as detected browser.
	origFile := fileExistsFunc
	defer func() { fileExistsFunc = origFile }()
	fileExistsFunc = func(path string) bool {
		return path == "/usr/bin/firefox"
	}

	dir := t.TempDir()
	_, err := WritePlaywrightConfig(dir, "127.0.0.1:8080", PlaywrightHTTPSSkip, fixedTime())
	if err != nil {
		t.Fatalf("WritePlaywrightConfig() error: %v", err)
	}

	configPath := PlaywrightConfigPath(dir)
	data, readErr := readFileBytes(t, configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var browser map[string]json.RawMessage
	if err := json.Unmarshal(cfg["browser"], &browser); err != nil {
		t.Fatalf("parse browser: %v", err)
	}

	// browserName should be firefox.
	var browserName string
	if err := json.Unmarshal(browser["browserName"], &browserName); err != nil {
		t.Fatalf("parse browserName: %v", err)
	}
	if browserName != "firefox" {
		t.Errorf("browserName = %q, want %q", browserName, "firefox")
	}

	var lo map[string]json.RawMessage
	if err := json.Unmarshal(browser["launchOptions"], &lo); err != nil {
		t.Fatalf("parse launchOptions: %v", err)
	}

	// channel should not be set for firefox.
	if _, ok := lo["channel"]; ok {
		t.Error("expected no channel for firefox")
	}

	// args should not exist or not contain --no-sandbox.
	if argsRaw, ok := lo["args"]; ok {
		var args []string
		if err := json.Unmarshal(argsRaw, &args); err == nil {
			for _, a := range args {
				if a == "--no-sandbox" {
					t.Error("expected no --no-sandbox for firefox")
				}
			}
		}
	}
}

func TestDetectionFromChannel(t *testing.T) {
	tests := []struct {
		channel      string
		wantBrowser  string
		wantChromium bool
		wantInstall  string
	}{
		{"chromium", "chromium", true, "chromium"},
		{"chrome", "chromium", true, "chrome"},
		{"firefox", "firefox", false, "firefox"},
		{"unknown", "chromium", true, "chromium"},
	}

	for _, tt := range tests {
		t.Run(tt.channel, func(t *testing.T) {
			det := detectionFromChannel(tt.channel)
			if det.browserName != tt.wantBrowser {
				t.Errorf("browserName = %q, want %q", det.browserName, tt.wantBrowser)
			}
			if det.isChromium != tt.wantChromium {
				t.Errorf("isChromium = %v, want %v", det.isChromium, tt.wantChromium)
			}
			if det.installTarget != tt.wantInstall {
				t.Errorf("installTarget = %q, want %q", det.installTarget, tt.wantInstall)
			}
		})
	}
}

func TestIsBrowserInstalled(t *testing.T) {
	orig := fileExistsFunc
	defer func() { fileExistsFunc = orig }()

	t.Run("installed", func(t *testing.T) {
		fileExistsFunc = func(path string) bool {
			return path == "/usr/bin/chromium"
		}
		det := browserDetection{installTarget: "chromium"}
		if !isBrowserInstalled(det) {
			t.Error("expected browser to be detected as installed")
		}
	})

	t.Run("not installed", func(t *testing.T) {
		fileExistsFunc = func(_ string) bool { return false }
		det := browserDetection{installTarget: "chromium"}
		if isBrowserInstalled(det) {
			t.Error("expected browser to be detected as not installed")
		}
	})
}

// Helper functions for tests.

func fixedTime() time.Time {
	return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
}

func readFileBytes(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}
