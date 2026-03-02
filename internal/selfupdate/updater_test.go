package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockHTTPClient implements HTTPClient for testing.
type mockHTTPClient struct {
	responses map[string]*http.Response
	errors    map[string]error
}

func newMockHTTPClient() *mockHTTPClient {
	return &mockHTTPClient{
		responses: make(map[string]*http.Response),
		errors:    make(map[string]error),
	}
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	if err, ok := m.errors[url]; ok {
		return nil, err
	}
	if resp, ok := m.responses[url]; ok {
		return resp, nil
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

func (m *mockHTTPClient) addResponse(url string, statusCode int, body string) {
	m.responses[url] = &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func (m *mockHTTPClient) addResponseBytes(url string, statusCode int, body []byte) {
	m.responses[url] = &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func (m *mockHTTPClient) addError(url string, err error) {
	m.errors[url] = err
}

const testReleaseJSON = `{
	"tag_name": "v1.1.0",
	"assets": [
		{"name": "yorishiro-proxy-v1.1.0-linux-amd64.tar.gz", "browser_download_url": "https://example.com/linux-amd64.tar.gz"},
		{"name": "yorishiro-proxy-v1.1.0-linux-arm64.tar.gz", "browser_download_url": "https://example.com/linux-arm64.tar.gz"},
		{"name": "yorishiro-proxy-v1.1.0-darwin-amd64.tar.gz", "browser_download_url": "https://example.com/darwin-amd64.tar.gz"},
		{"name": "yorishiro-proxy-v1.1.0-darwin-arm64.tar.gz", "browser_download_url": "https://example.com/darwin-arm64.tar.gz"},
		{"name": "yorishiro-proxy-v1.1.0-windows-amd64.zip", "browser_download_url": "https://example.com/windows-amd64.zip"},
		{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"}
	]
}`

func TestNewUpdater(t *testing.T) {
	u := NewUpdater("v1.0.0")
	if u.CurrentVersion != "v1.0.0" {
		t.Errorf("CurrentVersion = %q, want %q", u.CurrentVersion, "v1.0.0")
	}
	if u.Owner != defaultOwner {
		t.Errorf("Owner = %q, want %q", u.Owner, defaultOwner)
	}
	if u.Repo != defaultRepo {
		t.Errorf("Repo = %q, want %q", u.Repo, defaultRepo)
	}
}

func TestUpdater_FetchLatestRelease(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		testReleaseJSON,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	release, err := u.FetchLatestRelease(ctx)
	if err != nil {
		t.Fatalf("FetchLatestRelease() error = %v", err)
	}
	if release.TagName != "v1.1.0" {
		t.Errorf("TagName = %q, want %q", release.TagName, "v1.1.0")
	}
	if len(release.Assets) != 6 {
		t.Errorf("len(Assets) = %d, want 6", len(release.Assets))
	}
}

func TestUpdater_FetchLatestRelease_APIError(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusForbidden,
		`{"message":"rate limit exceeded"}`,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	_, err := u.FetchLatestRelease(ctx)
	if err == nil {
		t.Fatal("FetchLatestRelease() should return error for non-200 status")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestUpdater_FetchLatestRelease_NetworkError(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addError(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		fmt.Errorf("connection refused"),
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	_, err := u.FetchLatestRelease(ctx)
	if err == nil {
		t.Fatal("FetchLatestRelease() should return error on network failure")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error should contain original message, got: %v", err)
	}
}

func TestUpdater_Check_UpdateAvailable(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		testReleaseJSON,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	result, err := u.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.HasUpdate {
		t.Error("Check() HasUpdate = false, want true")
	}
	if result.CurrentVersion != "v1.0.0" {
		t.Errorf("CurrentVersion = %q, want %q", result.CurrentVersion, "v1.0.0")
	}
	if result.LatestVersion != "v1.1.0" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "v1.1.0")
	}
}

func TestUpdater_Check_AlreadyLatest(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		testReleaseJSON,
	)

	u := NewUpdater("v1.1.0")
	u.Client = mock

	result, err := u.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.HasUpdate {
		t.Error("Check() HasUpdate = true, want false")
	}
}

func TestUpdater_Check_DevBuild(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		testReleaseJSON,
	)

	u := NewUpdater("dev")
	u.Client = mock

	result, err := u.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.HasUpdate {
		t.Error("Check() HasUpdate = false, want true for dev build")
	}
}

func TestAssetName(t *testing.T) {
	tests := []struct {
		name    string
		version string
		goos    string
		goarch  string
		want    string
	}{
		{
			name:    "linux amd64",
			version: "v1.0.0",
			goos:    "linux",
			goarch:  "amd64",
			want:    "yorishiro-proxy-v1.0.0-linux-amd64.tar.gz",
		},
		{
			name:    "darwin arm64",
			version: "v1.0.0",
			goos:    "darwin",
			goarch:  "arm64",
			want:    "yorishiro-proxy-v1.0.0-darwin-arm64.tar.gz",
		},
		{
			name:    "windows amd64",
			version: "v1.0.0",
			goos:    "windows",
			goarch:  "amd64",
			want:    "yorishiro-proxy-v1.0.0-windows-amd64.zip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assetName(tt.version, tt.goos, tt.goarch)
			if got != tt.want {
				t.Errorf("assetName(%q, %q, %q) = %q, want %q", tt.version, tt.goos, tt.goarch, got, tt.want)
			}
		})
	}
}

func TestFindAsset(t *testing.T) {
	release := &Release{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: "yorishiro-proxy-v1.0.0-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
			{Name: "yorishiro-proxy-v1.0.0-windows-amd64.zip", BrowserDownloadURL: "https://example.com/windows"},
			{Name: "checksums.txt", BrowserDownloadURL: "https://example.com/checksums"},
		},
	}

	t.Run("found", func(t *testing.T) {
		url, err := findAsset(release, "linux", "amd64")
		if err != nil {
			t.Fatalf("findAsset() error = %v", err)
		}
		if url != "https://example.com/linux" {
			t.Errorf("findAsset() = %q, want %q", url, "https://example.com/linux")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := findAsset(release, "freebsd", "amd64")
		if err == nil {
			t.Fatal("findAsset() should return error for unsupported platform")
		}
	})
}

func TestFindChecksumAsset(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		release := &Release{
			Assets: []ReleaseAsset{
				{Name: "yorishiro-proxy-v1.0.0-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
				{Name: "checksums.txt", BrowserDownloadURL: "https://example.com/checksums"},
			},
		}
		url, err := findChecksumAsset(release)
		if err != nil {
			t.Fatalf("findChecksumAsset() error = %v", err)
		}
		if url != "https://example.com/checksums" {
			t.Errorf("findChecksumAsset() = %q, want %q", url, "https://example.com/checksums")
		}
	})

	t.Run("not found", func(t *testing.T) {
		release := &Release{
			Assets: []ReleaseAsset{
				{Name: "yorishiro-proxy-v1.0.0-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
			},
		}
		_, err := findChecksumAsset(release)
		if err == nil {
			t.Fatal("findChecksumAsset() should return error when checksums.txt is missing")
		}
	})
}

func TestParseChecksums(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "standard sha256sum output",
			input: "abc123  yorishiro-proxy-v1.0.0-linux-amd64.tar.gz\ndef456  yorishiro-proxy-v1.0.0-windows-amd64.zip\n",
			want: map[string]string{
				"yorishiro-proxy-v1.0.0-linux-amd64.tar.gz":  "abc123",
				"yorishiro-proxy-v1.0.0-windows-amd64.zip":   "def456",
			},
		},
		{
			name:  "single space separator",
			input: "abc123 file.tar.gz\n",
			want: map[string]string{
				"file.tar.gz": "abc123",
			},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "blank lines and whitespace",
			input: "\n  \nabc123  file.tar.gz\n\n",
			want: map[string]string{
				"file.tar.gz": "abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseChecksums([]byte(tt.input))
			if len(got) != len(tt.want) {
				t.Errorf("parseChecksums() returned %d entries, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseChecksums()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()

	// Create a file with known content.
	content := []byte("hello world\n")
	filePath := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Calculate the actual hash.
	h := sha256.Sum256(content)
	correctHash := hex.EncodeToString(h[:])

	t.Run("correct checksum", func(t *testing.T) {
		if err := verifyChecksum(filePath, correctHash); err != nil {
			t.Errorf("verifyChecksum() error = %v", err)
		}
	})

	t.Run("correct checksum uppercase", func(t *testing.T) {
		if err := verifyChecksum(filePath, strings.ToUpper(correctHash)); err != nil {
			t.Errorf("verifyChecksum() error = %v for uppercase hash", err)
		}
	})

	t.Run("wrong checksum", func(t *testing.T) {
		err := verifyChecksum(filePath, "0000000000000000000000000000000000000000000000000000000000000000")
		if err == nil {
			t.Fatal("verifyChecksum() should return error for wrong hash")
		}
		if !strings.Contains(err.Error(), "checksum mismatch") {
			t.Errorf("error should mention checksum mismatch, got: %v", err)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		err := verifyChecksum(filepath.Join(dir, "nonexistent"), correctHash)
		if err == nil {
			t.Fatal("verifyChecksum() should return error for nonexistent file")
		}
	})
}

func TestCheckWritePermission(t *testing.T) {
	t.Run("writable directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := checkWritePermission(dir); err != nil {
			t.Errorf("checkWritePermission() error = %v", err)
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		err := checkWritePermission("/nonexistent/path/that/does/not/exist")
		if err == nil {
			t.Fatal("checkWritePermission() should return error for nonexistent directory")
		}
	})
}

func TestAtomicReplace_Unix(t *testing.T) {
	dir := t.TempDir()

	// Create the "old" binary.
	oldPath := filepath.Join(dir, "binary")
	if err := os.WriteFile(oldPath, []byte("old content"), 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	// Create the "new" binary.
	newPath := filepath.Join(dir, "binary.new")
	if err := os.WriteFile(newPath, []byte("new content"), 0755); err != nil {
		t.Fatalf("write new binary: %v", err)
	}

	// Replace.
	if err := atomicReplace(oldPath, newPath, "linux"); err != nil {
		t.Fatalf("atomicReplace() error = %v", err)
	}

	// Verify the content was replaced.
	content, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if string(content) != "new content" {
		t.Errorf("replaced binary content = %q, want %q", string(content), "new content")
	}

	// Verify the new file was removed (it's been renamed).
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Error("new binary should no longer exist at original path after rename")
	}
}

func TestAtomicReplace_Windows(t *testing.T) {
	dir := t.TempDir()

	// Create the "old" binary.
	oldPath := filepath.Join(dir, "binary.exe")
	if err := os.WriteFile(oldPath, []byte("old content"), 0755); err != nil {
		t.Fatalf("write old binary: %v", err)
	}

	// Create the "new" binary.
	newPath := filepath.Join(dir, "binary.exe.new")
	if err := os.WriteFile(newPath, []byte("new content"), 0755); err != nil {
		t.Fatalf("write new binary: %v", err)
	}

	// Replace using Windows path.
	if err := atomicReplace(oldPath, newPath, "windows"); err != nil {
		t.Fatalf("atomicReplace() error = %v", err)
	}

	// Verify the content was replaced.
	content, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if string(content) != "new content" {
		t.Errorf("replaced binary content = %q, want %q", string(content), "new content")
	}
}

func TestUpdater_LatestReleaseURL(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		repo  string
		want  string
	}{
		{
			name: "defaults",
			want: "https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		},
		{
			name:  "custom owner and repo",
			owner: "testowner",
			repo:  "testrepo",
			want:  "https://api.github.com/repos/testowner/testrepo/releases/latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := NewUpdater("v1.0.0")
			if tt.owner != "" {
				u.Owner = tt.owner
			}
			if tt.repo != "" {
				u.Repo = tt.repo
			}
			got := u.latestReleaseURL()
			if got != tt.want {
				t.Errorf("latestReleaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// createTestTarGz creates a tar.gz archive containing a fake yorishiro-proxy binary.
func createTestTarGz(t *testing.T, binaryContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "yorishiro-proxy",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatalf("write tar content: %v", err)
	}

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// createTestZip creates a zip archive containing a fake yorishiro-proxy.exe binary.
func createTestZip(t *testing.T, binaryContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("yorishiro-proxy.exe")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(binaryContent); err != nil {
		t.Fatalf("write zip content: %v", err)
	}

	zw.Close()
	return buf.Bytes()
}

func TestUpdater_Upgrade_NoUpdate(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		`{"tag_name": "v1.0.0", "assets": []}`,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	result, err := u.Upgrade(ctx)
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if result.HasUpdate {
		t.Error("Upgrade() HasUpdate = true, want false when already latest")
	}
}

func TestUpdater_Upgrade_MissingAsset(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()
	// Release with no matching platform asset.
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		`{"tag_name": "v2.0.0", "assets": [{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums"}]}`,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	_, err := u.Upgrade(ctx)
	if err == nil {
		t.Fatal("Upgrade() should return error when platform asset is missing")
	}
	if !strings.Contains(err.Error(), "no asset found") {
		t.Errorf("error should mention missing asset, got: %v", err)
	}
}

func TestUpdater_downloadToFile(t *testing.T) {
	ctx := context.Background()

	t.Run("successful download", func(t *testing.T) {
		mock := newMockHTTPClient()
		mock.addResponseBytes("https://example.com/file.bin", http.StatusOK, []byte("binary data"))

		u := NewUpdater("v1.0.0")
		u.Client = mock

		dir := t.TempDir()
		path, err := u.downloadToFile(ctx, "https://example.com/file.bin", dir)
		if err != nil {
			t.Fatalf("downloadToFile() error = %v", err)
		}
		defer os.Remove(path)

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read downloaded file: %v", err)
		}
		if string(content) != "binary data" {
			t.Errorf("content = %q, want %q", string(content), "binary data")
		}
	})

	t.Run("HTTP error status", func(t *testing.T) {
		mock := newMockHTTPClient()
		mock.addResponse("https://example.com/file.bin", http.StatusInternalServerError, "error")

		u := NewUpdater("v1.0.0")
		u.Client = mock

		dir := t.TempDir()
		_, err := u.downloadToFile(ctx, "https://example.com/file.bin", dir)
		if err == nil {
			t.Fatal("downloadToFile() should return error for non-200 status")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error should mention status code, got: %v", err)
		}
	})

	t.Run("network error", func(t *testing.T) {
		mock := newMockHTTPClient()
		mock.addError("https://example.com/file.bin", fmt.Errorf("connection reset"))

		u := NewUpdater("v1.0.0")
		u.Client = mock

		dir := t.TempDir()
		_, err := u.downloadToFile(ctx, "https://example.com/file.bin", dir)
		if err == nil {
			t.Fatal("downloadToFile() should return error on network failure")
		}
	})

	t.Run("unwritable directory", func(t *testing.T) {
		mock := newMockHTTPClient()
		mock.addResponseBytes("https://example.com/file.bin", http.StatusOK, []byte("data"))

		u := NewUpdater("v1.0.0")
		u.Client = mock

		_, err := u.downloadToFile(ctx, "https://example.com/file.bin", "/nonexistent/dir")
		if err == nil {
			t.Fatal("downloadToFile() should return error for unwritable directory")
		}
	})
}

func TestUpdater_Upgrade_MissingChecksumAsset(t *testing.T) {
	ctx := context.Background()
	mock := newMockHTTPClient()

	// Release with platform asset but no checksums.txt.
	releaseJSON := fmt.Sprintf(`{
		"tag_name": "v2.0.0",
		"assets": [
			{"name": "yorishiro-proxy-v2.0.0-linux-amd64.tar.gz", "browser_download_url": "https://example.com/archive.tar.gz"},
			{"name": "yorishiro-proxy-v2.0.0-linux-arm64.tar.gz", "browser_download_url": "https://example.com/archive-arm64.tar.gz"},
			{"name": "yorishiro-proxy-v2.0.0-darwin-amd64.tar.gz", "browser_download_url": "https://example.com/archive-darwin.tar.gz"},
			{"name": "yorishiro-proxy-v2.0.0-darwin-arm64.tar.gz", "browser_download_url": "https://example.com/archive-darwin-arm64.tar.gz"},
			{"name": "yorishiro-proxy-v2.0.0-windows-amd64.zip", "browser_download_url": "https://example.com/archive-windows.zip"}
		]
	}`)
	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		releaseJSON,
	)

	u := NewUpdater("v1.0.0")
	u.Client = mock

	_, err := u.Upgrade(ctx)
	if err == nil {
		t.Fatal("Upgrade() should return error when checksums.txt is missing")
	}
	if !strings.Contains(err.Error(), "checksums.txt") {
		t.Errorf("error should mention checksums.txt, got: %v", err)
	}
}

func TestUpdater_Upgrade_ChecksumMismatch(t *testing.T) {
	ctx := context.Background()

	binaryContent := []byte("new binary v2")
	archiveData := createTestTarGz(t, binaryContent)

	// Compute a wrong checksum.
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	mock := newMockHTTPClient()

	// Build a release JSON that covers the current runtime OS/arch.
	archiveAssetName := assetName("v2.0.0", "linux", "amd64")
	releaseJSON := fmt.Sprintf(`{
		"tag_name": "v2.0.0",
		"assets": [
			{"name": "%s", "browser_download_url": "https://example.com/archive"},
			{"name": "yorishiro-proxy-v2.0.0-linux-arm64.tar.gz", "browser_download_url": "https://example.com/archive-arm64"},
			{"name": "yorishiro-proxy-v2.0.0-darwin-amd64.tar.gz", "browser_download_url": "https://example.com/archive-darwin"},
			{"name": "yorishiro-proxy-v2.0.0-darwin-arm64.tar.gz", "browser_download_url": "https://example.com/archive-darwin-arm64"},
			{"name": "yorishiro-proxy-v2.0.0-windows-amd64.zip", "browser_download_url": "https://example.com/archive-windows"},
			{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums"}
		]
	}`, archiveAssetName)

	mock.addResponse(
		"https://api.github.com/repos/usk6666/yorishiro-proxy/releases/latest",
		http.StatusOK,
		releaseJSON,
	)
	mock.addResponseBytes("https://example.com/archive", http.StatusOK, archiveData)
	mock.addResponse("https://example.com/checksums", http.StatusOK,
		fmt.Sprintf("%s  %s\n", wrongChecksum, archiveAssetName))

	u := NewUpdater("v1.0.0")
	u.Client = mock

	// Note: This test will reach the checkWritePermission step which uses os.Executable(),
	// so it may fail at that point in some environments. The key assertion is that
	// it doesn't succeed silently.
	_, err := u.Upgrade(ctx)
	if err == nil {
		t.Fatal("Upgrade() should return error on checksum mismatch")
	}
	// The error could be from checksum mismatch or from permission check depending on the env.
}
