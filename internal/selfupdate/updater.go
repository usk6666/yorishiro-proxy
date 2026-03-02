package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// defaultOwner is the GitHub repository owner.
	defaultOwner = "usk6666"
	// defaultRepo is the GitHub repository name.
	defaultRepo = "yorishiro-proxy"
)

// ReleaseAsset represents a single asset in a GitHub release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Release represents a GitHub release response (subset of fields).
type Release struct {
	TagName string         `json:"tag_name"`
	Assets  []ReleaseAsset `json:"assets"`
}

// HTTPClient is the interface used for HTTP requests.
// It allows injecting a mock client for testing.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Updater handles checking for and applying self-updates from GitHub Releases.
type Updater struct {
	// CurrentVersion is the version of the currently running binary (e.g. "v1.0.0" or "dev").
	CurrentVersion string

	// Owner is the GitHub repository owner. Defaults to defaultOwner.
	Owner string
	// Repo is the GitHub repository name. Defaults to defaultRepo.
	Repo string

	// Client is the HTTP client used for API and download requests.
	// If nil, http.DefaultClient is used.
	Client HTTPClient
}

// NewUpdater creates a new Updater with the given current version.
func NewUpdater(currentVersion string) *Updater {
	return &Updater{
		CurrentVersion: currentVersion,
		Owner:          defaultOwner,
		Repo:           defaultRepo,
	}
}

// httpClient returns the configured HTTP client or the default one.
func (u *Updater) httpClient() HTTPClient {
	if u.Client != nil {
		return u.Client
	}
	return http.DefaultClient
}

// latestReleaseURL returns the GitHub API URL for the latest release.
func (u *Updater) latestReleaseURL() string {
	owner := u.Owner
	if owner == "" {
		owner = defaultOwner
	}
	repo := u.Repo
	if repo == "" {
		repo = defaultRepo
	}
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
}

// FetchLatestRelease fetches the latest release information from GitHub.
func (u *Updater) FetchLatestRelease(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.latestReleaseURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "yorishiro-proxy/selfupdate")

	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release response: %w", err)
	}

	return &release, nil
}

// CheckResult holds the result of a version check.
type CheckResult struct {
	// CurrentVersion is the version of the running binary.
	CurrentVersion string
	// LatestVersion is the latest available version from GitHub.
	LatestVersion string
	// HasUpdate is true if a newer version is available.
	HasUpdate bool
}

// Check checks whether a newer version is available without downloading anything.
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	release, err := u.FetchLatestRelease(ctx)
	if err != nil {
		return nil, err
	}

	newer, err := IsNewerThan(release.TagName, u.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("compare versions: %w", err)
	}

	return &CheckResult{
		CurrentVersion: u.CurrentVersion,
		LatestVersion:  release.TagName,
		HasUpdate:      newer,
	}, nil
}

// assetName returns the expected archive asset name for the given version, OS, and architecture.
// For example: "yorishiro-proxy-v1.0.0-linux-amd64.tar.gz"
func assetName(version, goos, goarch string) string {
	if goos == "windows" {
		return fmt.Sprintf("yorishiro-proxy-%s-%s-%s.zip", version, goos, goarch)
	}
	return fmt.Sprintf("yorishiro-proxy-%s-%s-%s.tar.gz", version, goos, goarch)
}

// findAsset finds the download URL for the appropriate platform asset in a release.
func findAsset(release *Release, goos, goarch string) (string, error) {
	name := assetName(release.TagName, goos, goarch)
	for _, asset := range release.Assets {
		if asset.Name == name {
			return asset.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no asset found for %s/%s (expected %s)", goos, goarch, name)
}

// findChecksumAsset finds the download URL for the checksums file.
func findChecksumAsset(release *Release) (string, error) {
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			return asset.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no checksums.txt asset found in release")
}

// downloadToFile downloads the content from url into a temporary file in the given directory.
// It returns the path to the temporary file.
func (u *Updater) downloadToFile(ctx context.Context, url, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create download request: %w", err)
	}
	req.Header.Set("User-Agent", "yorishiro-proxy/selfupdate")

	resp, err := u.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dir, "yorishiro-proxy-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("write download: %w", err)
	}

	return tmp.Name(), nil
}

// parseChecksums parses a sha256sum-format checksums file and returns a map of filename -> hex hash.
func parseChecksums(data []byte) map[string]string {
	checksums := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// sha256sum format: "<hash>  <filename>" or "<hash> <filename>"
		parts := strings.Fields(line)
		if len(parts) == 2 {
			checksums[parts[1]] = parts[0]
		}
	}
	return checksums
}

// verifyChecksum verifies the SHA-256 checksum of a file against an expected hex-encoded hash.
func verifyChecksum(filePath, expectedHash string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file for checksum: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read file for checksum: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedHash) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actual)
	}

	return nil
}

// Upgrade checks for a new version, downloads the appropriate binary, verifies
// its checksum, and atomically replaces the running binary.
// It returns the CheckResult describing what happened.
func (u *Updater) Upgrade(ctx context.Context) (*CheckResult, error) {
	release, err := u.FetchLatestRelease(ctx)
	if err != nil {
		return nil, err
	}

	newer, err := IsNewerThan(release.TagName, u.CurrentVersion)
	if err != nil {
		return nil, fmt.Errorf("compare versions: %w", err)
	}

	result := &CheckResult{
		CurrentVersion: u.CurrentVersion,
		LatestVersion:  release.TagName,
		HasUpdate:      newer,
	}

	if !newer {
		return result, nil
	}

	// Find the platform-specific archive asset.
	archiveURL, err := findAsset(release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}

	// Find the checksums asset.
	checksumURL, err := findChecksumAsset(release)
	if err != nil {
		return nil, err
	}

	// Get the path of the currently running binary.
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return nil, fmt.Errorf("resolve executable symlinks: %w", err)
	}

	// Verify write permission to the binary directory.
	execDir := filepath.Dir(execPath)
	if err := checkWritePermission(execDir); err != nil {
		return nil, fmt.Errorf("insufficient permissions to update %s: %w", execPath, err)
	}

	// Download the checksums file.
	checksumPath, err := u.downloadToFile(ctx, checksumURL, execDir)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}
	defer os.Remove(checksumPath)

	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return nil, fmt.Errorf("read checksums file: %w", err)
	}
	checksums := parseChecksums(checksumData)

	// Download the archive.
	archivePath, err := u.downloadToFile(ctx, archiveURL, execDir)
	if err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}
	defer os.Remove(archivePath)

	// Verify checksum of the downloaded archive.
	expectedAssetName := assetName(release.TagName, runtime.GOOS, runtime.GOARCH)
	expectedHash, ok := checksums[expectedAssetName]
	if !ok {
		return nil, fmt.Errorf("no checksum found for %s in checksums.txt", expectedAssetName)
	}
	if err := verifyChecksum(archivePath, expectedHash); err != nil {
		return nil, fmt.Errorf("archive checksum verification failed: %w", err)
	}

	// Extract the binary from the archive.
	binaryPath, err := extractBinary(archivePath, execDir, runtime.GOOS)
	if err != nil {
		return nil, fmt.Errorf("extract binary: %w", err)
	}
	defer func() {
		// Clean up if rename fails or on other errors.
		if binaryPath != "" {
			os.Remove(binaryPath)
		}
	}()

	// Make the extracted binary executable.
	if err := os.Chmod(binaryPath, 0755); err != nil {
		return nil, fmt.Errorf("set binary permissions: %w", err)
	}

	// Atomically replace the current binary.
	if err := atomicReplace(execPath, binaryPath, runtime.GOOS); err != nil {
		return nil, fmt.Errorf("replace binary: %w", err)
	}
	// Clear binaryPath so the deferred cleanup doesn't remove the new binary.
	binaryPath = ""

	return result, nil
}

// checkWritePermission checks that the directory is writable by creating and
// immediately removing a temporary file.
func checkWritePermission(dir string) error {
	tmp, err := os.CreateTemp(dir, ".yorishiro-proxy-perm-check-*")
	if err != nil {
		return fmt.Errorf("directory %s is not writable: %w", dir, err)
	}
	name := tmp.Name()
	tmp.Close()
	os.Remove(name)
	return nil
}

// atomicReplace replaces oldPath with newPath atomically using rename.
// On Windows, the running binary cannot be deleted directly, so the old
// binary is renamed to a .old suffix first, then the new binary is moved
// into place.
func atomicReplace(oldPath, newPath, goos string) error {
	if goos == "windows" {
		// Windows: rename the old binary out of the way first.
		backupPath := oldPath + ".old"
		// Remove any leftover backup from a previous upgrade.
		os.Remove(backupPath)
		if err := os.Rename(oldPath, backupPath); err != nil {
			return fmt.Errorf("backup current binary: %w", err)
		}
		if err := os.Rename(newPath, oldPath); err != nil {
			// Try to restore the backup on failure.
			_ = os.Rename(backupPath, oldPath)
			return fmt.Errorf("install new binary: %w", err)
		}
		// Best-effort cleanup of the backup. On Windows the old binary may
		// still be locked by the running process, so this may fail.
		os.Remove(backupPath)
		return nil
	}

	// Unix: os.Rename is atomic when src and dst are on the same filesystem.
	return os.Rename(newPath, oldPath)
}
