package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// extractBinary extracts the yorishiro-proxy binary from an archive file
// into the specified directory. It returns the path to the extracted binary.
// The archive format is determined by the target OS: zip for Windows, tar.gz otherwise.
func extractBinary(archivePath, destDir, goos string) (string, error) {
	if goos == "windows" {
		return extractFromZip(archivePath, destDir)
	}
	return extractFromTarGz(archivePath, destDir)
}

// extractFromTarGz extracts the yorishiro-proxy binary from a .tar.gz archive.
func extractFromTarGz(archivePath, destDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("create gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar entry: %w", err)
		}

		// We only care about the yorishiro-proxy binary.
		name := filepath.Base(header.Name)
		if name != "yorishiro-proxy" {
			continue
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Write to a temporary file in the destination directory.
		tmp, err := os.CreateTemp(destDir, "yorishiro-proxy-new-*")
		if err != nil {
			return "", fmt.Errorf("create temp file: %w", err)
		}

		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return "", fmt.Errorf("extract binary: %w", err)
		}
		tmp.Close()
		return tmp.Name(), nil
	}

	return "", fmt.Errorf("binary not found in tar.gz archive")
}

// extractFromZip extracts the yorishiro-proxy.exe binary from a .zip archive.
func extractFromZip(archivePath, destDir string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open zip archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name != "yorishiro-proxy.exe" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open zip entry: %w", err)
		}

		tmp, err := os.CreateTemp(destDir, "yorishiro-proxy-new-*.exe")
		if err != nil {
			rc.Close()
			return "", fmt.Errorf("create temp file: %w", err)
		}

		if _, err := io.Copy(tmp, rc); err != nil {
			tmp.Close()
			rc.Close()
			os.Remove(tmp.Name())
			return "", fmt.Errorf("extract binary: %w", err)
		}
		tmp.Close()
		rc.Close()
		return tmp.Name(), nil
	}

	return "", fmt.Errorf("binary not found in zip archive")
}
