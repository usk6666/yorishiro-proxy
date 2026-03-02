package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFromTarGz(t *testing.T) {
	t.Run("extracts binary successfully", func(t *testing.T) {
		binaryContent := []byte("#!/bin/sh\necho hello\n")
		archiveData := createTestTarGz(t, binaryContent)

		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.tar.gz")
		if err := os.WriteFile(archivePath, archiveData, 0644); err != nil {
			t.Fatalf("write archive: %v", err)
		}

		extracted, err := extractFromTarGz(archivePath, dir)
		if err != nil {
			t.Fatalf("extractFromTarGz() error = %v", err)
		}
		defer os.Remove(extracted)

		content, err := os.ReadFile(extracted)
		if err != nil {
			t.Fatalf("read extracted: %v", err)
		}
		if string(content) != string(binaryContent) {
			t.Errorf("extracted content = %q, want %q", string(content), string(binaryContent))
		}
	})

	t.Run("binary not in archive", func(t *testing.T) {
		// Create archive with a different file name.
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		hdr := &tar.Header{
			Name: "other-file",
			Mode: 0755,
			Size: 5,
		}
		tw.WriteHeader(hdr)
		tw.Write([]byte("hello"))
		tw.Close()
		gw.Close()

		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.tar.gz")
		os.WriteFile(archivePath, buf.Bytes(), 0644)

		_, err := extractFromTarGz(archivePath, dir)
		if err == nil {
			t.Fatal("extractFromTarGz() should return error when binary not found")
		}
	})

	t.Run("invalid archive", func(t *testing.T) {
		dir := t.TempDir()
		archivePath := filepath.Join(dir, "invalid.tar.gz")
		os.WriteFile(archivePath, []byte("not a valid archive"), 0644)

		_, err := extractFromTarGz(archivePath, dir)
		if err == nil {
			t.Fatal("extractFromTarGz() should return error for invalid archive")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		dir := t.TempDir()
		_, err := extractFromTarGz(filepath.Join(dir, "nonexistent.tar.gz"), dir)
		if err == nil {
			t.Fatal("extractFromTarGz() should return error for nonexistent file")
		}
	})
}

func TestExtractFromZip(t *testing.T) {
	t.Run("extracts binary successfully", func(t *testing.T) {
		binaryContent := []byte("MZ\x00\x00fake windows binary")
		archiveData := createTestZip(t, binaryContent)

		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.zip")
		if err := os.WriteFile(archivePath, archiveData, 0644); err != nil {
			t.Fatalf("write archive: %v", err)
		}

		extracted, err := extractFromZip(archivePath, dir)
		if err != nil {
			t.Fatalf("extractFromZip() error = %v", err)
		}
		defer os.Remove(extracted)

		content, err := os.ReadFile(extracted)
		if err != nil {
			t.Fatalf("read extracted: %v", err)
		}
		if string(content) != string(binaryContent) {
			t.Errorf("extracted content = %q, want %q", string(content), string(binaryContent))
		}
	})

	t.Run("binary not in archive", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("other-file.exe")
		w.Write([]byte("hello"))
		zw.Close()

		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.zip")
		os.WriteFile(archivePath, buf.Bytes(), 0644)

		_, err := extractFromZip(archivePath, dir)
		if err == nil {
			t.Fatal("extractFromZip() should return error when binary not found")
		}
	})

	t.Run("invalid archive", func(t *testing.T) {
		dir := t.TempDir()
		archivePath := filepath.Join(dir, "invalid.zip")
		os.WriteFile(archivePath, []byte("not a valid archive"), 0644)

		_, err := extractFromZip(archivePath, dir)
		if err == nil {
			t.Fatal("extractFromZip() should return error for invalid archive")
		}
	})
}

func TestExtractBinary_DispatchesByOS(t *testing.T) {
	binaryContent := []byte("test binary content")

	t.Run("linux uses tar.gz", func(t *testing.T) {
		archiveData := createTestTarGz(t, binaryContent)
		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.tar.gz")
		os.WriteFile(archivePath, archiveData, 0644)

		extracted, err := extractBinary(archivePath, dir, "linux")
		if err != nil {
			t.Fatalf("extractBinary(linux) error = %v", err)
		}
		defer os.Remove(extracted)

		content, err := os.ReadFile(extracted)
		if err != nil {
			t.Fatalf("read extracted: %v", err)
		}
		if string(content) != string(binaryContent) {
			t.Errorf("content = %q, want %q", string(content), string(binaryContent))
		}
	})

	t.Run("darwin uses tar.gz", func(t *testing.T) {
		archiveData := createTestTarGz(t, binaryContent)
		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.tar.gz")
		os.WriteFile(archivePath, archiveData, 0644)

		extracted, err := extractBinary(archivePath, dir, "darwin")
		if err != nil {
			t.Fatalf("extractBinary(darwin) error = %v", err)
		}
		defer os.Remove(extracted)
	})

	t.Run("windows uses zip", func(t *testing.T) {
		archiveData := createTestZip(t, binaryContent)
		dir := t.TempDir()
		archivePath := filepath.Join(dir, "test.zip")
		os.WriteFile(archivePath, archiveData, 0644)

		extracted, err := extractBinary(archivePath, dir, "windows")
		if err != nil {
			t.Fatalf("extractBinary(windows) error = %v", err)
		}
		defer os.Remove(extracted)

		content, err := os.ReadFile(extracted)
		if err != nil {
			t.Fatalf("read extracted: %v", err)
		}
		if string(content) != string(binaryContent) {
			t.Errorf("content = %q, want %q", string(content), string(binaryContent))
		}
	})
}
