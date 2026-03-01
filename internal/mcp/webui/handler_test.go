package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestNewHandler_ServesStaticFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":       {Data: []byte("<h1>Home</h1>")},
		"assets/style.css": {Data: []byte("body{}")},
	}

	handler := NewHandler(fsys)

	tests := []struct {
		path     string
		wantBody string
	}{
		{"/", "<h1>Home</h1>"},
		// Note: /index.html is redirected to / by http.FileServer (301).
		{"/assets/style.css", "body{}"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("GET %s body = %q, want to contain %q", tt.path, body, tt.wantBody)
			}
		})
	}
}

func TestNewHandler_SPAFallback(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<h1>SPA</h1>")},
	}

	handler := NewHandler(fsys)

	paths := []string{"/nonexistent", "/some/deep/path", "/app/dashboard"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", path, rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<h1>SPA</h1>") {
				t.Errorf("GET %s body = %q, want SPA fallback content", path, body)
			}
		})
	}
}

func TestNewFSHandler_ValidDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<p>FS</p>"), 0644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	handler, err := NewFSHandler(dir)
	if err != nil {
		t.Fatalf("NewFSHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<p>FS</p>") {
		t.Errorf("GET / body = %q, want to contain %q", body, "<p>FS</p>")
	}
}

func TestNewFSHandler_NonexistentDirectory(t *testing.T) {
	_, err := NewFSHandler("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestNewFSHandler_FileNotDirectory(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notadir")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()

	_, err = NewFSHandler(f.Name())
	if err == nil {
		t.Fatal("expected error for file (not directory), got nil")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not a directory")
	}
}

func TestDefaultHandler_ServesEmbeddedContent(t *testing.T) {
	handler := DefaultHandler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}

	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "yorishiro-proxy") {
		t.Errorf("GET / body = %q, want to contain %q", string(body), "yorishiro-proxy")
	}
}
