package webui

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
)

// NewHandler returns an http.Handler that serves static files from fsys with
// SPA fallback: if the requested path does not exist and does not look like a
// file (no dot in the final segment), index.html is served instead.
func NewHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	return &spaHandler{fs: fsys, fileServer: fileServer}
}

type spaHandler struct {
	fs         fs.FS
	fileServer http.Handler
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Clean the path (strip leading slash for fs.Open).
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	// Check whether the file exists.
	f, err := h.fs.Open(path)
	if err == nil {
		f.Close()
		h.fileServer.ServeHTTP(w, r)
		return
	}

	// File not found — serve index.html for SPA routing.
	r.URL.Path = "/"
	h.fileServer.ServeHTTP(w, r)
}

// NewFSHandler returns an http.Handler that serves files from the given
// filesystem directory with SPA fallback. It validates that dir exists and
// is a directory.
func NewFSHandler(dir string) (http.Handler, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("webui dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("webui dir %q: not a directory", dir)
	}
	return NewHandler(os.DirFS(dir)), nil
}

// DefaultHandler returns an http.Handler that serves the embedded dist/
// directory with SPA fallback.
func DefaultHandler() http.Handler {
	sub, err := fs.Sub(DistFS, "dist")
	if err != nil {
		// This should never happen since "dist" is always embedded.
		panic(fmt.Sprintf("webui: fs.Sub(DistFS, \"dist\"): %v", err))
	}
	return NewHandler(sub)
}
