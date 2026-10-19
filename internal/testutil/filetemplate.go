package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// FileTemplate builds a single file at most once per test process and hands
// out byte-identical copies of it. It exists so that expensive fixtures — a
// SQLite database that has run the whole migration chain, for example — are
// produced once and then copied into each test's private directory instead of
// being rebuilt by every test.
//
// The build function receives an empty scratch directory and returns the path
// of the file to snapshot. After build returns, the scratch directory must
// contain exactly that one file: a leftover sidecar (a SQLite -wal / -shm
// file, say) means the snapshot would not be self-contained, so it is
// reported as a build error rather than silently dropped. The scratch
// directory is removed as soon as the file has been read.
//
// A build error is cached alongside the bytes: every caller sees the same
// error and the build is never retried.
//
// FileTemplate is safe for concurrent use; the cached bytes are read-only
// once built.
type FileTemplate struct {
	name  string
	build func(dir string) (string, error)

	once   sync.Once
	data   []byte
	err    error
	builds atomic.Int64
}

// NewFileTemplate returns a FileTemplate whose file is produced by build.
// name is used only in error messages.
func NewFileTemplate(name string, build func(dir string) (string, error)) *FileTemplate {
	return &FileTemplate{name: name, build: build}
}

// Bytes returns the template file's contents, building it on first use.
// The returned slice is shared and must not be modified.
func (ft *FileTemplate) Bytes() ([]byte, error) {
	ft.once.Do(func() {
		ft.builds.Add(1)
		ft.data, ft.err = ft.runBuild()
	})
	return ft.data, ft.err
}

// Builds reports how many times the build function has been invoked.
// It is at most 1 for the lifetime of the FileTemplate.
func (ft *FileTemplate) Builds() int64 {
	return ft.builds.Load()
}

// CopyTo writes a copy of the template file to dst, building the template
// first if necessary. A build or write failure fails the test.
func (ft *FileTemplate) CopyTo(t testing.TB, dst string) {
	t.Helper()
	data, err := ft.Bytes()
	if err != nil {
		t.Fatalf("%s template: %v", ft.name, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("%s template: copy to %s: %v", ft.name, dst, err)
	}
}

func (ft *FileTemplate) runBuild() (data []byte, err error) {
	dir, err := os.MkdirTemp("", "testutil-filetemplate-*")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil && err == nil {
			err = fmt.Errorf("remove build dir: %w", rmErr)
		}
	}()

	path, err := ft.build(dir)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list build dir: %w", err)
	}
	want := filepath.Base(path)
	if filepath.Dir(filepath.Clean(path)) != filepath.Clean(dir) {
		return nil, fmt.Errorf("build returned %s, which is not directly inside the build dir", path)
	}
	for _, e := range entries {
		if e.Name() != want {
			return nil, fmt.Errorf("build left an extra file %q next to %q; the snapshot would not be self-contained", e.Name(), want)
		}
	}

	data, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read built file: %w", err)
	}
	return data, nil
}
