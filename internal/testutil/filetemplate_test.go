package testutil

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileTemplate_BuildsOnceAndCopies(t *testing.T) {
	t.Parallel()
	var calls int
	var buildDir string
	ft := NewFileTemplate("demo", func(dir string) (string, error) {
		calls++
		buildDir = dir
		p := filepath.Join(dir, "x.bin")
		return p, os.WriteFile(p, []byte("payload"), 0o600)
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ft.Bytes(); err != nil {
				t.Errorf("Bytes: %v", err)
			}
		}()
	}
	wg.Wait()

	for i := 0; i < 3; i++ {
		dst := filepath.Join(t.TempDir(), "copy.bin")
		ft.CopyTo(t, dst)
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("read copy: %v", err)
		}
		if string(got) != "payload" {
			t.Fatalf("copy = %q, want %q", got, "payload")
		}
	}
	if calls != 1 || ft.Builds() != 1 {
		t.Fatalf("build ran %d times (Builds()=%d), want exactly 1", calls, ft.Builds())
	}
	if _, err := os.Stat(buildDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("build dir %s still exists after build (stat err %v)", buildDir, err)
	}
}

func TestFileTemplate_BuildErrorIsStickyAndNotRetried(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	ft := NewFileTemplate("failing", func(string) (string, error) {
		return "", sentinel
	})
	for i := 0; i < 3; i++ {
		data, err := ft.Bytes()
		if !errors.Is(err, sentinel) {
			t.Fatalf("call %d: err = %v, want %v", i, err, sentinel)
		}
		if data != nil {
			t.Fatalf("call %d: data = %q, want nil", i, data)
		}
	}
	if ft.Builds() != 1 {
		t.Fatalf("Builds() = %d, want 1 (a failed build must not be retried)", ft.Builds())
	}
}

func TestFileTemplate_SidecarFileIsAnError(t *testing.T) {
	t.Parallel()
	ft := NewFileTemplate("sidecar", func(dir string) (string, error) {
		p := filepath.Join(dir, "db")
		if err := os.WriteFile(p, []byte("main"), 0o600); err != nil {
			return "", err
		}
		return p, os.WriteFile(p+"-wal", []byte("wal"), 0o600)
	})
	if _, err := ft.Bytes(); err == nil {
		t.Fatal("Bytes succeeded although the build left a -wal sidecar; want error")
	}
}
