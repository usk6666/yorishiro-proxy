package flow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Flow sink file layout (USK-1119).
//
// The sink appends to <dir>/flows.jsonl. When the next line would take it
// past max_file_bytes, the file is renamed to
// flows-<UTC timestamp>-<n>.jsonl and a new flows.jsonl is opened, so a
// line never spans two files and every rotated file is complete. Rotated
// names sort chronologically. The consumer ingests rotated files and owns
// deleting them; with max_files > 0 the proxy also deletes the oldest
// rotated files beyond that count. A non-empty flows.jsonl found at open
// (left by an earlier run, possibly ending in a torn line after a crash)
// is rotated away first.
//
// The active file is never a symlink (refused at open, and opened with
// O_NOFOLLOW where available); it is chmod'ed to 0600 on every open so
// a pre-existing looser mode is not inherited by the rotated files.

const (
	sinkActiveFileName = "flows.jsonl"
	sinkRotatedGlob    = "flows-*.jsonl"
	sinkRotatedTime    = "20060102T150405.000000000Z"
)

// fileSinkWriter is the rotating JSONL file behind NewFileSink. Used by
// the Sink worker goroutine only.
type fileSinkWriter struct {
	dir       string
	maxBytes  int64
	maxFiles  int
	fsync     bool
	f         *os.File
	size      int64
	rotations int
	// torn is set when a failed write left a partial line that could not
	// be truncated away; the next write rotates the file first.
	torn bool
	now  func() time.Time
	// writeFile writes to the active file; nil means f.Write. Tests
	// replace it to simulate a short write.
	writeFile func(f *os.File, b []byte) (int, error)
}

func openFileSinkWriter(dir string, maxBytes int64, maxFiles int, fsync bool) (*fileSinkWriter, error) {
	if dir == "" {
		return nil, errors.New("flow sink: directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("flow sink: create directory %s: %w", dir, err)
	}
	w := &fileSinkWriter{dir: dir, maxBytes: maxBytes, maxFiles: maxFiles, fsync: fsync, now: time.Now}
	active := w.activePath()
	if fi, err := os.Lstat(active); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("flow sink: %s is a symlink; refusing to write through it", active)
	} else if err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		if err := os.Rename(active, w.nextRotatedPath()); err != nil {
			return nil, fmt.Errorf("flow sink: rotate previous %s: %w", active, err)
		}
		w.prune()
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("flow sink: stat %s: %w", active, err)
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *fileSinkWriter) activePath() string { return filepath.Join(w.dir, sinkActiveFileName) }

func (w *fileSinkWriter) open() error {
	f, err := os.OpenFile(w.activePath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND|sinkOpenNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("flow sink: open %s: %w", w.activePath(), err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("flow sink: stat %s: %w", w.activePath(), err)
	}
	// The create mode applies only to a new file; tighten a pre-existing
	// one too (rotated files keep the active file's mode).
	if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return fmt.Errorf("flow sink: chmod %s: %w", w.activePath(), err)
		}
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// nextRotatedPath returns an unused rotated file name.
func (w *fileSinkWriter) nextRotatedPath() string {
	ts := w.now().UTC().Format(sinkRotatedTime)
	for {
		w.rotations++
		p := filepath.Join(w.dir, fmt.Sprintf("flows-%s-%06d.jsonl", ts, w.rotations))
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			return p
		}
	}
}

// WriteLine appends line and a newline, rotating first when the line
// would take a non-empty file past maxBytes. A failed write is rolled
// back so no partial line is left for the next one to be appended to.
func (w *fileSinkWriter) WriteLine(line []byte) error {
	if w.f == nil {
		if err := w.open(); err != nil {
			return err
		}
	}
	need := int64(len(line)) + 1
	if w.torn || (w.size > 0 && w.size+need > w.maxBytes) {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	buf := make([]byte, 0, need)
	buf = append(append(buf, line...), '\n')
	write := w.writeFile
	if write == nil {
		write = (*os.File).Write
	}
	n, err := write(w.f, buf)
	if err != nil {
		if n > 0 {
			if terr := w.f.Truncate(w.size); terr != nil {
				// The fragment stays; keep the file out of further use.
				w.size += int64(n)
				w.torn = true
			}
		}
		return fmt.Errorf("flow sink: write %s: %w", w.activePath(), err)
	}
	w.size += int64(n)
	if w.fsync {
		if err := w.f.Sync(); err != nil {
			return fmt.Errorf("flow sink: sync %s: %w", w.activePath(), err)
		}
	}
	return nil
}

func (w *fileSinkWriter) rotate() error {
	if err := os.Rename(w.activePath(), w.nextRotatedPath()); err != nil {
		return fmt.Errorf("flow sink: rotate %s: %w", w.activePath(), err)
	}
	err := w.f.Close()
	w.f = nil
	w.torn = false
	w.prune()
	if oerr := w.open(); oerr != nil {
		return oerr
	}
	if err != nil {
		return fmt.Errorf("flow sink: close rotated file: %w", err)
	}
	return nil
}

// prune deletes the oldest rotated files beyond maxFiles (0 keeps all).
// Failures are left for the next rotation.
func (w *fileSinkWriter) prune() {
	if w.maxFiles <= 0 {
		return
	}
	files, err := filepath.Glob(filepath.Join(w.dir, sinkRotatedGlob))
	if err != nil || len(files) <= w.maxFiles {
		return
	}
	sort.Strings(files)
	for _, f := range files[:len(files)-w.maxFiles] {
		_ = os.Remove(f)
	}
}

// Close closes the active file.
func (w *fileSinkWriter) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
