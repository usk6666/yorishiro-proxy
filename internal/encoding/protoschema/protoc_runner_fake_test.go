package protoschema

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Fake-protoc tests (USK-1208). The real-protoc tests in
// protoc_runner_test.go skip wherever protoc is not installed — which
// includes the fast CI tier — so RunProtoc's result reading and error
// wrapping went unexercised there. These drive RunProtoc against a
// POSIX shell script standing in for protoc.
//
// The script cannot be the usual re-exec'd test binary: RunProtoc gives
// the child only PATH, so an env-var-driven helper would never learn what
// to do. Everything the script needs (fixture path, argv log path,
// behaviour) is baked into its text instead.

// fakeProtocMode selects what the fake protoc does after logging its argv.
type fakeProtocMode int

const (
	// fakeProtocWriteDesc copies the embedded test.desc fixture to the
	// --descriptor_set_out path and exits 0.
	fakeProtocWriteDesc fakeProtocMode = iota
	// fakeProtocFail prints fakeProtocErrMarker to stderr and exits 3.
	fakeProtocFail
	// fakeProtocNoOutput exits 0 without writing the descriptor set.
	fakeProtocNoOutput
)

const fakeProtocErrMarker = "FAKE_PROTOC_ERR_MARKER"

// writeFakeProtoc writes the fake protoc script and returns its absolute
// path plus the file it logs its argv to (one argument per line).
func writeFakeProtoc(t *testing.T, mode fakeProtocMode) (bin, argvLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake protoc is a POSIX shell script")
	}
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixture.desc")
	if err := os.WriteFile(fixture, testDescBytes, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	argvLog = filepath.Join(dir, "argv.log")

	var tail string
	switch mode {
	case fakeProtocWriteDesc:
		tail = "cat " + shellQuote(fixture) + " > \"$out\"\nexit 0\n"
	case fakeProtocFail:
		tail = "echo " + fakeProtocErrMarker + " >&2\nexit 3\n"
	case fakeProtocNoOutput:
		tail = "exit 0\n"
	}
	script := "#!/bin/sh\n" +
		": > " + shellQuote(argvLog) + "\n" +
		"out=\n" +
		"for a in \"$@\"; do\n" +
		"  printf '%s\\n' \"$a\" >> " + shellQuote(argvLog) + "\n" +
		"  case \"$a\" in --descriptor_set_out=*) out=\"${a#--descriptor_set_out=}\" ;; esac\n" +
		"done\n" +
		tail
	bin = filepath.Join(dir, "protoc")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake protoc: %v", err)
	}
	return bin, argvLog
}

// shellQuote returns s as a single-quoted POSIX shell word, escaping any
// embedded single quote (close the quote, emit an escaped quote, reopen)
// so a quote in TMPDIR cannot break out of the script's quoting.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fakeProtocInput writes a .proto file (content is irrelevant to the fake)
// and returns its path and the directory holding it.
func fakeProtocInput(t *testing.T) (proto, dir string) {
	t.Helper()
	dir = t.TempDir()
	proto = filepath.Join(dir, "greeter.proto")
	if err := os.WriteFile(proto, []byte(`syntax = "proto3";`), 0o644); err != nil {
		t.Fatal(err)
	}
	return proto, dir
}

func TestRunProtoc_Fake_Success(t *testing.T) {
	t.Parallel()
	bin, argvLog := writeFakeProtoc(t, fakeProtocWriteDesc)
	proto, dir := fakeProtocInput(t)

	res, err := RunProtoc(context.Background(), ProtocRunOptions{
		Binary:       bin,
		ProtoPaths:   []string{proto},
		AllowedRoots: []string{dir},
	})
	if err != nil {
		t.Fatalf("RunProtoc: %v", err)
	}
	if !bytes.Equal(res.DescriptorSet, testDescBytes) {
		t.Fatalf("DescriptorSet = %d bytes, want the %d-byte fixture the fake protoc wrote", len(res.DescriptorSet), len(testDescBytes))
	}
	specs, err := LoadFileDescriptorSet(res.DescriptorSet, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	if !slices.ContainsFunc(specs, func(s *ServiceSpec) bool { return s.Service == "usk.test.Greeter" }) {
		t.Errorf("specs do not include usk.test.Greeter: %+v", specs)
	}

	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("fake protoc argv log: %v", err)
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedProto := filepath.Join(resolvedDir, filepath.Base(proto))
	for _, want := range []string{"-I" + resolvedDir, "--include_imports", resolvedProto} {
		if !slices.Contains(argv, want) {
			t.Errorf("protoc argv %q is missing %q", argv, want)
		}
	}
	if !slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "--descriptor_set_out=") }) {
		t.Errorf("protoc argv %q has no --descriptor_set_out", argv)
	}
}

func TestRunProtoc_Fake_NonZeroExit(t *testing.T) {
	t.Parallel()
	bin, _ := writeFakeProtoc(t, fakeProtocFail)
	proto, dir := fakeProtocInput(t)

	res, err := RunProtoc(context.Background(), ProtocRunOptions{
		Binary:       bin,
		ProtoPaths:   []string{proto},
		AllowedRoots: []string{dir},
	})
	if err == nil {
		t.Fatalf("RunProtoc succeeded (%d bytes) on a protoc that exited 3", len(res.DescriptorSet))
	}
	if errors.Is(err, ErrProtocNotFound()) {
		t.Errorf("err is ErrProtocNotFound for a protoc that ran: %v", err)
	}
	for _, want := range []string{"protoc failed (exit 3)", fakeProtocErrMarker} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to contain %q", err, want)
		}
	}
}

func TestRunProtoc_Fake_NoOutputFile(t *testing.T) {
	t.Parallel()
	bin, _ := writeFakeProtoc(t, fakeProtocNoOutput)
	proto, dir := fakeProtocInput(t)

	res, err := RunProtoc(context.Background(), ProtocRunOptions{
		Binary:       bin,
		ProtoPaths:   []string{proto},
		AllowedRoots: []string{dir},
	})
	if err == nil {
		t.Fatalf("RunProtoc succeeded (%d bytes) without a descriptor set on disk", len(res.DescriptorSet))
	}
	if !strings.Contains(err.Error(), "read protoc output") {
		t.Errorf("err = %q, want it to contain %q", err, "read protoc output")
	}
}
