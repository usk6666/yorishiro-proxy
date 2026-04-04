package encoding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStarlarkCodec_Valid(t *testing.T) {
	src := []byte(`
name = "sql_escape"

def encode(s):
    return s.replace("'", "''")

def decode(s):
    return s.replace("''", "'")
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}
	if c.Name() != "sql_escape" {
		t.Errorf("Name() = %q, want %q", c.Name(), "sql_escape")
	}

	encoded, err := c.Encode("admin'--")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded != "admin''--" {
		t.Errorf("Encode() = %q, want %q", encoded, "admin''--")
	}

	decoded, err := c.Decode("admin''--")
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded != "admin'--" {
		t.Errorf("Decode() = %q, want %q", decoded, "admin'--")
	}
}

func TestParseStarlarkCodec_EncodeOnly(t *testing.T) {
	src := []byte(`
name = "prefix"

def encode(s):
    return "PREFIX_" + s
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	encoded, err := c.Encode("hello")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded != "PREFIX_hello" {
		t.Errorf("Encode() = %q, want %q", encoded, "PREFIX_hello")
	}

	_, err = c.Decode("PREFIX_hello")
	if err == nil {
		t.Error("Decode() expected error when decode is not defined")
	}
}

func TestParseStarlarkCodec_MissingName(t *testing.T) {
	src := []byte(`
def encode(s):
    return s
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for missing name")
	}
	if !strings.Contains(err.Error(), "missing required top-level 'name'") {
		t.Errorf("error = %v, want mention of missing name", err)
	}
}

func TestParseStarlarkCodec_EmptyName(t *testing.T) {
	src := []byte(`
name = ""
def encode(s):
    return s
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for empty name")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %v, want mention of empty name", err)
	}
}

func TestParseStarlarkCodec_NonStringName(t *testing.T) {
	src := []byte(`
name = 42
def encode(s):
    return s
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for non-string name")
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Errorf("error = %v, want mention of string type", err)
	}
}

func TestParseStarlarkCodec_MissingEncode(t *testing.T) {
	src := []byte(`
name = "test"
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for missing encode")
	}
	if !strings.Contains(err.Error(), "missing required 'encode' function") {
		t.Errorf("error = %v, want mention of missing encode", err)
	}
}

func TestParseStarlarkCodec_EncodeNotCallable(t *testing.T) {
	src := []byte(`
name = "test"
encode = "not a function"
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for non-callable encode")
	}
	if !strings.Contains(err.Error(), "must be a function") {
		t.Errorf("error = %v, want mention of function type", err)
	}
}

func TestParseStarlarkCodec_DecodeNotCallable(t *testing.T) {
	src := []byte(`
name = "test"
def encode(s):
    return s
decode = "not a function"
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for non-callable decode")
	}
	if !strings.Contains(err.Error(), "'decode' must be a function") {
		t.Errorf("error = %v, want mention of function type", err)
	}
}

func TestParseStarlarkCodec_SyntaxError(t *testing.T) {
	src := []byte(`
this is not valid starlark
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for syntax error")
	}
}

func TestStarlarkCodec_EncodeReturnsNonString(t *testing.T) {
	src := []byte(`
name = "bad_return"

def encode(s):
    return 42
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	_, err = c.Encode("hello")
	if err == nil {
		t.Error("Encode() expected error for non-string return")
	}
	if !strings.Contains(err.Error(), "want string") {
		t.Errorf("error = %v, want mention of string return", err)
	}
}

func TestStarlarkCodec_DecodeReturnsNonString(t *testing.T) {
	src := []byte(`
name = "bad_decode"

def encode(s):
    return s

def decode(s):
    return 42
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	_, err = c.Decode("hello")
	if err == nil {
		t.Error("Decode() expected error for non-string return")
	}
	if !strings.Contains(err.Error(), "want string") {
		t.Errorf("error = %v, want mention of string return", err)
	}
}

func TestStarlarkCodec_EncodeRuntimeError(t *testing.T) {
	src := []byte(`
name = "runtime_err"

def encode(s):
    return s + None  # type error
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	_, err = c.Encode("hello")
	if err == nil {
		t.Error("Encode() expected error for runtime error")
	}
}

func TestLoadStarlarkCodec_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_codec.star")
	err := os.WriteFile(path, []byte(`
name = "file_test"

def encode(s):
    return s.upper()
`), 0644)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	c, err := LoadStarlarkCodec(path)
	if err != nil {
		t.Fatalf("LoadStarlarkCodec() error = %v", err)
	}
	if c.Name() != "file_test" {
		t.Errorf("Name() = %q, want %q", c.Name(), "file_test")
	}

	encoded, err := c.Encode("hello")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded != "HELLO" {
		t.Errorf("Encode() = %q, want %q", encoded, "HELLO")
	}
}

func TestLoadStarlarkCodec_FileNotFound(t *testing.T) {
	_, err := LoadStarlarkCodec("/nonexistent/path.star")
	if err == nil {
		t.Fatal("LoadStarlarkCodec() expected error for missing file")
	}
}

func TestLoadCodecPlugins_Files(t *testing.T) {
	dir := t.TempDir()

	// Create two codec files.
	writeStarFile(t, dir, "sql_escape.star", `
name = "sql_escape"
def encode(s):
    return s.replace("'", "''")
def decode(s):
    return s.replace("''", "'")
`)
	writeStarFile(t, dir, "prefix.star", `
name = "prefix_test"
def encode(s):
    return "PFX_" + s
`)

	r := NewRegistry()
	configs := []CodecPluginConfig{
		{Path: filepath.Join(dir, "sql_escape.star")},
		{Path: filepath.Join(dir, "prefix.star")},
	}

	loaded, err := LoadCodecPlugins(r, configs, nil)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	if loaded != 2 {
		t.Errorf("loaded = %d, want 2", loaded)
	}

	// Verify the codecs are registered.
	c, ok := r.Get("sql_escape")
	if !ok {
		t.Fatal("sql_escape not found in registry")
	}
	encoded, err := c.Encode("admin'")
	if err != nil {
		t.Fatalf("sql_escape.Encode() error = %v", err)
	}
	if encoded != "admin''" {
		t.Errorf("sql_escape.Encode() = %q, want %q", encoded, "admin''")
	}

	c, ok = r.Get("prefix_test")
	if !ok {
		t.Fatal("prefix_test not found in registry")
	}
	encoded, err = c.Encode("hello")
	if err != nil {
		t.Fatalf("prefix_test.Encode() error = %v", err)
	}
	if encoded != "PFX_hello" {
		t.Errorf("prefix_test.Encode() = %q, want %q", encoded, "PFX_hello")
	}
}

func TestLoadCodecPlugins_Directory(t *testing.T) {
	dir := t.TempDir()

	writeStarFile(t, dir, "a.star", `
name = "codec_a"
def encode(s):
    return s + "_a"
`)
	writeStarFile(t, dir, "b.star", `
name = "codec_b"
def encode(s):
    return s + "_b"
`)
	// Non-star files should be ignored.
	err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignored"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	r := NewRegistry()
	configs := []CodecPluginConfig{{Path: dir}}

	loaded, err := LoadCodecPlugins(r, configs, nil)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	if loaded != 2 {
		t.Errorf("loaded = %d, want 2", loaded)
	}

	if _, ok := r.Get("codec_a"); !ok {
		t.Error("codec_a not found in registry")
	}
	if _, ok := r.Get("codec_b"); !ok {
		t.Error("codec_b not found in registry")
	}
}

func TestLoadCodecPlugins_DuplicateNameError(t *testing.T) {
	dir := t.TempDir()

	writeStarFile(t, dir, "base64_custom.star", `
name = "base64"
def encode(s):
    return s
`)

	r := NewRegistry()
	configs := []CodecPluginConfig{
		{Path: filepath.Join(dir, "base64_custom.star")},
	}

	_, err := LoadCodecPlugins(r, configs, nil)
	if err == nil {
		t.Fatal("LoadCodecPlugins() expected error for duplicate name")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error = %v, want mention of already registered", err)
	}
}

func TestLoadCodecPlugins_SkipsBadFile(t *testing.T) {
	dir := t.TempDir()

	// Bad file (missing required 'name' variable).
	writeStarFile(t, dir, "bad.star", `
def encode(s):
    return s
`)

	// Good file.
	writeStarFile(t, dir, "good.star", `
name = "good_codec"
def encode(s):
    return s
`)

	r := NewRegistry()

	var warnings []string
	logWarn := func(msg string, args ...any) {
		warnings = append(warnings, msg)
	}

	configs := []CodecPluginConfig{
		{Path: filepath.Join(dir, "bad.star")},
		{Path: filepath.Join(dir, "good.star")},
	}

	loaded, err := LoadCodecPlugins(r, configs, logWarn)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	// Bad file should be skipped, good file loaded.
	if loaded != 1 {
		t.Errorf("loaded = %d, want 1", loaded)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings count = %d, want 1", len(warnings))
	}
	if _, ok := r.Get("good_codec"); !ok {
		t.Error("good_codec not found in registry")
	}
}

func TestLoadCodecPlugins_MissingPath(t *testing.T) {
	r := NewRegistry()
	var warnings []string
	logWarn := func(msg string, args ...any) {
		warnings = append(warnings, msg)
	}

	configs := []CodecPluginConfig{
		{Path: "/nonexistent/path.star"},
	}

	loaded, err := LoadCodecPlugins(r, configs, logWarn)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	if loaded != 0 {
		t.Errorf("loaded = %d, want 0", loaded)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings count = %d, want 1", len(warnings))
	}
}

func TestLoadCodecPlugins_EmptyPath(t *testing.T) {
	r := NewRegistry()
	configs := []CodecPluginConfig{{Path: ""}}

	loaded, err := LoadCodecPlugins(r, configs, nil)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	if loaded != 0 {
		t.Errorf("loaded = %d, want 0", loaded)
	}
}

func TestLoadCodecPlugins_EmptyConfigs(t *testing.T) {
	r := NewRegistry()
	loaded, err := LoadCodecPlugins(r, nil, nil)
	if err != nil {
		t.Fatalf("LoadCodecPlugins() error = %v", err)
	}
	if loaded != 0 {
		t.Errorf("loaded = %d, want 0", loaded)
	}
}

func TestStarlarkCodec_ChainWithBuiltin(t *testing.T) {
	src := []byte(`
name = "sql_escape"
def encode(s):
    return s.replace("'", "''")
def decode(s):
    return s.replace("''", "'")
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	r := NewRegistry()
	if err := r.Register("sql_escape", c); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Chain: sql_escape -> url_encode_query.
	result, err := r.Encode("admin'--", []string{"sql_escape", "url_encode_query"})
	if err != nil {
		t.Fatalf("Encode chain error = %v", err)
	}
	// sql_escape: admin'-- -> admin''--
	// url_encode_query: admin''-- -> admin%27%27--
	want := "admin%27%27--"
	if result != want {
		t.Errorf("Encode chain = %q, want %q", result, want)
	}

	// Reverse chain.
	decoded, err := r.Decode(result, []string{"sql_escape", "url_encode_query"})
	if err != nil {
		t.Fatalf("Decode chain error = %v", err)
	}
	if decoded != "admin'--" {
		t.Errorf("Decode chain = %q, want %q", decoded, "admin'--")
	}
}

func TestLoadStarlarkCodec_FileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.star")

	// Create a file just over 1 MB.
	data := make([]byte, 1<<20+1)
	for i := range data {
		data[i] = ' '
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadStarlarkCodec(path)
	if err == nil {
		t.Fatal("LoadStarlarkCodec() expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %v, want mention of exceeds limit", err)
	}
}

func TestStarlarkCodec_EncodeStepLimitPreventsExcessiveComputation(t *testing.T) {
	// Use deep recursion to exhaust step limit.
	src := []byte(`
name = "expensive"

def spin(n):
    if n <= 0:
        return ""
    return spin(n - 1)

def encode(s):
    return spin(10000000)
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	_, err = c.Encode("hello")
	if err == nil {
		t.Fatal("Encode() expected error for excessive computation, got nil")
	}
}

func TestStarlarkCodec_DecodeStepLimitPreventsExcessiveComputation(t *testing.T) {
	src := []byte(`
name = "expensive_decode"

def spin(n):
    if n <= 0:
        return ""
    return spin(n - 1)

def encode(s):
    return s

def decode(s):
    return spin(10000000)
`)

	c, err := ParseStarlarkCodec("test.star", src)
	if err != nil {
		t.Fatalf("ParseStarlarkCodec() error = %v", err)
	}

	_, err = c.Decode("hello")
	if err == nil {
		t.Fatal("Decode() expected error for excessive computation, got nil")
	}
}

func TestParseStarlarkCodec_StepLimitPreventsExcessiveComputationAtLoad(t *testing.T) {
	// Use a comprehension to exhaust step limit at load time.
	src := []byte(`
x = [i for i in range(10000000)]
name = "never_reached"
def encode(s):
    return s
`)

	_, err := ParseStarlarkCodec("test.star", src)
	if err == nil {
		t.Fatal("ParseStarlarkCodec() expected error for excessive computation at load time")
	}
}

// writeStarFile creates a .star file in the given directory.
func writeStarFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	if err != nil {
		t.Fatalf("WriteFile(%s) error = %v", name, err)
	}
}
