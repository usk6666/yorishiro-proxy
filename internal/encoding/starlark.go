package encoding

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// defaultMaxSteps is the default maximum number of Starlark execution steps
// per codec invocation. This prevents infinite loops from causing DoS.
const defaultMaxSteps uint64 = 1_000_000

// maxCodecFileSize is the maximum allowed file size for a Starlark codec file (1 MB).
const maxCodecFileSize int64 = 1 << 20

// StarlarkCodec wraps Starlark encode/decode functions as a Codec.
// It is safe for concurrent use because a new starlark.Thread is
// created for each Encode/Decode call.
type StarlarkCodec struct {
	name      string
	encodeFn  starlark.Callable
	decodeFn  starlark.Callable // nil if decode is not defined
	maxSteps  uint64
	printFunc func(msg string)
}

// Name returns the codec's registered name.
func (c *StarlarkCodec) Name() string { return c.name }

// Encode calls the Starlark encode function.
func (c *StarlarkCodec) Encode(s string) (string, error) {
	return c.callStarlark("encode", c.encodeFn, s)
}

// Decode calls the Starlark decode function. Returns an error if decode is not defined.
func (c *StarlarkCodec) Decode(s string) (string, error) {
	if c.decodeFn == nil {
		return "", fmt.Errorf("codec %q: decode not defined", c.name)
	}
	return c.callStarlark("decode", c.decodeFn, s)
}

// callStarlark invokes a Starlark callable with a single string argument
// and returns the string result. A new Thread is created per call for
// concurrency safety.
func (c *StarlarkCodec) callStarlark(fnName string, fn starlark.Callable, s string) (string, error) {
	thread := &starlark.Thread{
		Name: c.name + "." + fnName,
		Print: func(_ *starlark.Thread, msg string) {
			if c.printFunc != nil {
				c.printFunc(msg)
			}
		},
	}
	thread.SetMaxExecutionSteps(c.maxSteps)

	result, err := starlark.Call(thread, fn, starlark.Tuple{starlark.String(s)}, nil)
	if err != nil {
		return "", fmt.Errorf("codec %q %s: %w", c.name, fnName, err)
	}

	str, ok := starlark.AsString(result)
	if !ok {
		return "", fmt.Errorf("codec %q %s: returned %s, want string", c.name, fnName, result.Type())
	}
	return str, nil
}

// LoadStarlarkCodec loads a Starlark codec from a file path.
// The file must define a top-level "name" string and an "encode" function.
// An optional "decode" function may be provided.
// Files larger than 1 MB are rejected to prevent excessive memory usage.
func LoadStarlarkCodec(path string) (*StarlarkCodec, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read codec file %s: %w", path, err)
	}
	if info.Size() > maxCodecFileSize {
		return nil, fmt.Errorf("codec file %s: size %d exceeds limit %d bytes", path, info.Size(), maxCodecFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read codec file %s: %w", path, err)
	}
	return ParseStarlarkCodec(path, data)
}

// ParseStarlarkCodec parses a Starlark codec from source data.
// filename is used for error messages.
func ParseStarlarkCodec(filename string, data []byte) (*StarlarkCodec, error) {
	thread := &starlark.Thread{Name: filename}
	thread.SetMaxExecutionSteps(defaultMaxSteps)

	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread,
		filename,
		data,
		nil, // no predeclared
	)
	if err != nil {
		return nil, fmt.Errorf("exec codec file %s: %w", filename, err)
	}

	// Extract "name" string.
	nameVal, ok := globals["name"]
	if !ok {
		return nil, fmt.Errorf("codec file %s: missing required top-level 'name' variable", filename)
	}
	name, ok := starlark.AsString(nameVal)
	if !ok {
		return nil, fmt.Errorf("codec file %s: 'name' must be a string, got %s", filename, nameVal.Type())
	}
	if name == "" {
		return nil, fmt.Errorf("codec file %s: 'name' must not be empty", filename)
	}

	// Extract "encode" function.
	encodeVal, ok := globals["encode"]
	if !ok {
		return nil, fmt.Errorf("codec file %s: missing required 'encode' function", filename)
	}
	encodeFn, ok := encodeVal.(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("codec file %s: 'encode' must be a function, got %s", filename, encodeVal.Type())
	}

	// Extract optional "decode" function.
	var decodeFn starlark.Callable
	if decodeVal, ok := globals["decode"]; ok {
		decodeFn, ok = decodeVal.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("codec file %s: 'decode' must be a function, got %s", filename, decodeVal.Type())
		}
	}

	return &StarlarkCodec{
		name:     name,
		encodeFn: encodeFn,
		decodeFn: decodeFn,
		maxSteps: defaultMaxSteps,
	}, nil
}

// CodecPluginConfig defines the configuration for a single codec plugin entry.
type CodecPluginConfig struct {
	// Path is the filesystem path to a Starlark codec file or directory.
	// If a directory, all *.star files in it are loaded.
	Path string `json:"path"`
}

// LoadCodecPlugins loads and registers all Starlark codec plugins from the given configs.
// Each loaded codec is registered with the given registry.
// If a codec name conflicts with an existing registration, an error is returned.
// If a file fails to load, it is logged and skipped.
func LoadCodecPlugins(registry *Registry, configs []CodecPluginConfig, logWarn func(msg string, args ...any)) (int, error) {
	if logWarn == nil {
		logWarn = func(_ string, _ ...any) {}
	}

	loaded := 0
	for _, cfg := range configs {
		if cfg.Path == "" {
			continue
		}

		info, err := os.Stat(cfg.Path)
		if err != nil {
			logWarn("codec plugin path not found, skipping",
				"path", cfg.Path, "error", err.Error())
			continue
		}

		if info.IsDir() {
			n, err := loadCodecDir(registry, cfg.Path, logWarn)
			if err != nil {
				return loaded, err
			}
			loaded += n
		} else {
			ok, err := loadCodecFile(registry, cfg.Path, logWarn)
			if err != nil {
				return loaded, err
			}
			if ok {
				loaded++
			}
		}
	}
	return loaded, nil
}

// loadCodecDir loads all *.star files in a directory.
func loadCodecDir(registry *Registry, dir string, logWarn func(string, ...any)) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read codec directory %s: %w", dir, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".star") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		ok, err := loadCodecFile(registry, path, logWarn)
		if err != nil {
			return loaded, err
		}
		if ok {
			loaded++
		}
	}
	return loaded, nil
}

// loadCodecFile loads a single Starlark codec file and registers it.
// Returns (true, nil) on success, (false, nil) if the file was skipped,
// or (false, error) if registration failed due to a name conflict.
func loadCodecFile(registry *Registry, path string, logWarn func(string, ...any)) (bool, error) {
	codec, err := LoadStarlarkCodec(path)
	if err != nil {
		logWarn("failed to load codec plugin, skipping",
			"path", path, "error", err.Error())
		return false, nil
	}

	if err := registry.Register(codec.name, codec); err != nil {
		return false, fmt.Errorf("register codec plugin %q from %s: %w", codec.name, path, err)
	}
	return true, nil
}
