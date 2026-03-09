// Package codec provides bidirectional string encoding/decoding transformations.
// It is designed to be shared across macro, fuzzer, resender, and plugin consumers.
package codec

import (
	"fmt"
	"sort"
	"sync"
)

// Codec represents a bidirectional string transformation.
// For irreversible transformations (e.g. hashes), Decode returns an error.
type Codec interface {
	// Name returns the codec's registered name.
	Name() string
	// Encode transforms the input string.
	Encode(s string) (string, error)
	// Decode reverses the transformation. Returns an error for irreversible codecs.
	Decode(s string) (string, error)
}

// ErrIrreversible is returned by Decode for one-way codecs (hashes, case transforms).
var ErrIrreversible = fmt.Errorf("codec: irreversible transformation, decode not supported")

// Registry maps codec names to Codec implementations.
type Registry struct {
	mu     sync.RWMutex
	codecs map[string]Codec
}

// NewRegistry creates a new Registry with all built-in codecs registered.
func NewRegistry() *Registry {
	r := &Registry{
		codecs: make(map[string]Codec),
	}
	for _, c := range builtins() {
		r.codecs[c.Name()] = c
	}
	return r
}

var (
	defaultOnce     sync.Once
	defaultRegistry *Registry
)

// DefaultRegistry returns the process-wide shared Registry singleton.
func DefaultRegistry() *Registry {
	defaultOnce.Do(func() {
		defaultRegistry = NewRegistry()
	})
	return defaultRegistry
}

// Get returns the Codec registered under the given name.
func (r *Registry) Get(name string) (Codec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.codecs[name]
	return c, ok
}

// List returns the sorted names of all registered codecs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.codecs))
	for name := range r.codecs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Register adds a custom Codec to the registry.
// Returns an error if a codec with the same name is already registered.
func (r *Registry) Register(name string, c Codec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.codecs[name]; exists {
		return fmt.Errorf("codec: %q is already registered", name)
	}
	r.codecs[name] = c
	return nil
}

// Encode applies a chain of codecs in order, encoding the value through each.
func (r *Registry) Encode(value string, names []string) (string, error) {
	result := value
	for _, name := range names {
		c, ok := r.Get(name)
		if !ok {
			return "", fmt.Errorf("codec: unknown codec %q", name)
		}
		var err error
		result, err = c.Encode(result)
		if err != nil {
			return "", fmt.Errorf("codec %q encode: %w", name, err)
		}
	}
	return result, nil
}

// Decode applies a chain of codecs in reverse order, decoding the value through each.
func (r *Registry) Decode(value string, names []string) (string, error) {
	result := value
	// Apply in reverse order.
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		c, ok := r.Get(name)
		if !ok {
			return "", fmt.Errorf("codec: unknown codec %q", name)
		}
		var err error
		result, err = c.Decode(result)
		if err != nil {
			return "", fmt.Errorf("codec %q decode: %w", name, err)
		}
	}
	return result, nil
}

// Package-level convenience functions delegating to DefaultRegistry.

// Encode applies a chain of codecs to the value using the default registry.
func Encode(value string, names []string) (string, error) {
	return DefaultRegistry().Encode(value, names)
}

// Decode applies a chain of codecs in reverse to the value using the default registry.
func Decode(value string, names []string) (string, error) {
	return DefaultRegistry().Decode(value, names)
}

// builtins returns all built-in codec instances.
func builtins() []Codec {
	return []Codec{
		&base64Codec{},
		&base64URLCodec{},
		&urlEncodeQueryCodec{},
		&urlEncodePathCodec{},
		&urlEncodeFullCodec{},
		&doubleURLEncodeCodec{},
		&hexCodec{},
		&htmlEntityCodec{},
		&htmlEscapeCodec{},
		&unicodeEscapeCodec{},
		&hashCodec{name: "md5"},
		&hashCodec{name: "sha256"},
		&caseCodec{name: "lower"},
		&caseCodec{name: "upper"},
	}
}
