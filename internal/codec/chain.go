package codec

// Chain provides a fluent interface for applying multiple codecs in sequence.
type Chain struct {
	registry *Registry
	names    []string
}

// NewChain creates a Chain using the given registry and codec names.
func NewChain(registry *Registry, names ...string) *Chain {
	return &Chain{
		registry: registry,
		names:    names,
	}
}

// Encode applies all codecs in order to the value.
func (c *Chain) Encode(value string) (string, error) {
	return c.registry.Encode(value, c.names)
}

// Decode applies all codecs in reverse order to the value.
func (c *Chain) Decode(value string) (string, error) {
	return c.registry.Decode(value, c.names)
}
