package codec

import (
	"strings"
)

// caseCodec implements case transformations (lower, upper).
// Decode always returns ErrIrreversible.
type caseCodec struct {
	name string
}

func (c *caseCodec) Name() string { return c.name }

func (c *caseCodec) Encode(s string) (string, error) {
	switch c.name {
	case "lower":
		return strings.ToLower(s), nil
	case "upper":
		return strings.ToUpper(s), nil
	default:
		return s, nil
	}
}

func (c *caseCodec) Decode(_ string) (string, error) {
	return "", ErrIrreversible
}
