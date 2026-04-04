package encoding

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// hashCodec implements one-way hash functions.
// Decode always returns ErrIrreversible.
type hashCodec struct {
	name string
}

func (c *hashCodec) Name() string { return c.name }

func (c *hashCodec) Encode(s string) (string, error) {
	switch c.name {
	case "md5":
		h := md5.Sum([]byte(s))
		return hex.EncodeToString(h[:]), nil
	case "sha256":
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("codec: unknown hash algorithm %q", c.name)
	}
}

func (c *hashCodec) Decode(_ string) (string, error) {
	return "", ErrIrreversible
}
