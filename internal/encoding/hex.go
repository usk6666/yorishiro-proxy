package encoding

import (
	"encoding/hex"
)

// hexCodec implements hexadecimal encoding.
type hexCodec struct{}

func (c *hexCodec) Name() string { return "hex" }

func (c *hexCodec) Encode(s string) (string, error) {
	return hex.EncodeToString([]byte(s)), nil
}

func (c *hexCodec) Decode(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
