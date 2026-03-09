package codec

import (
	"encoding/base64"
)

// base64Codec implements standard Base64 encoding (RFC 4648).
type base64Codec struct{}

func (c *base64Codec) Name() string { return "base64" }

func (c *base64Codec) Encode(s string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}

func (c *base64Codec) Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// base64URLCodec implements URL-safe Base64 encoding (RFC 4648 §5).
type base64URLCodec struct{}

func (c *base64URLCodec) Name() string { return "base64url" }

func (c *base64URLCodec) Encode(s string) (string, error) {
	return base64.URLEncoding.EncodeToString([]byte(s)), nil
}

func (c *base64URLCodec) Decode(s string) (string, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
