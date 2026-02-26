package macro

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"
)

// EncoderFunc is a function that transforms a string value.
type EncoderFunc func(string) (string, error)

// builtinEncoders maps encoder names to their implementations.
var builtinEncoders = map[string]EncoderFunc{
	"url_encode":    encodeURL,
	"base64":        encodeBase64,
	"base64_decode": decodeBase64,
	"html_encode":   encodeHTML,
	"hex":           encodeHex,
	"lower":         encodeLower,
	"upper":         encodeUpper,
	"md5":           encodeMD5,
	"sha256":        encodeSHA256,
}

// GetEncoder returns the encoder function for the given name.
// Returns nil if the encoder is not found.
func GetEncoder(name string) EncoderFunc {
	return builtinEncoders[name]
}

// ListEncoders returns the names of all available built-in encoders.
func ListEncoders() []string {
	names := make([]string, 0, len(builtinEncoders))
	for name := range builtinEncoders {
		names = append(names, name)
	}
	return names
}

// ApplyEncoders applies a chain of encoders to a value in order.
// Returns an error if any encoder in the chain is unknown or fails.
func ApplyEncoders(value string, encoderNames []string) (string, error) {
	result := value
	for _, name := range encoderNames {
		enc := GetEncoder(name)
		if enc == nil {
			return "", fmt.Errorf("unknown encoder %q", name)
		}
		var err error
		result, err = enc(result)
		if err != nil {
			return "", fmt.Errorf("encoder %q: %w", name, err)
		}
	}
	return result, nil
}

func encodeURL(s string) (string, error) {
	return url.QueryEscape(s), nil
}

func encodeBase64(s string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}

func decodeBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid base64 input: %w", err)
	}
	return string(b), nil
}

func encodeHTML(s string) (string, error) {
	return html.EscapeString(s), nil
}

func encodeHex(s string) (string, error) {
	return hex.EncodeToString([]byte(s)), nil
}

func encodeLower(s string) (string, error) {
	return strings.ToLower(s), nil
}

func encodeUpper(s string) (string, error) {
	return strings.ToUpper(s), nil
}

func encodeMD5(s string) (string, error) {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:]), nil
}

func encodeSHA256(s string) (string, error) {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:]), nil
}
