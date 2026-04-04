package macro

import (
	"fmt"
	"sort"

	"github.com/usk6666/yorishiro-proxy/internal/encoding"
)

// EncoderFunc is a function that transforms a string value.
type EncoderFunc func(string) (string, error)

// encoderAliases maps legacy macro encoder names to their codec equivalents.
var encoderAliases = map[string]string{
	"url_encode":  "url_encode_query",
	"html_encode": "html_escape",
}

// GetEncoder returns the encoder function for the given name.
// Returns nil if the encoder is not found.
// Supports both legacy names (url_encode, html_encode, base64_decode) and
// codec names.
func GetEncoder(name string) EncoderFunc {
	// Handle base64_decode as a special case: it maps to codec base64's Decode.
	if name == "base64_decode" {
		return func(s string) (string, error) {
			return encoding.Decode(s, []string{"base64"})
		}
	}

	// Resolve legacy aliases.
	codecName := name
	if alias, ok := encoderAliases[name]; ok {
		codecName = alias
	}

	c, ok := encoding.DefaultRegistry().Get(codecName)
	if !ok {
		return nil
	}
	return c.Encode
}

// ListEncoders returns the names of all available built-in encoders.
// This returns the legacy encoder names for backward compatibility.
func ListEncoders() []string {
	names := []string{
		"url_encode",
		"base64",
		"base64_decode",
		"html_encode",
		"hex",
		"lower",
		"upper",
		"md5",
		"sha256",
	}
	sort.Strings(names)
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
