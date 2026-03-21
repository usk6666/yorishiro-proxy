package macro

import (
	"fmt"
	"strings"
)

// DelimOpen is the opening delimiter for template expressions.
// Uses the section sign (§, U+00A7) to avoid collisions with common payloads
// such as Handlebars/Mustache templates, Angular expressions, and SSTI test vectors.
const DelimOpen = "§"

// DelimClose is the closing delimiter for template expressions.
const DelimClose = "§"

// ExpandTemplate replaces all §variable§ and §variable | encoder1 | encoder2§
// expressions in the input string with values from the KV Store.
// Unknown variables are left as-is (no error). Unknown encoders cause an error.
func ExpandTemplate(input string, kvStore map[string]string) (string, error) {
	var result strings.Builder
	remaining := input

	for {
		// Find the next opening delimiter.
		openIdx := strings.Index(remaining, DelimOpen)
		if openIdx == -1 {
			result.WriteString(remaining)
			break
		}

		// Write everything before the delimiter.
		result.WriteString(remaining[:openIdx])

		// Find the closing delimiter after the opening one.
		after := remaining[openIdx+len(DelimOpen):]
		closeIdx := strings.Index(after, DelimClose)
		if closeIdx == -1 {
			// No closing delimiter — write the rest as literal.
			result.WriteString(remaining[openIdx:])
			break
		}

		// Extract the expression inside § §.
		expr := after[:closeIdx]
		expanded, err := expandExpression(expr, kvStore)
		if err != nil {
			return "", fmt.Errorf("template expression %s%s%s: %w", DelimOpen, expr, DelimClose, err)
		}
		result.WriteString(expanded)

		remaining = after[closeIdx+len(DelimClose):]
	}

	return result.String(), nil
}

// expandExpression evaluates a single template expression like "var_name" or
// "var_name | encoder1 | encoder2".
func expandExpression(expr string, kvStore map[string]string) (string, error) {
	parts := strings.Split(expr, "|")
	varName := strings.TrimSpace(parts[0])

	if varName == "" {
		return "", fmt.Errorf("empty variable name")
	}

	value, ok := kvStore[varName]
	if !ok {
		// Unknown variable — return the original expression unchanged.
		return DelimOpen + expr + DelimClose, nil
	}

	// Apply encoder chain if present.
	if len(parts) > 1 {
		encoderNames := make([]string, 0, len(parts)-1)
		for _, p := range parts[1:] {
			name := strings.TrimSpace(p)
			if name == "" {
				return "", fmt.Errorf("empty encoder name in pipe chain")
			}
			encoderNames = append(encoderNames, name)
		}
		var err error
		value, err = ApplyEncoders(value, encoderNames)
		if err != nil {
			return "", err
		}
	}

	return value, nil
}

// ExpandHeaders applies template expansion to each header value.
func ExpandHeaders(headers map[string]string, kvStore map[string]string) (map[string]string, error) {
	if len(headers) == 0 {
		return headers, nil
	}
	result := make(map[string]string, len(headers))
	for k, v := range headers {
		expanded, err := ExpandTemplate(v, kvStore)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", k, err)
		}
		result[k] = expanded
	}
	return result, nil
}
