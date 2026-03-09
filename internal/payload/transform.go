package payload

import (
	"fmt"
	"strings"
)

// Transform is a function that transforms a single payload string.
type Transform func(s string) string

// Reverse returns the input string reversed (rune-aware).
func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Repeat returns the input string repeated n times.
// If n <= 0, returns an empty string.
func Repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(s, n)
}

// Truncate returns the first n runes of the input string.
// If n is greater than the string length or n <= 0, returns the original string
// (for n <= 0, returns empty string).
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if n >= len(runes) {
		return s
	}
	return string(runes[:n])
}

// Prefix returns a Transform that prepends the given prefix.
func Prefix(prefix string) Transform {
	return func(s string) string {
		return prefix + s
	}
}

// Suffix returns a Transform that appends the given suffix.
func Suffix(suffix string) Transform {
	return func(s string) string {
		return s + suffix
	}
}

// ApplyTransforms applies a sequence of transforms to each payload in the list.
func ApplyTransforms(payloads []string, transforms ...Transform) []string {
	if len(transforms) == 0 {
		return payloads
	}
	result := make([]string, len(payloads))
	for i, p := range payloads {
		s := p
		for _, t := range transforms {
			s = t(s)
		}
		result[i] = s
	}
	return result
}

// TransformPipeline wraps a Generator and applies transforms to its output.
type TransformPipeline struct {
	Generator  Generator
	Transforms []Transform
}

// Generate produces payloads and applies all transforms in order.
func (tp *TransformPipeline) Generate() ([]string, error) {
	payloads, err := tp.Generator.Generate()
	if err != nil {
		return nil, fmt.Errorf("payload: transform pipeline generate: %w", err)
	}
	return ApplyTransforms(payloads, tp.Transforms...), nil
}
