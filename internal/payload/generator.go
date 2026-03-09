// Package payload provides pattern-based payload generation for security testing.
// Generators produce lists of payload strings that can be piped through codec
// encode chains for flexible payload construction.
package payload

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// maxPayloadCount is the maximum number of payloads a single generator can produce
// to prevent out-of-memory conditions.
const maxPayloadCount = 1_000_000

// Generator produces a list of payload strings.
type Generator interface {
	// Generate returns the list of payload strings.
	Generate() ([]string, error)
}

// RangeGenerator produces numeric string payloads from start to end (inclusive)
// with the given step.
type RangeGenerator struct {
	Start int
	End   int
	Step  int
}

// Generate produces numeric strings for each value in the range [Start, End].
func (g *RangeGenerator) Generate() ([]string, error) {
	step := g.Step
	if step == 0 {
		return nil, fmt.Errorf("payload: range step cannot be zero")
	}

	count := estimateCount(g.Start, g.End, step)
	if count == 0 {
		return nil, nil
	}
	if count > maxPayloadCount {
		return nil, fmt.Errorf("payload: range would generate %d payloads, exceeding maximum of %d", count, maxPayloadCount)
	}

	payloads := make([]string, 0, count)
	if step > 0 {
		for i := g.Start; i <= g.End; i += step {
			payloads = append(payloads, strconv.Itoa(i))
		}
	} else {
		for i := g.Start; i >= g.End; i += step {
			payloads = append(payloads, strconv.Itoa(i))
		}
	}
	return payloads, nil
}

// CharsetGenerator produces all combinations of characters from the given
// charset with the specified length. For example, charset "ab" with length 2
// produces: "aa", "ab", "ba", "bb".
type CharsetGenerator struct {
	Charset string
	Length  int
}

// Generate produces all character combinations. Returns an error if the total
// count would exceed maxPayloadCount.
func (g *CharsetGenerator) Generate() ([]string, error) {
	if g.Length <= 0 {
		return nil, fmt.Errorf("payload: charset length must be positive, got %d", g.Length)
	}
	chars := []rune(g.Charset)
	if len(chars) == 0 {
		return nil, fmt.Errorf("payload: charset cannot be empty")
	}

	// Calculate total: len(chars)^length. Check for overflow and limit.
	total := 1
	for i := 0; i < g.Length; i++ {
		total *= len(chars)
		if total > maxPayloadCount {
			return nil, fmt.Errorf("payload: charset would generate more than %d payloads (charset=%d, length=%d)",
				maxPayloadCount, len(chars), g.Length)
		}
	}

	payloads := make([]string, 0, total)
	buf := make([]rune, g.Length)
	g.generateRecursive(chars, buf, 0, &payloads)
	return payloads, nil
}

func (g *CharsetGenerator) generateRecursive(chars []rune, buf []rune, pos int, out *[]string) {
	if pos == g.Length {
		*out = append(*out, string(buf))
		return
	}
	for _, c := range chars {
		buf[pos] = c
		g.generateRecursive(chars, buf, pos+1, out)
	}
}

// CaseVariationGenerator produces case variations of the input string.
// It generates: original, all lower, all upper, title case, swapped case,
// and up to maxCaseBitVariations bit-flip variations (toggling case of each letter).
type CaseVariationGenerator struct {
	Input string
}

// maxCaseBitVariations is the maximum number of bit-flip case variations to generate.
// For inputs with more alpha characters than this, only the fixed variations are produced.
const maxCaseBitVariations = 16

// Generate produces case variations of the input.
func (g *CaseVariationGenerator) Generate() ([]string, error) {
	if g.Input == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var payloads []string

	addUnique := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			payloads = append(payloads, s)
		}
	}

	// Fixed variations.
	addUnique(g.Input)
	addUnique(strings.ToLower(g.Input))
	addUnique(strings.ToUpper(g.Input))

	// Title case: first letter upper, rest lower.
	runes := []rune(strings.ToLower(g.Input))
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
		addUnique(string(runes))
	}

	// Swap case.
	runes = []rune(g.Input)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			runes[i] = unicode.ToLower(r)
		} else if unicode.IsLower(r) {
			runes[i] = unicode.ToUpper(r)
		}
	}
	addUnique(string(runes))

	// Bit-flip variations: toggle case of each alphabetic character position.
	alphaPositions := alphaIndices(g.Input)
	if len(alphaPositions) <= maxCaseBitVariations {
		total := 1 << len(alphaPositions)
		if total > maxPayloadCount {
			return payloads, nil
		}
		base := []rune(g.Input)
		for mask := 0; mask < total; mask++ {
			variant := make([]rune, len(base))
			copy(variant, base)
			for bit, pos := range alphaPositions {
				if mask&(1<<bit) != 0 {
					if unicode.IsUpper(variant[pos]) {
						variant[pos] = unicode.ToLower(variant[pos])
					} else {
						variant[pos] = unicode.ToUpper(variant[pos])
					}
				}
			}
			addUnique(string(variant))
		}
	}

	return payloads, nil
}

// alphaIndices returns the rune indices of alphabetic characters in s.
func alphaIndices(s string) []int {
	var indices []int
	for i, r := range []rune(s) {
		if unicode.IsLetter(r) {
			indices = append(indices, i)
		}
	}
	return indices
}

// NullByteInjectionGenerator produces variations of the input with null bytes
// inserted at various positions.
type NullByteInjectionGenerator struct {
	Input string
}

// Generate produces null byte injection variations:
// - null byte prepended
// - null byte appended
// - null byte between each character pair
// - URL-encoded null byte (%00) variants of the above
func (g *NullByteInjectionGenerator) Generate() ([]string, error) {
	if g.Input == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var payloads []string

	addUnique := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			payloads = append(payloads, s)
		}
	}

	nullBytes := []string{"\x00", "%00"}

	for _, nb := range nullBytes {
		// Prepend.
		addUnique(nb + g.Input)
		// Append.
		addUnique(g.Input + nb)

		// Between each character pair.
		runes := []rune(g.Input)
		for i := 1; i < len(runes); i++ {
			addUnique(string(runes[:i]) + nb + string(runes[i:]))
		}
	}

	return payloads, nil
}

// estimateCount calculates the number of elements a range will generate.
func estimateCount(start, end, step int) int {
	if step > 0 {
		if end < start {
			return 0
		}
		return (end-start)/step + 1
	}
	if step < 0 {
		if start < end {
			return 0
		}
		return (start-end)/(-step) + 1
	}
	return 0
}

// Pipeline combines a Generator with an optional codec encode chain.
// It generates payloads and then applies the encode chain to each.
type Pipeline struct {
	Generator  Generator
	EncodeFunc func(payload string) (string, error)
}

// Generate produces payloads from the generator and applies the encode function
// to each payload if one is configured.
func (p *Pipeline) Generate() ([]string, error) {
	payloads, err := p.Generator.Generate()
	if err != nil {
		return nil, fmt.Errorf("payload: generate: %w", err)
	}

	if p.EncodeFunc == nil {
		return payloads, nil
	}

	encoded := make([]string, 0, len(payloads))
	for _, pl := range payloads {
		enc, err := p.EncodeFunc(pl)
		if err != nil {
			return nil, fmt.Errorf("payload: encode %q: %w", pl, err)
		}
		encoded = append(encoded, enc)
	}
	return encoded, nil
}

// NewPipeline creates a Pipeline that generates payloads and optionally encodes them.
// If codecNames is empty, no encoding is applied. The encodeFunc should typically be
// a closure over codec.Registry.Encode.
func NewPipeline(gen Generator, encodeFunc func(string) (string, error)) *Pipeline {
	return &Pipeline{
		Generator:  gen,
		EncodeFunc: encodeFunc,
	}
}
