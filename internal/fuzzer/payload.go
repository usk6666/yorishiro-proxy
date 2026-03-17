package fuzzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/payload"
)

// PayloadSet defines a set of payloads to inject at a position.
type PayloadSet struct {
	// Type is the payload generation type: wordlist, file, range, sequence,
	// charset, case_variation, or null_byte_injection.
	Type string `json:"type"`
	// Values is the list of payload strings (for wordlist type).
	Values []string `json:"values,omitempty"`
	// Path is the file path relative to the wordlists base directory (for file type).
	Path string `json:"path,omitempty"`
	// Start is the range start value (for range/sequence types).
	Start *int `json:"start,omitempty"`
	// End is the range end value (for range/sequence types).
	End *int `json:"end,omitempty"`
	// Step is the range step value (for range/sequence types). Defaults to 1.
	Step *int `json:"step,omitempty"`
	// Format is the format string for sequence type (e.g., "user%04d").
	Format string `json:"format,omitempty"`
	// Encoding is an optional chain of codec names to apply to each generated payload.
	// Codecs are applied in order using codec.Encode (e.g., ["url_encode_query", "base64"]).
	Encoding []string `json:"encoding,omitempty"`
	// Charset is the character set for charset type (e.g., "abc" or "0123456789").
	Charset string `json:"charset,omitempty"`
	// Length is the combination length for charset type.
	Length *int `json:"length,omitempty"`
	// Input is the base string for case_variation and null_byte_injection types.
	Input string `json:"input,omitempty"`
}

// Validate checks that a PayloadSet is well-formed.
func (ps *PayloadSet) Validate() error {
	if err := ps.validateType(); err != nil {
		return err
	}
	return ps.validateEncoding()
}

// validateType checks that the PayloadSet type and its required fields are valid.
func (ps *PayloadSet) validateType() error {
	switch ps.Type {
	case "wordlist":
		return ps.validateWordlist()
	case "file":
		return ps.validateFile()
	case "range":
		return ps.validateRange()
	case "sequence":
		return ps.validateSequence()
	case "charset":
		return ps.validateCharset()
	case "case_variation":
		return ps.validateInputRequired("case_variation")
	case "null_byte_injection":
		return ps.validateInputRequired("null_byte_injection")
	default:
		return fmt.Errorf("invalid payload set type %q: must be one of wordlist, file, range, sequence, charset, case_variation, null_byte_injection", ps.Type)
	}
}

func (ps *PayloadSet) validateWordlist() error {
	if len(ps.Values) == 0 {
		return fmt.Errorf("wordlist payload set requires at least one value")
	}
	if len(ps.Values) > maxPayloadCount {
		return fmt.Errorf("wordlist payload set contains %d values, exceeding maximum of %d", len(ps.Values), maxPayloadCount)
	}
	return nil
}

func (ps *PayloadSet) validateFile() error {
	if ps.Path == "" {
		return fmt.Errorf("file payload set requires a path")
	}
	if filepath.IsAbs(ps.Path) {
		return fmt.Errorf("file path must be relative, got absolute path %q", ps.Path)
	}
	return nil
}

func (ps *PayloadSet) validateRange() error {
	if ps.Start == nil || ps.End == nil {
		return fmt.Errorf("range payload set requires start and end")
	}
	return nil
}

func (ps *PayloadSet) validateSequence() error {
	if ps.Start == nil || ps.End == nil {
		return fmt.Errorf("sequence payload set requires start and end")
	}
	if ps.Format == "" {
		return fmt.Errorf("sequence payload set requires a format string")
	}
	return nil
}

func (ps *PayloadSet) validateCharset() error {
	if ps.Charset == "" {
		return fmt.Errorf("charset payload set requires a charset")
	}
	if ps.Length == nil || *ps.Length <= 0 {
		return fmt.Errorf("charset payload set requires a positive length")
	}
	return nil
}

func (ps *PayloadSet) validateInputRequired(typeName string) error {
	if ps.Input == "" {
		return fmt.Errorf("%s payload set requires an input string", typeName)
	}
	return nil
}

// maxEncodingChainLen is the maximum number of codecs allowed in an encoding chain
// to prevent excessive CPU consumption from very long chains.
const maxEncodingChainLen = 10

// validateEncoding checks that all encoding codec names exist in the registry.
func (ps *PayloadSet) validateEncoding() error {
	if len(ps.Encoding) == 0 {
		return nil
	}
	if len(ps.Encoding) > maxEncodingChainLen {
		return fmt.Errorf("encoding chain length %d exceeds maximum of %d", len(ps.Encoding), maxEncodingChainLen)
	}
	reg := codec.DefaultRegistry()
	for _, name := range ps.Encoding {
		if _, ok := reg.Get(name); !ok {
			return fmt.Errorf("unknown encoding codec %q", name)
		}
	}
	return nil
}

// Generate produces the list of payload strings from this PayloadSet.
// baseDir is the wordlists base directory (used for file type).
func (ps *PayloadSet) Generate(baseDir string) ([]string, error) {
	var payloads []string
	var err error

	switch ps.Type {
	case "wordlist":
		payloads = ps.Values
	case "file":
		payloads, err = ps.generateFromFile(baseDir)
	case "range":
		payloads, err = ps.generateRange()
	case "sequence":
		payloads, err = ps.generateSequence()
	case "charset":
		payloads, err = ps.generateCharset()
	case "case_variation":
		payloads, err = ps.generateCaseVariation()
	case "null_byte_injection":
		payloads, err = ps.generateNullByteInjection()
	default:
		return nil, fmt.Errorf("unsupported payload set type %q", ps.Type)
	}
	if err != nil {
		return nil, err
	}

	// Apply encoding chain if specified.
	if len(ps.Encoding) > 0 {
		payloads, err = applyEncoding(payloads, ps.Encoding)
		if err != nil {
			return nil, err
		}
	}

	return payloads, nil
}

// generateCharset delegates to payload.CharsetGenerator.
func (ps *PayloadSet) generateCharset() ([]string, error) {
	gen := &payload.CharsetGenerator{
		Charset: ps.Charset,
		Length:  *ps.Length,
	}
	return gen.Generate()
}

// generateCaseVariation delegates to payload.CaseVariationGenerator.
func (ps *PayloadSet) generateCaseVariation() ([]string, error) {
	gen := &payload.CaseVariationGenerator{
		Input: ps.Input,
	}
	return gen.Generate()
}

// generateNullByteInjection delegates to payload.NullByteInjectionGenerator.
func (ps *PayloadSet) generateNullByteInjection() ([]string, error) {
	gen := &payload.NullByteInjectionGenerator{
		Input: ps.Input,
	}
	return gen.Generate()
}

// applyEncoding applies a codec encoding chain to each payload.
func applyEncoding(payloads []string, encodingChain []string) ([]string, error) {
	encoded := make([]string, 0, len(payloads))
	for _, p := range payloads {
		enc, err := codec.Encode(p, encodingChain)
		if err != nil {
			return nil, fmt.Errorf("encode payload %q: %w", p, err)
		}
		encoded = append(encoded, enc)
	}
	return encoded, nil
}

// generateFromFile reads payloads from a file, one per line.
func (ps *PayloadSet) generateFromFile(baseDir string) ([]string, error) {
	fullPath, err := resolveWordlistPath(baseDir, ps.Path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist file %q: %w", ps.Path, err)
	}
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			payloads = append(payloads, line)
			if len(payloads) > maxPayloadCount {
				return nil, fmt.Errorf("wordlist file %q exceeds maximum of %d lines", ps.Path, maxPayloadCount)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist file %q: %w", ps.Path, err)
	}

	return payloads, nil
}

// maxPayloadCount is the maximum number of payloads a single set can generate
// to prevent out-of-memory conditions from excessively large ranges.
const maxPayloadCount = 1_000_000

// generateRange produces a list of number strings from start to end (inclusive) with step.
func (ps *PayloadSet) generateRange() ([]string, error) {
	start := *ps.Start
	end := *ps.End
	step := 1
	if ps.Step != nil {
		step = *ps.Step
	}

	if step == 0 {
		return nil, fmt.Errorf("range step cannot be zero")
	}

	// Estimate count and check against the limit.
	count := estimateCount(start, end, step)
	if count > maxPayloadCount {
		return nil, fmt.Errorf("range would generate %d payloads, exceeding maximum of %d", count, maxPayloadCount)
	}

	payloads := make([]string, 0, count)
	if step > 0 {
		for i := start; i <= end; i += step {
			payloads = append(payloads, strconv.Itoa(i))
		}
	} else {
		for i := start; i >= end; i += step {
			payloads = append(payloads, strconv.Itoa(i))
		}
	}

	return payloads, nil
}

// generateSequence produces formatted strings from start to end with step.
func (ps *PayloadSet) generateSequence() ([]string, error) {
	start := *ps.Start
	end := *ps.End
	step := 1
	if ps.Step != nil {
		step = *ps.Step
	}

	if step == 0 {
		return nil, fmt.Errorf("sequence step cannot be zero")
	}

	// Estimate count and check against the limit.
	count := estimateCount(start, end, step)
	if count > maxPayloadCount {
		return nil, fmt.Errorf("sequence would generate %d payloads, exceeding maximum of %d", count, maxPayloadCount)
	}

	payloads := make([]string, 0, count)
	if step > 0 {
		for i := start; i <= end; i += step {
			payloads = append(payloads, fmt.Sprintf(ps.Format, i))
		}
	} else {
		for i := start; i >= end; i += step {
			payloads = append(payloads, fmt.Sprintf(ps.Format, i))
		}
	}

	return payloads, nil
}

// estimateCount calculates the number of elements a range/sequence will generate.
func estimateCount(start, end, step int) int {
	if step > 0 {
		if end < start {
			return 0
		}
		return (end-start)/step + 1
	}
	// step < 0 (step == 0 is handled by caller)
	if start < end {
		return 0
	}
	return (start-end)/(-step) + 1
}

// resolveWordlistPath resolves and validates a relative wordlist path
// against the base directory, preventing path traversal.
func resolveWordlistPath(baseDir, relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("wordlist path is empty")
	}

	// Reject absolute paths.
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("wordlist path must be relative, got %q", relPath)
	}

	// Reject obvious traversal attempts before filesystem operations.
	if strings.Contains(relPath, "..") {
		return "", fmt.Errorf("path traversal detected in %q", relPath)
	}

	fullPath := filepath.Join(baseDir, relPath)

	// Resolve symlinks to get the real path.
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return "", fmt.Errorf("resolve wordlist path %q (hint: place wordlist files in %q): %w", relPath, baseDir, err)
	}

	// Resolve the base directory as well.
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolve base directory %q: %w", baseDir, err)
	}

	// Ensure the resolved path is within the base directory.
	if !strings.HasPrefix(resolved, resolvedBase+string(filepath.Separator)) && resolved != resolvedBase {
		return "", fmt.Errorf("path traversal detected: %q resolves to %q which is outside %q", relPath, resolved, resolvedBase)
	}

	return resolved, nil
}

// DefaultWordlistBaseDir returns the default base directory for wordlist files.
func DefaultWordlistBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".yorishiro-proxy", "wordlists")
	}
	return filepath.Join(home, ".yorishiro-proxy", "wordlists")
}
