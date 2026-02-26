package fuzzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PayloadSet defines a set of payloads to inject at a position.
type PayloadSet struct {
	// Type is the payload generation type: wordlist, file, range, sequence.
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
}

// Validate checks that a PayloadSet is well-formed.
func (ps *PayloadSet) Validate() error {
	switch ps.Type {
	case "wordlist":
		if len(ps.Values) == 0 {
			return fmt.Errorf("wordlist payload set requires at least one value")
		}
	case "file":
		if ps.Path == "" {
			return fmt.Errorf("file payload set requires a path")
		}
		if filepath.IsAbs(ps.Path) {
			return fmt.Errorf("file path must be relative, got absolute path %q", ps.Path)
		}
	case "range":
		if ps.Start == nil || ps.End == nil {
			return fmt.Errorf("range payload set requires start and end")
		}
	case "sequence":
		if ps.Start == nil || ps.End == nil {
			return fmt.Errorf("sequence payload set requires start and end")
		}
		if ps.Format == "" {
			return fmt.Errorf("sequence payload set requires a format string")
		}
	default:
		return fmt.Errorf("invalid payload set type %q: must be one of wordlist, file, range, sequence", ps.Type)
	}
	return nil
}

// Generate produces the list of payload strings from this PayloadSet.
// baseDir is the wordlists base directory (used for file type).
func (ps *PayloadSet) Generate(baseDir string) ([]string, error) {
	switch ps.Type {
	case "wordlist":
		return ps.Values, nil
	case "file":
		return ps.generateFromFile(baseDir)
	case "range":
		return ps.generateRange()
	case "sequence":
		return ps.generateSequence()
	default:
		return nil, fmt.Errorf("unsupported payload set type %q", ps.Type)
	}
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
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wordlist file %q: %w", ps.Path, err)
	}

	return payloads, nil
}

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

	var payloads []string
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

	var payloads []string
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
		return "", fmt.Errorf("resolve wordlist path %q: %w", relPath, err)
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
		return filepath.Join(".", ".katashiro-proxy", "wordlists")
	}
	return filepath.Join(home, ".katashiro-proxy", "wordlists")
}
