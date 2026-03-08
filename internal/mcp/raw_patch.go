package mcp

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// RawPatch represents a single byte-level modification operation on raw bytes.
// Exactly one patch mode must be specified:
//   - offset + data_base64: overwrite bytes at a specific offset
//   - find_base64 + replace_base64: binary search and replace
//   - find_text + replace_text: text search and replace
type RawPatch struct {
	// Offset is the byte position to start overwriting (used with DataBase64).
	Offset *int `json:"offset,omitempty" jsonschema:"byte offset for overwrite patch"`
	// DataBase64 is the Base64-encoded replacement data for offset-based patching.
	DataBase64 string `json:"data_base64,omitempty" jsonschema:"Base64-encoded data to write at offset"`
	// FindBase64 is the Base64-encoded byte sequence to search for (binary search/replace).
	FindBase64 string `json:"find_base64,omitempty" jsonschema:"Base64-encoded bytes to find"`
	// ReplaceBase64 is the Base64-encoded byte sequence to replace with (binary search/replace).
	ReplaceBase64 string `json:"replace_base64,omitempty" jsonschema:"Base64-encoded bytes to replace with"`
	// FindText is the text string to search for (text search/replace).
	FindText string `json:"find_text,omitempty" jsonschema:"text to find"`
	// ReplaceText is the text string to replace with (text search/replace).
	ReplaceText string `json:"replace_text,omitempty" jsonschema:"text to replace with"`
}

// validateRawPatch checks that a RawPatch has exactly one patch mode specified.
func validateRawPatch(rp RawPatch) error {
	hasOffset := rp.Offset != nil || rp.DataBase64 != ""
	hasBinaryFind := rp.FindBase64 != "" || rp.ReplaceBase64 != ""
	hasTextFind := rp.FindText != "" || rp.ReplaceText != ""

	if err := validatePatchModeCount(hasOffset, hasBinaryFind, hasTextFind); err != nil {
		return err
	}

	switch {
	case hasOffset:
		return validateOffsetPatchFields(rp)
	case hasBinaryFind:
		return validateBinaryFindPatchFields(rp)
	case hasTextFind:
		return validateTextFindPatchFields(rp)
	}
	return nil
}

// validatePatchModeCount ensures exactly one patch mode is specified.
func validatePatchModeCount(hasOffset, hasBinaryFind, hasTextFind bool) error {
	modes := 0
	if hasOffset {
		modes++
	}
	if hasBinaryFind {
		modes++
	}
	if hasTextFind {
		modes++
	}

	if modes == 0 {
		return fmt.Errorf("patch must specify one of: offset+data_base64, find_base64+replace_base64, or find_text+replace_text")
	}
	if modes > 1 {
		return fmt.Errorf("patch must specify exactly one mode: offset+data_base64, find_base64+replace_base64, or find_text+replace_text")
	}
	return nil
}

// validateOffsetPatchFields validates fields for offset-based patch mode.
func validateOffsetPatchFields(rp RawPatch) error {
	if rp.Offset == nil {
		return fmt.Errorf("offset is required when data_base64 is specified")
	}
	if rp.DataBase64 == "" {
		return fmt.Errorf("data_base64 is required when offset is specified")
	}
	if *rp.Offset < 0 {
		return fmt.Errorf("offset must be >= 0, got %d", *rp.Offset)
	}
	return nil
}

// validateBinaryFindPatchFields validates fields for binary find/replace patch mode.
func validateBinaryFindPatchFields(rp RawPatch) error {
	if rp.FindBase64 == "" {
		return fmt.Errorf("find_base64 is required for binary search/replace")
	}
	// replace_base64 can be empty (replace with nothing = delete).
	return nil
}

// validateTextFindPatchFields validates fields for text find/replace patch mode.
func validateTextFindPatchFields(rp RawPatch) error {
	if rp.FindText == "" {
		return fmt.Errorf("find_text is required for text search/replace")
	}
	// replace_text can be empty (replace with nothing = delete).
	return nil
}

// applyRawPatches applies a sequence of RawPatch operations to the given raw bytes.
// Patches are applied in order. Returns the modified bytes.
func applyRawPatches(data []byte, patches []RawPatch) ([]byte, error) {
	// Work on a copy to avoid mutating the original slice.
	result := make([]byte, len(data))
	copy(result, data)

	for i, p := range patches {
		if err := validateRawPatch(p); err != nil {
			return nil, fmt.Errorf("patches[%d]: %w", i, err)
		}

		var err error
		switch {
		case p.Offset != nil:
			result, err = applyOffsetPatch(result, *p.Offset, p.DataBase64)
		case p.FindBase64 != "":
			result, err = applyBinaryFindReplace(result, p.FindBase64, p.ReplaceBase64)
		case p.FindText != "":
			result = applyTextFindReplace(result, p.FindText, p.ReplaceText)
		}
		if err != nil {
			return nil, fmt.Errorf("patches[%d]: %w", i, err)
		}
	}

	return result, nil
}

// applyOffsetPatch overwrites bytes starting at the given offset with Base64-decoded data.
func applyOffsetPatch(data []byte, offset int, dataBase64 string) ([]byte, error) {
	replacement, err := base64.StdEncoding.DecodeString(dataBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid data_base64: %w", err)
	}
	if len(replacement) == 0 {
		return nil, fmt.Errorf("data_base64 decodes to empty bytes")
	}

	endOffset := offset + len(replacement)
	if offset > len(data) {
		return nil, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
	}

	// If the replacement extends beyond the current data, grow the slice.
	if endOffset > len(data) {
		extended := make([]byte, endOffset)
		copy(extended, data)
		data = extended
	}

	copy(data[offset:], replacement)
	return data, nil
}

// applyBinaryFindReplace searches for a Base64-decoded byte pattern and replaces all
// occurrences with the replacement bytes.
func applyBinaryFindReplace(data []byte, findBase64, replaceBase64 string) ([]byte, error) {
	find, err := base64.StdEncoding.DecodeString(findBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid find_base64: %w", err)
	}
	if len(find) == 0 {
		return nil, fmt.Errorf("find_base64 decodes to empty bytes")
	}

	var replace []byte
	if replaceBase64 != "" {
		replace, err = base64.StdEncoding.DecodeString(replaceBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid replace_base64: %w", err)
		}
	}

	return bytes.ReplaceAll(data, find, replace), nil
}

// applyTextFindReplace searches for a text pattern and replaces all occurrences.
func applyTextFindReplace(data []byte, findText, replaceText string) []byte {
	return bytes.ReplaceAll(data, []byte(findText), []byte(replaceText))
}
