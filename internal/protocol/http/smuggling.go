package http

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	gohttp "net/http"
	"strings"
)

// smugglingFlags holds the results of HTTP request smuggling checks.
// Each field indicates whether a specific smuggling pattern was detected
// in the raw request headers.
type smugglingFlags struct {
	// CLTEConflict is true when both Content-Length and Transfer-Encoding
	// headers are present in the same request (CL.TE or TE.CL attack vector).
	CLTEConflict bool

	// AmbiguousTE is true when the Transfer-Encoding header contains
	// obfuscated values (e.g., "chunked " with trailing space, "Chunked"
	// with unusual capitalization, or multiple TE directives).
	AmbiguousTE bool

	// Warnings contains human-readable descriptions of detected patterns.
	Warnings []string
}

// hasWarnings returns true if any smuggling pattern was detected.
func (f *smugglingFlags) hasWarnings() bool {
	return len(f.Warnings) > 0
}

// maxPeekSize is the maximum number of bytes to peek for header scanning.
// HTTP headers should not exceed this in normal operation.
const maxPeekSize = 8192

// checkRequestSmuggling inspects the raw request headers in the buffered reader
// for HTTP request smuggling patterns. It uses Peek to examine bytes without
// consuming them, so ReadRequest can still process the request normally.
//
// Detection scope:
//   - CL/TE conflict: Content-Length and Transfer-Encoding both present
//   - Ambiguous Transfer-Encoding: obfuscated TE values that may confuse
//     different HTTP implementations
//
// Go's net/http.ReadRequest already provides these protections:
//   - Rejects requests with multiple different Content-Length values
//   - Prioritizes Transfer-Encoding over Content-Length when both present
//     (removes CL from headers, sets ContentLength to -1)
//   - De-chunks chunked transfer encoding automatically
//
// This function adds detection and logging on top of Go's built-in handling,
// which is important for a security assessment tool to flag suspicious traffic.
func checkRequestSmuggling(reader *bufio.Reader, logger *slog.Logger) *smugglingFlags {
	flags := &smugglingFlags{}

	// Peek at raw header bytes to detect patterns before ReadRequest normalizes them.
	headerBytes := peekHeaders(reader)
	if headerBytes == nil {
		return flags
	}

	// Normalize to lowercase for case-insensitive matching.
	lowerHeaders := bytes.ToLower(headerBytes)

	// Check for CL/TE conflict.
	hasCL := containsHeader(lowerHeaders, "content-length")
	hasTE := containsHeader(lowerHeaders, "transfer-encoding")

	if hasCL && hasTE {
		flags.CLTEConflict = true
		flags.Warnings = append(flags.Warnings,
			"request contains both Content-Length and Transfer-Encoding headers (potential CL/TE smuggling)")
	}

	// Check for ambiguous Transfer-Encoding values.
	if hasTE {
		checkAmbiguousTE(headerBytes, flags)
	}

	return flags
}

// peekHeaders attempts to peek at the raw HTTP request headers from the
// buffered reader. It returns the header portion (up to and excluding the
// blank line terminator) or nil if headers cannot be peeked.
//
// The function first triggers a single read to fill the bufio buffer (by
// peeking 1 byte), then peeks only the buffered amount. This avoids blocking
// when the request is smaller than a fixed peek size, which would cause Peek
// to wait for more data from the underlying connection (especially over TLS
// where reads are record-based).
func peekHeaders(reader *bufio.Reader) []byte {
	// Trigger a buffer fill by peeking 1 byte. This causes the bufio.Reader
	// to call Read on the underlying connection exactly once, filling its
	// internal buffer with whatever data is immediately available.
	if _, err := reader.Peek(1); err != nil {
		return nil
	}

	// Now peek exactly what's been buffered — no additional blocking reads.
	// Cap at maxPeekSize to avoid scanning excessively large buffers.
	buffered := reader.Buffered()
	if buffered == 0 {
		return nil
	}
	if buffered > maxPeekSize {
		buffered = maxPeekSize
	}

	peeked, _ := reader.Peek(buffered)
	if idx := bytes.Index(peeked, []byte("\r\n\r\n")); idx >= 0 {
		return peeked[:idx]
	}

	// Header terminator not found in buffered data. This may happen if the
	// headers span multiple TLS records or TCP segments. Return what we have
	// and scan it for patterns — partial detection is better than none.
	return peeked
}

// containsHeader checks if a lowercased header block contains a specific
// header name (case-insensitive). It looks for the header at the start of a
// line to avoid false positives from header values.
// It also handles the obfuscation case where a space appears before the colon
// (e.g., "Transfer-Encoding : chunked").
func containsHeader(lowerHeaders []byte, headerName string) bool {
	// The request line (e.g., "GET / HTTP/1.1\r\n") comes first, so all
	// actual headers follow \r\n. Check for both standard "name:" and
	// obfuscated "name :" patterns.
	target := []byte("\r\n" + headerName + ":")
	targetSpace := []byte("\r\n" + headerName + " ")
	return bytes.Contains(lowerHeaders, target) || bytes.Contains(lowerHeaders, targetSpace)
}

// checkAmbiguousTE inspects Transfer-Encoding header values for obfuscation
// techniques that may cause different HTTP implementations to interpret the
// request differently.
//
// Common obfuscation techniques (from PortSwigger research):
//   - "Transfer-Encoding : chunked" (space before colon)
//   - "Transfer-Encoding: chunked " (trailing space/tab)
//   - "Transfer-Encoding: xchunked" (unknown value)
//   - "Transfer-Encoding: chunked\r\nTransfer-Encoding: x" (duplicate TE)
//   - "Transfer-Encoding:\tchunked" (tab instead of space)
func checkAmbiguousTE(headerBytes []byte, flags *smugglingFlags) {
	lines := bytes.Split(headerBytes, []byte("\r\n"))

	var teValues []string
	for _, line := range lines {
		lowerLine := bytes.ToLower(line)

		// Find Transfer-Encoding headers anchored to line start to avoid
		// false positives from header values containing "transfer-encoding".
		if !bytes.HasPrefix(lowerLine, []byte("transfer-encoding")) {
			continue
		}

		// Check for space before colon (obfuscation).
		afterName := line[len("transfer-encoding"):]
		if len(afterName) > 0 && afterName[0] != ':' {
			flags.AmbiguousTE = true
			flags.Warnings = append(flags.Warnings,
				fmt.Sprintf("Transfer-Encoding header has unexpected character before colon: %q", string(line)))
		}

		// Extract the value after the colon.
		colonIdx := bytes.IndexByte(afterName, ':')
		if colonIdx < 0 {
			continue
		}
		rawValue := string(afterName[colonIdx+1:])
		value := strings.TrimSpace(rawValue)
		teValues = append(teValues, value)

		// Check for non-standard TE values.
		normalizedValue := strings.ToLower(value)
		if normalizedValue != "chunked" && normalizedValue != "identity" && normalizedValue != "" {
			flags.AmbiguousTE = true
			flags.Warnings = append(flags.Warnings,
				fmt.Sprintf("Transfer-Encoding header has non-standard value: %q", value))
		}

		// Check for trailing whitespace in the raw value (obfuscation).
		// Use the value with only leading whitespace trimmed to detect trailing spaces/tabs.
		leftTrimmed := strings.TrimLeft(rawValue, " \t")
		if leftTrimmed != strings.TrimRight(leftTrimmed, " \t") {
			flags.AmbiguousTE = true
			flags.Warnings = append(flags.Warnings,
				fmt.Sprintf("Transfer-Encoding value has trailing whitespace: %q", rawValue))
		}
	}

	// Multiple Transfer-Encoding headers.
	if len(teValues) > 1 {
		flags.AmbiguousTE = true
		flags.Warnings = append(flags.Warnings,
			fmt.Sprintf("multiple Transfer-Encoding headers detected: %v", teValues))
	}
}

// smugglingTags converts detected smuggling flags into session tags.
// Returns nil if no smuggling patterns were detected, avoiding unnecessary
// allocations for normal requests.
func smugglingTags(flags *smugglingFlags) map[string]string {
	if flags == nil || !flags.hasWarnings() {
		return nil
	}

	tags := make(map[string]string)
	if flags.CLTEConflict {
		tags["smuggling:cl_te_conflict"] = "true"
	}
	if flags.AmbiguousTE {
		tags["smuggling:ambiguous_te"] = "true"
	}
	if len(flags.Warnings) > 0 {
		tags["smuggling:warnings"] = strings.Join(flags.Warnings, "; ")
	}
	return tags
}

// logSmugglingWarnings logs detected smuggling patterns as warnings.
func logSmugglingWarnings(logger *slog.Logger, flags *smugglingFlags, req *gohttp.Request) {
	if !flags.hasWarnings() {
		return
	}

	method := ""
	urlStr := ""
	if req != nil {
		method = req.Method
		if req.URL != nil {
			urlStr = req.URL.String()
		}
	}

	for _, warning := range flags.Warnings {
		logger.Warn("HTTP request smuggling pattern detected",
			"warning", warning,
			"method", method,
			"url", urlStr,
			"cl_te_conflict", flags.CLTEConflict,
			"ambiguous_te", flags.AmbiguousTE,
		)
	}
}
