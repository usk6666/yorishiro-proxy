package flow

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// ConflictPolicy determines behavior when an imported stream ID already exists.
type ConflictPolicy string

const (
	// ConflictSkip skips streams whose ID already exists in the store.
	ConflictSkip ConflictPolicy = "skip"
	// ConflictReplace deletes the existing stream and re-imports.
	ConflictReplace ConflictPolicy = "replace"
)

// ImportOptions configures stream import behavior.
type ImportOptions struct {
	// OnConflict determines behavior for duplicate stream IDs.
	OnConflict ConflictPolicy
	// MaxScannerBuffer is the maximum per-line buffer size in bytes for the
	// JSONL scanner. 0 uses the default (4 MB).
	MaxScannerBuffer int
	// ValidateIDs when true requires stream and flow IDs to be valid UUIDs.
	ValidateIDs bool
}

// ImportError describes a single line-level error during import.
type ImportError struct {
	// Line is the 1-based line number in the JSONL input.
	Line int `json:"line"`
	// StreamID is the stream ID from the record, if available.
	StreamID string `json:"stream_id,omitempty"`
	// Reason describes why the import failed.
	Reason string `json:"reason"`
}

// ImportResult summarizes the outcome of an import operation.
type ImportResult struct {
	// Imported is the number of streams successfully imported.
	Imported int `json:"imported"`
	// Skipped is the number of streams skipped due to ID conflicts.
	Skipped int `json:"skipped"`
	// Errors is the number of streams that failed to import.
	Errors int `json:"errors"`
	// ErrorDetails contains per-line error descriptions. Only populated when
	// errors occur. Capped at maxErrorDetails entries to prevent unbounded
	// memory usage.
	ErrorDetails []ImportError `json:"error_details,omitempty"`
}

// maxErrorDetails limits the number of per-line error details stored in
// ImportResult to prevent unbounded memory growth on large files.
const maxErrorDetails = 50

// addError records an import error with an optional stream ID and reason.
func (r *ImportResult) addError(line int, streamID, reason string) {
	r.Errors++
	if len(r.ErrorDetails) < maxErrorDetails {
		r.ErrorDetails = append(r.ErrorDetails, ImportError{
			Line:     line,
			StreamID: streamID,
			Reason:   reason,
		})
	}
}

// isValidUUID checks whether s is a valid UUID (RFC 4122) string.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// ImportStreams reads JSONL-formatted stream data from r and persists it to the store.
// Each line must be a valid ExportRecord JSON object.
func ImportStreams(ctx context.Context, store Store, r io.Reader, opts ImportOptions) (*ImportResult, error) {
	if opts.OnConflict == "" {
		opts.OnConflict = ConflictSkip
	}

	result := &ImportResult{}
	scanner := newImportScanner(r, opts.MaxScannerBuffer)

	lineNum := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		record, streamID, err := parseAndValidateRecord(line, opts)
		if err != nil {
			result.addError(lineNum, streamID, err.Error())
			continue
		}

		st, err := exportToStream(record.Stream)
		if err != nil {
			result.addError(lineNum, streamID, fmt.Sprintf("convert stream: %v", err))
			continue
		}

		if handled := handleConflict(ctx, store, st.ID, opts.OnConflict, result, lineNum, streamID); handled {
			continue
		}

		if err := importStreamWithFlows(ctx, store, st, record.Flows); err != nil {
			result.addError(lineNum, streamID, err.Error())
			continue
		}

		result.Imported++
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read import data: %w", err)
	}

	return result, nil
}

// newImportScanner creates a buffered scanner for JSONL import with the given max buffer size.
func newImportScanner(r io.Reader, maxScannerBuffer int) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	maxBuf := maxScannerBuffer
	if maxBuf <= 0 {
		maxBuf = 4 * 1024 * 1024
	}
	initBuf := 64 * 1024
	if initBuf > maxBuf {
		initBuf = maxBuf
	}
	scanner.Buffer(make([]byte, 0, initBuf), maxBuf)
	return scanner
}

// parseAndValidateRecord unmarshals a JSONL line and validates the record structure and IDs.
// Returns the parsed record, the stream ID (for error reporting), and any validation error.
func parseAndValidateRecord(line []byte, opts ImportOptions) (*ExportRecord, string, error) {
	var record ExportRecord
	if err := json.Unmarshal(line, &record); err != nil {
		return nil, "", fmt.Errorf("invalid JSON: %v", err)
	}

	if record.Stream == nil {
		return nil, "", fmt.Errorf("missing stream field")
	}

	streamID := record.Stream.ID

	if record.Version != ExportFormatVersion {
		return nil, streamID, fmt.Errorf("unsupported version %q (expected %q)", record.Version, ExportFormatVersion)
	}

	if opts.ValidateIDs && !isValidUUID(streamID) {
		return nil, streamID, fmt.Errorf("invalid stream UUID: %q", streamID)
	}

	if opts.ValidateIDs {
		if invalidID := findInvalidFlowUUID(record.Flows); invalidID != "" {
			return nil, streamID, fmt.Errorf("invalid flow UUID: %q", invalidID)
		}
	}

	return &record, streamID, nil
}

// findInvalidFlowUUID returns the first invalid flow UUID, or empty string if all are valid.
func findInvalidFlowUUID(flows []*ExportFlow) string {
	for _, ef := range flows {
		if !isValidUUID(ef.ID) {
			return ef.ID
		}
	}
	return ""
}

// handleConflict checks for an existing stream and applies the conflict policy.
// Returns true if the record was handled (skipped or error), false if import should proceed.
func handleConflict(ctx context.Context, store Store, streamID string, policy ConflictPolicy, result *ImportResult, lineNum int, recordStreamID string) bool {
	existing, err := store.GetStream(ctx, streamID)
	if err != nil || existing == nil {
		return false
	}

	switch policy {
	case ConflictReplace:
		if err := store.DeleteStream(ctx, streamID); err != nil {
			result.addError(lineNum, recordStreamID,
				fmt.Sprintf("delete existing stream for replace: %v", err))
			return true
		}
		return false
	default:
		result.Skipped++
		return true
	}
}

// importStreamWithFlows saves a stream and its flows to the store.
// On flow import failure, the stream is cleaned up.
func importStreamWithFlows(ctx context.Context, store Store, st *Stream, flows []*ExportFlow) error {
	if err := store.SaveStream(ctx, st); err != nil {
		return fmt.Errorf("save stream: %v", err)
	}

	for _, ef := range flows {
		f, err := exportToFlow(ef)
		if err != nil {
			cleanupStream(ctx, store, st.ID)
			return fmt.Errorf("convert flow %q: %w", ef.ID, err)
		}
		if err := store.SaveFlow(ctx, f); err != nil {
			cleanupStream(ctx, store, st.ID)
			return fmt.Errorf("save flow %q: %w", ef.ID, err)
		}
	}
	return nil
}

// cleanupStream removes a stream from the store, logging any error.
func cleanupStream(ctx context.Context, store Store, streamID string) {
	if delErr := store.DeleteStream(ctx, streamID); delErr != nil {
		slog.Warn("failed to clean up stream after import error", "stream_id", streamID, "error", delErr)
	}
}

// exportToStream converts an ExportStream back to a Stream.
func exportToStream(es *ExportStream) (*Stream, error) {
	ts, err := time.Parse(time.RFC3339Nano, es.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse stream timestamp: %w", err)
	}

	st := &Stream{
		ID:        es.ID,
		ConnID:    es.ConnID,
		Protocol:  es.Protocol,
		State:     es.State,
		Timestamp: ts,
		Duration:  time.Duration(es.DurationMs) * time.Millisecond,
		Tags:      es.Tags,
		BlockedBy: es.BlockedBy,
	}

	if es.ConnInfo != nil {
		st.ConnInfo = &ConnectionInfo{
			ClientAddr:           es.ConnInfo.ClientAddr,
			ServerAddr:           es.ConnInfo.ServerAddr,
			TLSVersion:           es.ConnInfo.TLSVersion,
			TLSCipher:            es.ConnInfo.TLSCipher,
			TLSALPN:              es.ConnInfo.TLSALPN,
			TLSServerCertSubject: es.ConnInfo.TLSServerCertSubject,
		}
	}

	return st, nil
}

// exportToFlow converts an ExportFlow back to a Flow.
func exportToFlow(ef *ExportFlow) (*Flow, error) {
	ts, err := time.Parse(time.RFC3339Nano, ef.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse flow timestamp: %w", err)
	}

	f := &Flow{
		ID:            ef.ID,
		StreamID:      ef.StreamID,
		Sequence:      ef.Sequence,
		Direction:     ef.Direction,
		Timestamp:     ts,
		Headers:       ef.Headers,
		BodyTruncated: ef.BodyTruncated,
		Method:        ef.Method,
		StatusCode:    ef.StatusCode,
		Metadata:      ef.Metadata,
	}

	if ef.URL != "" {
		parsed, err := url.Parse(ef.URL)
		if err != nil {
			return nil, fmt.Errorf("parse flow URL: %w", err)
		}
		f.URL = parsed
	}

	if ef.Body != "" {
		body, err := base64.StdEncoding.DecodeString(ef.Body)
		if err != nil {
			return nil, fmt.Errorf("decode flow body: %w", err)
		}
		f.Body = body
	}

	if ef.RawBytes != "" {
		raw, err := base64.StdEncoding.DecodeString(ef.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("decode flow raw_bytes: %w", err)
		}
		f.RawBytes = raw
	}

	return f, nil
}
