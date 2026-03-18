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

// ConflictPolicy determines behavior when an imported flow ID already exists.
type ConflictPolicy string

const (
	// ConflictSkip skips flows whose ID already exists in the store.
	ConflictSkip ConflictPolicy = "skip"
	// ConflictReplace deletes the existing flow and re-imports.
	ConflictReplace ConflictPolicy = "replace"
)

// ImportOptions configures flow import behavior.
type ImportOptions struct {
	// OnConflict determines behavior for duplicate flow IDs.
	OnConflict ConflictPolicy
	// MaxScannerBuffer is the maximum per-line buffer size in bytes for the
	// JSONL scanner. 0 uses the default (4 MB).
	MaxScannerBuffer int
	// ValidateIDs when true requires flow and message IDs to be valid UUIDs.
	ValidateIDs bool
}

// ImportError describes a single line-level error during import.
type ImportError struct {
	// Line is the 1-based line number in the JSONL input.
	Line int `json:"line"`
	// FlowID is the flow ID from the record, if available.
	FlowID string `json:"flow_id,omitempty"`
	// Reason describes why the import failed.
	Reason string `json:"reason"`
}

// ImportResult summarizes the outcome of an import operation.
type ImportResult struct {
	// Imported is the number of flows successfully imported.
	Imported int `json:"imported"`
	// Skipped is the number of flows skipped due to ID conflicts.
	Skipped int `json:"skipped"`
	// Errors is the number of flows that failed to import.
	Errors int `json:"errors"`
	// ErrorDetails contains per-line error descriptions. Only populated when
	// errors occur. Capped at maxErrorDetails entries to prevent unbounded
	// memory usage.
	ErrorDetails []ImportError `json:"error_details,omitempty"`
}

// maxErrorDetails limits the number of per-line error details stored in
// ImportResult to prevent unbounded memory growth on large files.
const maxErrorDetails = 50

// addError records an import error with an optional flow ID and reason.
func (r *ImportResult) addError(line int, flowID, reason string) {
	r.Errors++
	if len(r.ErrorDetails) < maxErrorDetails {
		r.ErrorDetails = append(r.ErrorDetails, ImportError{
			Line:   line,
			FlowID: flowID,
			Reason: reason,
		})
	}
}

// isValidUUID checks whether s is a valid UUID (RFC 4122) string.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// ImportFlows reads JSONL-formatted flow data from r and persists it to the store.
// Each line must be a valid ExportRecord JSON object.
func ImportFlows(ctx context.Context, store Store, r io.Reader, opts ImportOptions) (*ImportResult, error) {
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

		record, flowID, err := parseAndValidateRecord(line, opts)
		if err != nil {
			result.addError(lineNum, flowID, err.Error())
			continue
		}

		fl, err := exportToFlow(record.Flow)
		if err != nil {
			result.addError(lineNum, flowID, fmt.Sprintf("convert flow: %v", err))
			continue
		}

		if handled := handleConflict(ctx, store, fl.ID, opts.OnConflict, result, lineNum, flowID); handled {
			continue
		}

		if err := importFlowWithMessages(ctx, store, fl, record.Messages); err != nil {
			result.addError(lineNum, flowID, err.Error())
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
// Returns the parsed record, the flow ID (for error reporting), and any validation error.
func parseAndValidateRecord(line []byte, opts ImportOptions) (*ExportRecord, string, error) {
	var record ExportRecord
	if err := json.Unmarshal(line, &record); err != nil {
		return nil, "", fmt.Errorf("invalid JSON: %v", err)
	}

	if record.Flow == nil {
		return nil, "", fmt.Errorf("missing flow field")
	}

	flowID := record.Flow.ID

	if record.Version != ExportFormatVersion {
		return nil, flowID, fmt.Errorf("unsupported version %q (expected %q)", record.Version, ExportFormatVersion)
	}

	if opts.ValidateIDs && !isValidUUID(flowID) {
		return nil, flowID, fmt.Errorf("invalid flow UUID: %q", flowID)
	}

	if opts.ValidateIDs {
		if invalidID := findInvalidMessageUUID(record.Messages); invalidID != "" {
			return nil, flowID, fmt.Errorf("invalid message UUID: %q", invalidID)
		}
	}

	return &record, flowID, nil
}

// findInvalidMessageUUID returns the first invalid message UUID, or empty string if all are valid.
func findInvalidMessageUUID(messages []*ExportMessage) string {
	for _, em := range messages {
		if !isValidUUID(em.ID) {
			return em.ID
		}
	}
	return ""
}

// handleConflict checks for an existing flow and applies the conflict policy.
// Returns true if the record was handled (skipped or error), false if import should proceed.
func handleConflict(ctx context.Context, store Store, flowID string, policy ConflictPolicy, result *ImportResult, lineNum int, recordFlowID string) bool {
	existing, err := store.GetFlow(ctx, flowID)
	if err != nil || existing == nil {
		return false
	}

	switch policy {
	case ConflictReplace:
		if err := store.DeleteFlow(ctx, flowID); err != nil {
			result.addError(lineNum, recordFlowID,
				fmt.Sprintf("delete existing flow for replace: %v", err))
			return true
		}
		return false
	default:
		result.Skipped++
		return true
	}
}

// importFlowWithMessages saves a flow and its messages to the store.
// On message import failure, the flow is cleaned up.
func importFlowWithMessages(ctx context.Context, store Store, fl *Flow, messages []*ExportMessage) error {
	if err := store.SaveFlow(ctx, fl); err != nil {
		return fmt.Errorf("save flow: %v", err)
	}

	for _, em := range messages {
		msg, err := exportToMessage(em)
		if err != nil {
			cleanupFlow(ctx, store, fl.ID)
			return fmt.Errorf("convert message %q: %w", em.ID, err)
		}
		if err := store.AppendMessage(ctx, msg); err != nil {
			cleanupFlow(ctx, store, fl.ID)
			return fmt.Errorf("save message %q: %w", em.ID, err)
		}
	}
	return nil
}

// cleanupFlow removes a flow from the store, logging any error.
func cleanupFlow(ctx context.Context, store Store, flowID string) {
	if delErr := store.DeleteFlow(ctx, flowID); delErr != nil {
		slog.Warn("failed to clean up flow after import error", "flow_id", flowID, "error", delErr)
	}
}

// exportToFlow converts an ExportFlow back to a Flow.
func exportToFlow(es *ExportFlow) (*Flow, error) {
	ts, err := time.Parse(time.RFC3339Nano, es.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse flow timestamp: %w", err)
	}

	fl := &Flow{
		ID:        es.ID,
		ConnID:    es.ConnID,
		Protocol:  es.Protocol,
		FlowType:  es.FlowType,
		State:     es.State,
		Timestamp: ts,
		Duration:  time.Duration(es.DurationMs) * time.Millisecond,
		Tags:      es.Tags,
		BlockedBy: es.BlockedBy,
	}

	if es.ConnInfo != nil {
		fl.ConnInfo = &ConnectionInfo{
			ClientAddr:           es.ConnInfo.ClientAddr,
			ServerAddr:           es.ConnInfo.ServerAddr,
			TLSVersion:           es.ConnInfo.TLSVersion,
			TLSCipher:            es.ConnInfo.TLSCipher,
			TLSALPN:              es.ConnInfo.TLSALPN,
			TLSServerCertSubject: es.ConnInfo.TLSServerCertSubject,
		}
	}

	return fl, nil
}

// exportToMessage converts an ExportMessage back to a Message.
func exportToMessage(em *ExportMessage) (*Message, error) {
	ts, err := time.Parse(time.RFC3339Nano, em.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse message timestamp: %w", err)
	}

	msg := &Message{
		ID:            em.ID,
		FlowID:        em.FlowID,
		Sequence:      em.Sequence,
		Direction:     em.Direction,
		Timestamp:     ts,
		Headers:       em.Headers,
		BodyTruncated: em.BodyTruncated,
		Method:        em.Method,
		StatusCode:    em.StatusCode,
		Metadata:      em.Metadata,
	}

	if em.URL != "" {
		parsed, err := url.Parse(em.URL)
		if err != nil {
			return nil, fmt.Errorf("parse message URL: %w", err)
		}
		msg.URL = parsed
	}

	if em.Body != "" {
		body, err := base64.StdEncoding.DecodeString(em.Body)
		if err != nil {
			return nil, fmt.Errorf("decode message body: %w", err)
		}
		msg.Body = body
	}

	if em.RawBytes != "" {
		raw, err := base64.StdEncoding.DecodeString(em.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("decode message raw_bytes: %w", err)
		}
		msg.RawBytes = raw
	}

	return msg, nil
}
