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
	scanner := bufio.NewScanner(r)
	// S-6: use caller-supplied buffer limit, default to 4 MB if not set.
	maxBuf := opts.MaxScannerBuffer
	if maxBuf <= 0 {
		maxBuf = 4 * 1024 * 1024
	}
	// Initial buffer size must not exceed maxBuf.
	initBuf := 64 * 1024
	if initBuf > maxBuf {
		initBuf = maxBuf
	}
	scanner.Buffer(make([]byte, 0, initBuf), maxBuf)

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

		var record ExportRecord
		if err := json.Unmarshal(line, &record); err != nil {
			result.addError(lineNum, "", fmt.Sprintf("invalid JSON: %v", err))
			continue
		}

		if record.Flow == nil {
			result.addError(lineNum, "", "missing flow field")
			continue
		}

		flowID := record.Flow.ID

		if record.Version != ExportFormatVersion {
			result.addError(lineNum, flowID,
				fmt.Sprintf("unsupported version %q (expected %q)", record.Version, ExportFormatVersion))
			continue
		}

		// S-5: validate flow ID is a valid UUID.
		if opts.ValidateIDs && !isValidUUID(flowID) {
			result.addError(lineNum, flowID,
				fmt.Sprintf("invalid flow UUID: %q", flowID))
			continue
		}

		fl, err := exportToFlow(record.Flow)
		if err != nil {
			result.addError(lineNum, flowID, fmt.Sprintf("convert flow: %v", err))
			continue
		}

		// S-5: validate message IDs are valid UUIDs.
		if opts.ValidateIDs {
			invalidMsg := false
			var invalidMsgID string
			for _, em := range record.Messages {
				if !isValidUUID(em.ID) {
					invalidMsg = true
					invalidMsgID = em.ID
					break
				}
			}
			if invalidMsg {
				result.addError(lineNum, flowID,
					fmt.Sprintf("invalid message UUID: %q", invalidMsgID))
				continue
			}
		}

		// Check for existing flow.
		existing, err := store.GetFlow(ctx, fl.ID)
		if err == nil && existing != nil {
			switch opts.OnConflict {
			case ConflictSkip:
				result.Skipped++
				continue
			case ConflictReplace:
				if err := store.DeleteFlow(ctx, fl.ID); err != nil {
					result.addError(lineNum, flowID,
						fmt.Sprintf("delete existing flow for replace: %v", err))
					continue
				}
			default:
				result.Skipped++
				continue
			}
		}

		if err := store.SaveFlow(ctx, fl); err != nil {
			result.addError(lineNum, flowID, fmt.Sprintf("save flow: %v", err))
			continue
		}

		var msgErr error
		for _, em := range record.Messages {
			msg, err := exportToMessage(em)
			if err != nil {
				msgErr = fmt.Errorf("convert message %q: %w", em.ID, err)
				break
			}
			if err := store.AppendMessage(ctx, msg); err != nil {
				msgErr = fmt.Errorf("save message %q: %w", em.ID, err)
				break
			}
		}

		if msgErr != nil {
			// Clean up the flow we just saved on message import failure.
			if delErr := store.DeleteFlow(ctx, fl.ID); delErr != nil {
				slog.Warn("failed to clean up flow after import error", "flow_id", fl.ID, "error", delErr)
			}
			result.addError(lineNum, flowID, msgErr.Error())
			continue
		}

		result.Imported++
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read import data: %w", err)
	}

	return result, nil
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
