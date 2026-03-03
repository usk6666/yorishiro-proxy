package session

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

// ConflictPolicy determines behavior when an imported session ID already exists.
type ConflictPolicy string

const (
	// ConflictSkip skips sessions whose ID already exists in the store.
	ConflictSkip ConflictPolicy = "skip"
	// ConflictReplace deletes the existing session and re-imports.
	ConflictReplace ConflictPolicy = "replace"
)

// ImportOptions configures session import behavior.
type ImportOptions struct {
	// OnConflict determines behavior for duplicate session IDs.
	OnConflict ConflictPolicy
	// MaxScannerBuffer is the maximum per-line buffer size in bytes for the
	// JSONL scanner. 0 uses the default (4 MB).
	MaxScannerBuffer int
	// ValidateIDs when true requires session and message IDs to be valid UUIDs.
	ValidateIDs bool
}

// ImportError describes a single line-level error during import.
type ImportError struct {
	// Line is the 1-based line number in the JSONL input.
	Line int `json:"line"`
	// SessionID is the session ID from the record, if available.
	SessionID string `json:"session_id,omitempty"`
	// Reason describes why the import failed.
	Reason string `json:"reason"`
}

// ImportResult summarizes the outcome of an import operation.
type ImportResult struct {
	// Imported is the number of sessions successfully imported.
	Imported int `json:"imported"`
	// Skipped is the number of sessions skipped due to ID conflicts.
	Skipped int `json:"skipped"`
	// Errors is the number of sessions that failed to import.
	Errors int `json:"errors"`
	// ErrorDetails contains per-line error descriptions. Only populated when
	// errors occur. Capped at maxErrorDetails entries to prevent unbounded
	// memory usage.
	ErrorDetails []ImportError `json:"error_details,omitempty"`
}

// maxErrorDetails limits the number of per-line error details stored in
// ImportResult to prevent unbounded memory growth on large files.
const maxErrorDetails = 50

// addError records an import error with an optional session ID and reason.
func (r *ImportResult) addError(line int, sessionID, reason string) {
	r.Errors++
	if len(r.ErrorDetails) < maxErrorDetails {
		r.ErrorDetails = append(r.ErrorDetails, ImportError{
			Line:      line,
			SessionID: sessionID,
			Reason:    reason,
		})
	}
}

// isValidUUID checks whether s is a valid UUID (RFC 4122) string.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// ImportSessions reads JSONL-formatted session data from r and persists it to the store.
// Each line must be a valid ExportRecord JSON object.
func ImportSessions(ctx context.Context, store Store, r io.Reader, opts ImportOptions) (*ImportResult, error) {
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

		if record.Session == nil {
			result.addError(lineNum, "", "missing session field")
			continue
		}

		sessionID := record.Session.ID

		if record.Version != ExportFormatVersion {
			result.addError(lineNum, sessionID,
				fmt.Sprintf("unsupported version %q (expected %q)", record.Version, ExportFormatVersion))
			continue
		}

		// S-5: validate session ID is a valid UUID.
		if opts.ValidateIDs && !isValidUUID(sessionID) {
			result.addError(lineNum, sessionID,
				fmt.Sprintf("invalid session UUID: %q", sessionID))
			continue
		}

		sess, err := exportToSession(record.Session)
		if err != nil {
			result.addError(lineNum, sessionID, fmt.Sprintf("convert session: %v", err))
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
				result.addError(lineNum, sessionID,
					fmt.Sprintf("invalid message UUID: %q", invalidMsgID))
				continue
			}
		}

		// Check for existing session.
		existing, err := store.GetSession(ctx, sess.ID)
		if err == nil && existing != nil {
			switch opts.OnConflict {
			case ConflictSkip:
				result.Skipped++
				continue
			case ConflictReplace:
				if err := store.DeleteSession(ctx, sess.ID); err != nil {
					result.addError(lineNum, sessionID,
						fmt.Sprintf("delete existing session for replace: %v", err))
					continue
				}
			default:
				result.Skipped++
				continue
			}
		}

		if err := store.SaveSession(ctx, sess); err != nil {
			result.addError(lineNum, sessionID, fmt.Sprintf("save session: %v", err))
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
			// Clean up the session we just saved on message import failure.
			if delErr := store.DeleteSession(ctx, sess.ID); delErr != nil {
				slog.Warn("failed to clean up session after import error", "session_id", sess.ID, "error", delErr)
			}
			result.addError(lineNum, sessionID, msgErr.Error())
			continue
		}

		result.Imported++
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read import data: %w", err)
	}

	return result, nil
}

// exportToSession converts an ExportSession back to a Session.
func exportToSession(es *ExportSession) (*Session, error) {
	ts, err := time.Parse(time.RFC3339Nano, es.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse session timestamp: %w", err)
	}

	sess := &Session{
		ID:          es.ID,
		ConnID:      es.ConnID,
		Protocol:    es.Protocol,
		SessionType: es.SessionType,
		State:       es.State,
		Timestamp:   ts,
		Duration:    time.Duration(es.DurationMs) * time.Millisecond,
		Tags:        es.Tags,
		BlockedBy:   es.BlockedBy,
	}

	if es.ConnInfo != nil {
		sess.ConnInfo = &ConnectionInfo{
			ClientAddr:           es.ConnInfo.ClientAddr,
			ServerAddr:           es.ConnInfo.ServerAddr,
			TLSVersion:           es.ConnInfo.TLSVersion,
			TLSCipher:            es.ConnInfo.TLSCipher,
			TLSALPN:              es.ConnInfo.TLSALPN,
			TLSServerCertSubject: es.ConnInfo.TLSServerCertSubject,
		}
	}

	return sess, nil
}

// exportToMessage converts an ExportMessage back to a Message.
func exportToMessage(em *ExportMessage) (*Message, error) {
	ts, err := time.Parse(time.RFC3339Nano, em.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse message timestamp: %w", err)
	}

	msg := &Message{
		ID:            em.ID,
		SessionID:     em.SessionID,
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
