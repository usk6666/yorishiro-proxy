package flow

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// ConflictPolicy determines behavior when an imported stream ID already exists.
type ConflictPolicy string

const (
	// ConflictSkip skips streams whose ID already exists in the store.
	ConflictSkip ConflictPolicy = "skip"
	// ConflictReplace deletes the existing stream and re-imports.
	ConflictReplace ConflictPolicy = "replace"
	// ConflictMerge upserts the stream from each line's snapshot (the
	// latest line wins) and inserts the line's flows whose IDs are not
	// stored yet. Re-importing the same lines is a no-op, which makes it
	// the policy for ingesting flow sink files.
	ConflictMerge ConflictPolicy = "merge"
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
	// Merged is the number of lines merged into an already stored stream
	// (ConflictMerge only).
	Merged int `json:"merged,omitempty"`
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
	// Imported rows are copies of records that exist elsewhere; the flow
	// sink does not re-emit them.
	ctx = withSinkSuppressed(ctx)

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

		if isSinkGapLine(line) {
			// Flow sink gap lines carry no stream: nothing to import.
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

		if opts.OnConflict == ConflictMerge {
			merged, err := mergeStreamWithFlows(ctx, store, st, record.Flows)
			if err != nil {
				result.addError(lineNum, streamID, err.Error())
				continue
			}
			if merged {
				result.Merged++
			} else {
				result.Imported++
			}
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

// isSinkGapLine reports whether line is a flow sink "gap" record.
func isSinkGapLine(line []byte) bool {
	var probe struct {
		Event string `json:"event"`
	}
	return json.Unmarshal(line, &probe) == nil && probe.Event == string(SinkEventGap)
}

// mergeStreamWithFlows applies one line under ConflictMerge: the stream
// is inserted, or - when it already exists - updated from the line's
// snapshot (the latest line wins for every field UpdateStream can set);
// then each flow whose ID is not stored yet is inserted. merged reports
// whether the stream already existed. Applying the same line twice is a
// no-op.
func mergeStreamWithFlows(ctx context.Context, store Store, st *Stream, flows []*ExportFlow) (merged bool, err error) {
	converted := make([]*Flow, 0, len(flows))
	for _, ef := range flows {
		if ef.StreamID != st.ID {
			return false, fmt.Errorf("flow %q belongs to stream %q, not the line's stream %q", ef.ID, ef.StreamID, st.ID)
		}
		f, err := exportToFlow(ef)
		if err != nil {
			return false, fmt.Errorf("convert flow %q: %w", ef.ID, err)
		}
		converted = append(converted, f)
	}

	if existing, gerr := store.GetStream(ctx, st.ID); gerr == nil && existing != nil {
		merged = true
		if err := store.UpdateStream(ctx, st.ID, streamSnapshotUpdate(st)); err != nil {
			return true, fmt.Errorf("update stream from snapshot: %v", err)
		}
	} else if err := store.SaveStream(ctx, st); err != nil {
		return false, fmt.Errorf("save stream: %v", err)
	}

	for _, f := range converted {
		if _, err := store.GetFlow(ctx, f.ID); err == nil {
			continue
		}
		if err := store.SaveFlow(ctx, f); err != nil {
			return merged, fmt.Errorf("save flow %q: %w", f.ID, err)
		}
	}
	return merged, nil
}

// streamSnapshotUpdate is the StreamUpdate that brings a stored stream to
// snapshot st. Identity fields set at creation (conn_id, timestamp,
// origin, listener_name, client_addr) are not updatable and keep their
// stored values; Tags replaces the stored tags.
func streamSnapshotUpdate(st *Stream) StreamUpdate {
	u := StreamUpdate{
		Protocol:      st.Protocol,
		Scheme:        st.Scheme,
		State:         st.State,
		FailureReason: st.FailureReason,
		BlockedBy:     st.BlockedBy,
		Duration:      st.Duration,
		Tags:          st.Tags,
		SendMs:        st.SendMs,
		WaitMs:        st.WaitMs,
		ReceiveMs:     st.ReceiveMs,
	}
	if ci := st.ConnInfo; ci != nil {
		u.ServerAddr = ci.ServerAddr
		u.UpstreamProxy = ci.UpstreamProxy
		u.TLSVersion = ci.TLSVersion
		u.TLSCipher = ci.TLSCipher
		u.TLSALPN = ci.TLSALPN
		u.TLSServerCertSubject = ci.TLSServerCertSubject
		u.TLSClientJA3 = ci.TLSClientJA3
		u.TLSClientJA4 = ci.TLSClientJA4
	}
	return u
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
//
// USK-785: Origin is inherited from the source as-is, including unknown
// enum values (forward-compat with future origin variants written by
// newer producers). Missing/empty origin falls back to OriginProxy so
// pre-USK-785 JSONL exports — and the no-origin HAR import path — land
// on the canonical default. The fallback intentionally does NOT validate
// against the current enum: imports that already encode an origin keep
// it verbatim, which mirrors how this importer treats other open-set
// fields like Protocol or State.
func exportToStream(es *ExportStream) (*Stream, error) {
	ts, err := time.Parse(time.RFC3339Nano, es.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse stream timestamp: %w", err)
	}

	origin := Origin(es.Origin)
	if origin == "" {
		origin = OriginProxy
	}

	st := &Stream{
		ID:            es.ID,
		ConnID:        es.ConnID,
		Protocol:      es.Protocol,
		Scheme:        es.Scheme,
		State:         es.State,
		FailureReason: es.FailureReason,
		Timestamp:     ts,
		Duration:      time.Duration(es.DurationMs) * time.Millisecond,
		Tags:          es.Tags,
		BlockedBy:     es.BlockedBy,
		Origin:        origin,
		ListenerName:  es.ListenerName,
		SendMs:        es.SendMs,
		WaitMs:        es.WaitMs,
		ReceiveMs:     es.ReceiveMs,
	}

	if es.ConnInfo != nil {
		st.ConnInfo = &ConnectionInfo{
			ClientAddr:           es.ConnInfo.ClientAddr,
			ServerAddr:           es.ConnInfo.ServerAddr,
			UpstreamProxy:        es.ConnInfo.UpstreamProxy,
			TLSVersion:           es.ConnInfo.TLSVersion,
			TLSCipher:            es.ConnInfo.TLSCipher,
			TLSALPN:              es.ConnInfo.TLSALPN,
			TLSServerCertSubject: es.ConnInfo.TLSServerCertSubject,
			TLSClientJA3:         es.ConnInfo.TLSClientJA3,
			TLSClientJA4:         es.ConnInfo.TLSClientJA4,
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
		Trailers:      ef.Trailers,
		BodyTruncated: ef.BodyTruncated,
		Method:        ef.Method,
		StatusCode:    ef.StatusCode,
		HTTPVersion:   ef.HTTPVersion,
		WireLevel:     ef.WireLevel,
		Metadata:      ef.Metadata,
	}

	if ef.URL != "" {
		// USK-1139: the exported url carries the wire path verbatim;
		// ParseWireURL accepts every shape the exporter writes.
		f.URL = envelope.ParseWireURL(ef.URL)
	}

	if ef.BodyOmitted {
		// A flow sink line that left an oversize body out: the imported
		// row has no body, which BodyTruncated records.
		f.BodyTruncated = true
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
