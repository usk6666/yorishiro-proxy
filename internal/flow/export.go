package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ExportFormatVersion is the current JSONL export format version.
const ExportFormatVersion = "1"

// ExportFilter specifies criteria for filtering streams during export.
type ExportFilter struct {
	// Protocol filters by protocol name (e.g. "HTTPS", "HTTP/1.x").
	Protocol string
	// URLPattern filters by URL substring match.
	URLPattern string
	// TimeAfter includes only streams with timestamps at or after this time.
	TimeAfter *time.Time
	// TimeBefore includes only streams with timestamps at or before this time.
	TimeBefore *time.Time
}

// ExportOptions configures stream export behavior.
type ExportOptions struct {
	// Filter specifies stream filter criteria.
	Filter ExportFilter
	// IncludeBodies controls whether flow body and raw_bytes are included.
	// If false, only metadata fields are exported.
	IncludeBodies bool
	// MaxFlows limits the number of streams exported.
	// 0 means no limit.
	MaxFlows int
}

// ExportRecord represents a single JSONL line in the export format.
type ExportRecord struct {
	Stream  *ExportStream `json:"stream"`
	Flows   []*ExportFlow `json:"flows"`
	Version string        `json:"version"`
}

// ExportStream is the JSON-serializable representation of a Stream.
type ExportStream struct {
	ID         string            `json:"id"`
	ConnID     string            `json:"conn_id"`
	Protocol   string            `json:"protocol"`
	State      string            `json:"state"`
	Timestamp  string            `json:"timestamp"`
	DurationMs int64             `json:"duration_ms"`
	Tags       map[string]string `json:"tags,omitempty"`
	ConnInfo   *ExportConnInfo   `json:"conn_info,omitempty"`
	BlockedBy  string            `json:"blocked_by,omitempty"`
	SendMs     *int64            `json:"send_ms,omitempty"`
	WaitMs     *int64            `json:"wait_ms,omitempty"`
	ReceiveMs  *int64            `json:"receive_ms,omitempty"`
}

// ExportConnInfo is the JSON-serializable representation of ConnectionInfo.
type ExportConnInfo struct {
	ClientAddr           string `json:"client_addr,omitempty"`
	ServerAddr           string `json:"server_addr,omitempty"`
	TLSVersion           string `json:"tls_version,omitempty"`
	TLSCipher            string `json:"tls_cipher,omitempty"`
	TLSALPN              string `json:"tls_alpn,omitempty"`
	TLSServerCertSubject string `json:"tls_server_cert_subject,omitempty"`
}

// ExportFlow is the JSON-serializable representation of a Flow.
type ExportFlow struct {
	ID            string              `json:"id"`
	StreamID      string              `json:"stream_id"`
	Sequence      int                 `json:"sequence"`
	Direction     string              `json:"direction"`
	Timestamp     string              `json:"timestamp"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Body          string              `json:"body,omitempty"`
	RawBytes      string              `json:"raw_bytes,omitempty"`
	BodyTruncated bool                `json:"body_truncated"`
	Method        string              `json:"method,omitempty"`
	URL           string              `json:"url,omitempty"`
	StatusCode    int                 `json:"status_code,omitempty"`
	Metadata      map[string]string   `json:"metadata,omitempty"`
}

// ExportStreams exports streams matching the filter to a JSONL writer.
// Each line is a complete JSON object containing a stream and its flows.
// Returns the number of streams exported.
func ExportStreams(ctx context.Context, store Store, w io.Writer, opts ExportOptions) (int, error) {
	// Build list options from filter, fetching all matching streams (no limit).
	listOpts := StreamListOptions{
		Protocol:   opts.Filter.Protocol,
		URLPattern: opts.Filter.URLPattern,
	}

	streams, err := store.ListStreams(ctx, listOpts)
	if err != nil {
		return 0, fmt.Errorf("list streams for export: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	exported := 0

	for _, st := range streams {
		if err := ctx.Err(); err != nil {
			return exported, err
		}

		// S-4: enforce stream count limit when set.
		if opts.MaxFlows > 0 && exported >= opts.MaxFlows {
			break
		}

		// Apply time-based filters (not supported by StreamListOptions).
		if opts.Filter.TimeAfter != nil && st.Timestamp.Before(*opts.Filter.TimeAfter) {
			continue
		}
		if opts.Filter.TimeBefore != nil && st.Timestamp.After(*opts.Filter.TimeBefore) {
			continue
		}

		flows, err := store.GetFlows(ctx, st.ID, FlowListOptions{})
		if err != nil {
			return exported, fmt.Errorf("get flows for stream %s: %w", st.ID, err)
		}

		record := ExportRecord{
			Stream:  streamToExport(st),
			Flows:   flowsToExport(flows, opts.IncludeBodies),
			Version: ExportFormatVersion,
		}

		if err := enc.Encode(record); err != nil {
			return exported, fmt.Errorf("encode export record: %w", err)
		}
		exported++
	}

	return exported, nil
}

// streamToExport converts a Stream to its export representation.
func streamToExport(s *Stream) *ExportStream {
	es := &ExportStream{
		ID:         s.ID,
		ConnID:     s.ConnID,
		Protocol:   s.Protocol,
		State:      s.State,
		Timestamp:  s.Timestamp.UTC().Format(time.RFC3339Nano),
		DurationMs: s.Duration.Milliseconds(),
		Tags:       s.Tags,
		BlockedBy:  s.BlockedBy,
		SendMs:     s.SendMs,
		WaitMs:     s.WaitMs,
		ReceiveMs:  s.ReceiveMs,
	}
	if s.ConnInfo != nil {
		es.ConnInfo = &ExportConnInfo{
			ClientAddr:           s.ConnInfo.ClientAddr,
			ServerAddr:           s.ConnInfo.ServerAddr,
			TLSVersion:           s.ConnInfo.TLSVersion,
			TLSCipher:            s.ConnInfo.TLSCipher,
			TLSALPN:              s.ConnInfo.TLSALPN,
			TLSServerCertSubject: s.ConnInfo.TLSServerCertSubject,
		}
	}
	return es
}

// flowsToExport converts Flows to their export representations.
func flowsToExport(flows []*Flow, includeBodies bool) []*ExportFlow {
	result := make([]*ExportFlow, len(flows))
	for i, f := range flows {
		ef := &ExportFlow{
			ID:            f.ID,
			StreamID:      f.StreamID,
			Sequence:      f.Sequence,
			Direction:     f.Direction,
			Timestamp:     f.Timestamp.UTC().Format(time.RFC3339Nano),
			Headers:       f.Headers,
			BodyTruncated: f.BodyTruncated,
			Method:        f.Method,
			StatusCode:    f.StatusCode,
			Metadata:      f.Metadata,
		}
		if f.URL != nil {
			ef.URL = f.URL.String()
		}
		if includeBodies {
			if len(f.Body) > 0 {
				ef.Body = base64.StdEncoding.EncodeToString(f.Body)
			}
			if len(f.RawBytes) > 0 {
				ef.RawBytes = base64.StdEncoding.EncodeToString(f.RawBytes)
			}
		}
		result[i] = ef
	}
	return result
}
