package session

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

// ExportFilter specifies criteria for filtering sessions during export.
type ExportFilter struct {
	// Protocol filters by protocol name (e.g. "HTTPS", "HTTP/1.x").
	Protocol string
	// URLPattern filters by URL substring match.
	URLPattern string
	// TimeAfter includes only sessions with timestamps at or after this time.
	TimeAfter *time.Time
	// TimeBefore includes only sessions with timestamps at or before this time.
	TimeBefore *time.Time
}

// ExportOptions configures session export behavior.
type ExportOptions struct {
	// Filter specifies session filter criteria.
	Filter ExportFilter
	// IncludeBodies controls whether message body and raw_bytes are included.
	// If false, only metadata fields are exported.
	IncludeBodies bool
}

// ExportRecord represents a single JSONL line in the export format.
type ExportRecord struct {
	Session  *ExportSession  `json:"session"`
	Messages []*ExportMessage `json:"messages"`
	Version  string           `json:"version"`
}

// ExportSession is the JSON-serializable representation of a Session.
type ExportSession struct {
	ID          string            `json:"id"`
	ConnID      string            `json:"conn_id"`
	Protocol    string            `json:"protocol"`
	SessionType string            `json:"session_type"`
	State       string            `json:"state"`
	Timestamp   string            `json:"timestamp"`
	DurationMs  int64             `json:"duration_ms"`
	Tags        map[string]string `json:"tags,omitempty"`
	ConnInfo    *ExportConnInfo   `json:"conn_info,omitempty"`
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

// ExportMessage is the JSON-serializable representation of a Message.
type ExportMessage struct {
	ID            string              `json:"id"`
	SessionID     string              `json:"session_id"`
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

// ExportSessions exports sessions matching the filter to a JSONL writer.
// Each line is a complete JSON object containing a session and its messages.
// Returns the number of sessions exported.
func ExportSessions(ctx context.Context, store Store, w io.Writer, opts ExportOptions) (int, error) {
	// Build list options from filter, fetching all matching sessions (no limit).
	listOpts := ListOptions{
		Protocol:   opts.Filter.Protocol,
		URLPattern: opts.Filter.URLPattern,
	}

	sessions, err := store.ListSessions(ctx, listOpts)
	if err != nil {
		return 0, fmt.Errorf("list sessions for export: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	exported := 0

	for _, sess := range sessions {
		if err := ctx.Err(); err != nil {
			return exported, err
		}

		// Apply time-based filters (not supported by ListOptions).
		if opts.Filter.TimeAfter != nil && sess.Timestamp.Before(*opts.Filter.TimeAfter) {
			continue
		}
		if opts.Filter.TimeBefore != nil && sess.Timestamp.After(*opts.Filter.TimeBefore) {
			continue
		}

		messages, err := store.GetMessages(ctx, sess.ID, MessageListOptions{})
		if err != nil {
			return exported, fmt.Errorf("get messages for session %s: %w", sess.ID, err)
		}

		record := ExportRecord{
			Session:  sessionToExport(sess),
			Messages: messagesToExport(messages, opts.IncludeBodies),
			Version:  ExportFormatVersion,
		}

		if err := enc.Encode(record); err != nil {
			return exported, fmt.Errorf("encode export record: %w", err)
		}
		exported++
	}

	return exported, nil
}

// sessionToExport converts a Session to its export representation.
func sessionToExport(s *Session) *ExportSession {
	es := &ExportSession{
		ID:          s.ID,
		ConnID:      s.ConnID,
		Protocol:    s.Protocol,
		SessionType: s.SessionType,
		State:       s.State,
		Timestamp:   s.Timestamp.UTC().Format(time.RFC3339Nano),
		DurationMs:  s.Duration.Milliseconds(),
		Tags:        s.Tags,
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

// messagesToExport converts Messages to their export representations.
func messagesToExport(msgs []*Message, includeBodies bool) []*ExportMessage {
	result := make([]*ExportMessage, len(msgs))
	for i, m := range msgs {
		em := &ExportMessage{
			ID:            m.ID,
			SessionID:     m.SessionID,
			Sequence:      m.Sequence,
			Direction:     m.Direction,
			Timestamp:     m.Timestamp.UTC().Format(time.RFC3339Nano),
			Headers:       m.Headers,
			BodyTruncated: m.BodyTruncated,
			Method:        m.Method,
			StatusCode:    m.StatusCode,
			Metadata:      m.Metadata,
		}
		if m.URL != nil {
			em.URL = m.URL.String()
		}
		if includeBodies {
			if len(m.Body) > 0 {
				em.Body = base64.StdEncoding.EncodeToString(m.Body)
			}
			if len(m.RawBytes) > 0 {
				em.RawBytes = base64.StdEncoding.EncodeToString(m.RawBytes)
			}
		}
		result[i] = em
	}
	return result
}
