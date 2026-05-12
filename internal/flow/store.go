package flow

import (
	"context"
	"time"
)

// MacroRecord represents a stored macro definition.
type MacroRecord struct {
	// Name is the unique macro identifier (primary key).
	Name string
	// Description is a human-readable description of the macro.
	Description string
	// ConfigJSON is the JSON-encoded macro configuration (steps, initial_vars, timeout_ms, etc.).
	ConfigJSON string
	// CreatedAt is the time the macro was first saved.
	CreatedAt time.Time
	// UpdatedAt is the time the macro was last saved.
	UpdatedAt time.Time
}

// StreamReader provides read-only access to streams.
type StreamReader interface {
	// GetStream retrieves a stream by ID.
	GetStream(ctx context.Context, id string) (*Stream, error)

	// ListStreams returns streams matching the given filter options.
	ListStreams(ctx context.Context, opts StreamListOptions) ([]*Stream, error)

	// CountStreams returns the total number of streams matching the given
	// filter options. Unlike ListStreams, it ignores Limit and Offset.
	CountStreams(ctx context.Context, opts StreamListOptions) (int, error)
}

// FlowReader provides read-only access to flows.
type FlowReader interface {
	// GetFlow retrieves a flow by ID.
	GetFlow(ctx context.Context, id string) (*Flow, error)

	// GetFlows retrieves flows for a stream, optionally filtered.
	GetFlows(ctx context.Context, streamID string, opts FlowListOptions) ([]*Flow, error)

	// CountFlows returns the number of flows for a stream.
	CountFlows(ctx context.Context, streamID string) (int, error)
}

// StreamWriter provides write access for creating and updating streams.
type StreamWriter interface {
	// SaveStream persists a new stream.
	SaveStream(ctx context.Context, s *Stream) error

	// UpdateStream applies partial updates to an existing stream.
	UpdateStream(ctx context.Context, id string, update StreamUpdate) error
}

// FlowWriter provides write access for creating flows.
type FlowWriter interface {
	// SaveFlow persists a new flow associated with a stream.
	SaveFlow(ctx context.Context, f *Flow) error
}

// Reader combines StreamReader and FlowReader for callers that need to
// read both streams and their associated flows.
type Reader interface {
	StreamReader
	FlowReader
}

// Writer combines StreamWriter and FlowWriter for callers that need to
// write both streams and their associated flows.
type Writer interface {
	StreamWriter
	FlowWriter
}

// StreamDeleteFilter selects which streams a bulk-delete operation
// targets. All non-zero fields combine with AND, mirroring the manage
// MCP tool's filter semantics (see USK-792). At least one field must be
// set; an empty filter is rejected by callers to avoid mass deletion
// disguised as a filtered call.
type StreamDeleteFilter struct {
	// Protocol matches Stream.Protocol exactly. Canonical lowercased
	// values: "http", "ws", "grpc", "grpc-web", "sse", "raw",
	// "tls-handshake".
	Protocol string
	// Scheme matches Stream.Scheme exactly. Canonical lowercased values:
	// "http", "https", "ws", "wss", "tcp".
	Scheme string
	// HTTPVersion matches an associated Flow's http_version column via
	// an EXISTS subquery. Canonical lowercased values: "http/1.0",
	// "http/1.1", "h2", "h2c". Nil means the predicate is omitted; the
	// non-nil empty string means "match streams whose flows have an
	// empty http_version" (pre-USK-788 rows). Empty string is the
	// source-of-truth marker for unknown / pre-migration data per
	// schemaV13's `DEFAULT ''`.
	HTTPVersion *string
	// URLPattern matches streams whose send-direction flow URL contains
	// this substring. Implemented as `EXISTS (SELECT 1 FROM flows m
	// WHERE m.stream_id = streams.id AND m.direction = 'send' AND
	// m.url LIKE ? ESCAPE '\\')`, mirroring the StreamListOptions
	// URL-pattern predicate used by export and the query tool. Empty
	// string means the predicate is omitted (USK-822).
	URLPattern string
	// TimeAfter matches streams with timestamps at or after this
	// instant (`streams.timestamp >= ?`). Nil disables the predicate.
	// The wire-comparable lex form is RFC3339Nano, identical to
	// DeleteStreamsOlderThan's bound semantics (USK-822).
	TimeAfter *time.Time
	// TimeBefore matches streams with timestamps at or before this
	// instant (`streams.timestamp <= ?`). Nil disables the predicate
	// (USK-822).
	TimeBefore *time.Time
}

// IsZero reports whether the filter selects no streams (every field is
// at its zero value). Callers reject zero filters to prevent accidental
// mass deletion via an empty filter object.
func (f StreamDeleteFilter) IsZero() bool {
	return f.Protocol == "" &&
		f.Scheme == "" &&
		f.HTTPVersion == nil &&
		f.URLPattern == "" &&
		f.TimeAfter == nil &&
		f.TimeBefore == nil
}

// StreamDeleter provides deletion operations for streams.
type StreamDeleter interface {
	// DeleteStream removes a stream and its associated flows by ID.
	DeleteStream(ctx context.Context, id string) error

	// DeleteAllStreams removes all streams and flows, returning the
	// number of deleted streams.
	DeleteAllStreams(ctx context.Context) (int64, error)

	// DeleteStreamsByProtocol removes streams matching the given protocol,
	// returning the number of deleted streams.
	// Associated flows are cascade-deleted.
	//
	// Deprecated: prefer DeleteStreamsByFilter for new callers; this
	// shim is preserved so existing callers and mocks compile unchanged
	// during the USK-792 transition. It is implemented as a thin
	// wrapper over DeleteStreamsByFilter on the SQLite store.
	DeleteStreamsByProtocol(ctx context.Context, protocol string) (int64, error)

	// DeleteStreamsByFilter removes streams matching the supplied
	// StreamDeleteFilter, returning the number of deleted streams. All
	// non-zero filter fields combine with AND. Associated flows are
	// cascade-deleted via the foreign key on the flows table.
	// Implementations must reject a zero-valued filter.
	DeleteStreamsByFilter(ctx context.Context, filter StreamDeleteFilter) (int64, error)

	// DeleteStreamsOlderThan removes streams with timestamps before the
	// given cutoff, returning the number of deleted streams.
	// Associated flows are cascade-deleted.
	DeleteStreamsOlderThan(ctx context.Context, before time.Time) (int64, error)

	// DeleteExcessStreams removes the oldest streams exceeding maxCount,
	// keeping only the most recent maxCount streams.
	DeleteExcessStreams(ctx context.Context, maxCount int) (int64, error)
}

// MacroStore provides CRUD operations for macro definitions.
type MacroStore interface {
	// SaveMacro persists a macro definition (upsert by name).
	SaveMacro(ctx context.Context, name, description, configJSON string) error

	// GetMacro retrieves a macro definition by name.
	GetMacro(ctx context.Context, name string) (*MacroRecord, error)

	// ListMacros returns all stored macro definitions ordered by name.
	ListMacros(ctx context.Context) ([]*MacroRecord, error)

	// DeleteMacro removes a macro definition by name.
	DeleteMacro(ctx context.Context, name string) error
}

// Store defines the composite interface for stream, flow, and macro persistence.
// It combines all sub-interfaces for backward compatibility. Callers that only
// need a subset of operations should accept the narrower interface instead.
type Store interface {
	StreamReader
	FlowReader
	StreamWriter
	FlowWriter
	StreamDeleter
	MacroStore
}

// StreamListOptions configures stream listing behavior.
type StreamListOptions struct {
	// Protocol filters streams by an exact protocol literal (e.g. "HTTP/1.x").
	// Mutually exclusive with Protocols; if both are set, Protocols wins.
	Protocol string
	// Protocols filters streams by a set of acceptable protocol literals,
	// matched as `s.protocol IN (...)`. Used by the MCP query tool to expand
	// canonical Message-type families (e.g. "http") into the legacy and new
	// recorded protocol strings that share the family during the RFC-001
	// parallel-coexistence window. The Store performs no normalization on
	// the values; callers pass the literal strings to match.
	Protocols []string
	// Scheme filters streams by URL scheme / transport indicator
	// (e.g. "https", "http", "wss", "ws", "tcp").
	Scheme string
	// HTTPVersion filters streams whose flows have at least one row
	// matching this http_version value (USK-792). Canonical lowercased
	// values: "http/1.0", "http/1.1", "h2", "h2c". Nil means the
	// predicate is omitted; non-nil empty string ("") matches streams
	// whose flows have an empty http_version (pre-USK-788 rows). The
	// match runs as `EXISTS (SELECT 1 FROM flows m WHERE m.stream_id =
	// s.id AND m.http_version = ?)` — i.e. a single matching flow makes
	// the whole stream selected, mirroring how Method/StatusCode work.
	HTTPVersion *string
	// Method filters streams that have a send flow with this HTTP method.
	Method string
	// URLPattern filters streams that have a send flow with a URL
	// containing this substring.
	URLPattern string
	// StatusCode filters streams that have a receive flow with this
	// HTTP response status code.
	StatusCode int
	// BlockedBy filters streams by their blocked_by value.
	// When set, only streams with a matching blocked_by value are returned.
	BlockedBy string
	// State filters streams by their lifecycle state
	// ("active", "complete", or "error").
	State string
	// Origin filters streams by their Origin classification (USK-786):
	// OriginProxy ("proxy"), OriginResend ("resend"), or OriginFuzz ("fuzz").
	// Empty string disables the filter and returns rows for all origins.
	// The filter is applied as an exact match on the streams.origin column;
	// the schemaV12 column default ('proxy') ensures pre-existing rows match
	// the OriginProxy filter without explicit backfill.
	Origin Origin
	// ConnID filters streams by connection ID (exact match).
	ConnID string
	// Host filters streams by host. Matches against the server_addr column
	// or the host portion of the URL in send flows.
	Host string
	// SortBy specifies the field to sort results by.
	// Valid values: "timestamp", "duration_ms".
	// Default (empty): "timestamp".
	SortBy string
	// Limit is the maximum number of streams to return.
	Limit int
	// Offset is the number of streams to skip for pagination.
	Offset int
}

// FlowListOptions configures flow listing behavior.
type FlowListOptions struct {
	// Direction filters flows by direction ("send" or "receive").
	Direction string
}
