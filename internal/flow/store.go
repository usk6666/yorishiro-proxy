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
	DeleteStreamsByProtocol(ctx context.Context, protocol string) (int64, error)

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
	// Protocol filters streams by protocol (e.g. "HTTP/1.x").
	Protocol string
	// Scheme filters streams by URL scheme / transport indicator
	// (e.g. "https", "http", "wss", "ws", "tcp").
	Scheme string
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
	// Technology filters streams whose tags contain a technology detection
	// matching this name (case-insensitive substring match on the
	// JSON-encoded "technologies" tag value).
	Technology string
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
