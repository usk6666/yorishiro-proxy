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

// FlowReader provides read-only access to flows and messages.
type FlowReader interface {
	// GetFlow retrieves a flow by ID.
	GetFlow(ctx context.Context, id string) (*Flow, error)

	// ListFlows returns flows matching the given filter options.
	ListFlows(ctx context.Context, opts ListOptions) ([]*Flow, error)

	// CountFlows returns the total number of flows matching the given
	// filter options. Unlike ListFlows, it ignores Limit and Offset.
	CountFlows(ctx context.Context, opts ListOptions) (int, error)

	// GetMessages retrieves messages for a flow, optionally filtered.
	GetMessages(ctx context.Context, flowID string, opts MessageListOptions) ([]*Message, error)

	// CountMessages returns the number of messages for a flow.
	CountMessages(ctx context.Context, flowID string) (int, error)
}

// FlowWriter provides write access for creating and updating flows and messages.
type FlowWriter interface {
	// SaveFlow persists a new flow.
	SaveFlow(ctx context.Context, s *Flow) error

	// UpdateFlow applies partial updates to an existing flow.
	UpdateFlow(ctx context.Context, id string, update FlowUpdate) error

	// AppendMessage persists a new message associated with a flow.
	AppendMessage(ctx context.Context, msg *Message) error
}

// FlowDeleter provides deletion operations for flows.
type FlowDeleter interface {
	// DeleteFlow removes a flow and its associated messages by ID.
	DeleteFlow(ctx context.Context, id string) error

	// DeleteAllFlows removes all flows and messages, returning the
	// number of deleted flows.
	DeleteAllFlows(ctx context.Context) (int64, error)

	// DeleteFlowsByProtocol removes flows matching the given protocol,
	// returning the number of deleted flows.
	// Associated messages are cascade-deleted.
	DeleteFlowsByProtocol(ctx context.Context, protocol string) (int64, error)

	// DeleteFlowsOlderThan removes flows with timestamps before the
	// given cutoff, returning the number of deleted flows.
	// Associated messages are cascade-deleted.
	DeleteFlowsOlderThan(ctx context.Context, before time.Time) (int64, error)

	// DeleteExcessFlows removes the oldest flows exceeding maxCount,
	// keeping only the most recent maxCount flows.
	DeleteExcessFlows(ctx context.Context, maxCount int) (int64, error)
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

// Store defines the composite interface for flow, message, and macro persistence.
// It combines all sub-interfaces for backward compatibility. Callers that only
// need a subset of operations should accept the narrower interface instead.
type Store interface {
	FlowReader
	FlowWriter
	FlowDeleter
	MacroStore
}

// ListOptions configures flow listing behavior.
type ListOptions struct {
	// Protocol filters flows by protocol (e.g. "HTTP/1.x").
	Protocol string
	// Method filters flows that have a send message with this HTTP method.
	Method string
	// URLPattern filters flows that have a send message with a URL
	// containing this substring.
	URLPattern string
	// StatusCode filters flows that have a receive message with this
	// HTTP response status code.
	StatusCode int
	// BlockedBy filters flows by their blocked_by value.
	// When set, only flows with a matching blocked_by value are returned.
	BlockedBy string
	// State filters flows by their lifecycle state
	// ("active", "complete", or "error").
	State string
	// Technology filters flows whose tags contain a technology detection
	// matching this name (case-insensitive substring match on the
	// JSON-encoded "technologies" tag value).
	Technology string
	// ConnID filters flows by connection ID (exact match).
	ConnID string
	// Host filters flows by host. Matches against the server_addr column
	// or the host portion of the URL in send messages.
	Host string
	// SortBy specifies the field to sort results by.
	// Valid values: "timestamp", "duration_ms".
	// Default (empty): "timestamp".
	SortBy string
	// Limit is the maximum number of flows to return.
	Limit int
	// Offset is the number of flows to skip for pagination.
	Offset int
}

// MessageListOptions configures message listing behavior.
type MessageListOptions struct {
	// Direction filters messages by direction ("send" or "receive").
	Direction string
}
