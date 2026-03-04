package session

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

// SessionReader provides read-only access to sessions and messages.
type SessionReader interface {
	// GetSession retrieves a session by ID.
	GetSession(ctx context.Context, id string) (*Session, error)

	// ListSessions returns sessions matching the given filter options.
	ListSessions(ctx context.Context, opts ListOptions) ([]*Session, error)

	// CountSessions returns the total number of sessions matching the given
	// filter options. Unlike ListSessions, it ignores Limit and Offset.
	CountSessions(ctx context.Context, opts ListOptions) (int, error)

	// GetMessages retrieves messages for a session, optionally filtered.
	GetMessages(ctx context.Context, sessionID string, opts MessageListOptions) ([]*Message, error)

	// CountMessages returns the number of messages for a session.
	CountMessages(ctx context.Context, sessionID string) (int, error)
}

// SessionWriter provides write access for creating and updating sessions and messages.
type SessionWriter interface {
	// SaveSession persists a new session.
	SaveSession(ctx context.Context, s *Session) error

	// UpdateSession applies partial updates to an existing session.
	UpdateSession(ctx context.Context, id string, update SessionUpdate) error

	// AppendMessage persists a new message associated with a session.
	AppendMessage(ctx context.Context, msg *Message) error
}

// SessionDeleter provides deletion operations for sessions.
type SessionDeleter interface {
	// DeleteSession removes a session and its associated messages by ID.
	DeleteSession(ctx context.Context, id string) error

	// DeleteAllSessions removes all sessions and messages, returning the
	// number of deleted sessions.
	DeleteAllSessions(ctx context.Context) (int64, error)

	// DeleteSessionsByProtocol removes sessions matching the given protocol,
	// returning the number of deleted sessions.
	// Associated messages are cascade-deleted.
	DeleteSessionsByProtocol(ctx context.Context, protocol string) (int64, error)

	// DeleteSessionsOlderThan removes sessions with timestamps before the
	// given cutoff, returning the number of deleted sessions.
	// Associated messages are cascade-deleted.
	DeleteSessionsOlderThan(ctx context.Context, before time.Time) (int64, error)

	// DeleteExcessSessions removes the oldest sessions exceeding maxCount,
	// keeping only the most recent maxCount sessions.
	DeleteExcessSessions(ctx context.Context, maxCount int) (int64, error)
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

// Store defines the composite interface for session, message, and macro persistence.
// It combines all sub-interfaces for backward compatibility. Callers that only
// need a subset of operations should accept the narrower interface instead.
type Store interface {
	SessionReader
	SessionWriter
	SessionDeleter
	MacroStore
}

// ListOptions configures session listing behavior.
type ListOptions struct {
	// Protocol filters sessions by protocol (e.g. "HTTP/1.x").
	Protocol string
	// Method filters sessions that have a send message with this HTTP method.
	Method string
	// URLPattern filters sessions that have a send message with a URL
	// containing this substring.
	URLPattern string
	// StatusCode filters sessions that have a receive message with this
	// HTTP response status code.
	StatusCode int
	// BlockedBy filters sessions by their blocked_by value.
	// When set, only sessions with a matching blocked_by value are returned.
	BlockedBy string
	// State filters sessions by their lifecycle state
	// ("active", "complete", or "error").
	State string
	// Limit is the maximum number of sessions to return.
	Limit int
	// Offset is the number of sessions to skip for pagination.
	Offset int
}

// MessageListOptions configures message listing behavior.
type MessageListOptions struct {
	// Direction filters messages by direction ("send" or "receive").
	Direction string
}
