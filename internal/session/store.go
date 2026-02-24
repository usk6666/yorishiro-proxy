package session

import "context"

// Store defines the interface for session entry persistence.
type Store interface {
	// Save persists a session entry.
	Save(ctx context.Context, entry *Entry) error

	// Get retrieves a session entry by ID.
	Get(ctx context.Context, id string) (*Entry, error)

	// List returns all session entries, optionally filtered.
	List(ctx context.Context, opts ListOptions) ([]*Entry, error)

	// Delete removes a session entry by ID.
	Delete(ctx context.Context, id string) error

	// DeleteAll removes all session entries and returns the number of deleted rows.
	DeleteAll(ctx context.Context) (int64, error)

	// Count returns the total number of session entries matching the given filter options.
	// Unlike List, it ignores Limit and Offset and returns the full matching count.
	Count(ctx context.Context, opts ListOptions) (int, error)
}

// ListOptions configures entry listing behavior.
type ListOptions struct {
	Protocol   string
	Method     string
	URLPattern string
	StatusCode int
	Limit      int
	Offset     int
}
