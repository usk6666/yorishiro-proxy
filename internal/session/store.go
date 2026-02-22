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
}

// ListOptions configures entry listing behavior.
type ListOptions struct {
	Protocol string
	Limit    int
	Offset   int
}
