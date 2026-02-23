package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// drainTimeout is the maximum duration allowed for flushing remaining writes
// during Close(). If the timeout expires, pending writes fail with a deadline error.
const drainTimeout = 5 * time.Second

// SQLiteStore implements Store using SQLite with WAL mode.
type SQLiteStore struct {
	db      *sql.DB
	writeCh chan writeOp
	done    chan struct{}
	wg      sync.WaitGroup
	logger  *slog.Logger
}

type writeOp struct {
	ctx    context.Context
	entry  *Entry
	result chan error
}

// NewSQLiteStore opens (or creates) a SQLite database at path and initializes the schema.
func NewSQLiteStore(ctx context.Context, path string, logger *slog.Logger) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	// Enable WAL mode for concurrent read/write.
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Run schema creation.
	if _, err := db.ExecContext(ctx, createSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	// Initialize schema version if empty.
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		db.Close()
		return nil, fmt.Errorf("check schema version: %w", err)
	}
	if count == 0 {
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", schemaVersion); err != nil {
			db.Close()
			return nil, fmt.Errorf("insert schema version: %w", err)
		}
	}

	s := &SQLiteStore{
		db:      db,
		writeCh: make(chan writeOp, 256),
		done:    make(chan struct{}),
		logger:  logger,
	}
	s.wg.Add(1)
	go s.writeLoop()
	logger.Info("session store initialized", "db_path", path)
	return s, nil
}

func (s *SQLiteStore) writeLoop() {
	defer s.wg.Done()
	for {
		select {
		case op, ok := <-s.writeCh:
			if !ok {
				return
			}
			err := s.saveSync(op.ctx, op.entry)
			if err != nil {
				s.logger.Warn("session write failed", "error", err)
			}
			op.result <- err
		case <-s.done:
			// Drain remaining writes with a timeout.
			drainCtx, drainCancel := context.WithTimeout(context.Background(), drainTimeout)
			defer drainCancel()
			for {
				select {
				case op := <-s.writeCh:
					err := s.saveSync(drainCtx, op.entry)
					if err != nil {
						s.logger.Warn("session write failed during drain", "error", err)
					}
					op.result <- err
				default:
					return
				}
			}
		}
	}
}

func (s *SQLiteStore) saveSync(ctx context.Context, entry *Entry) error {
	reqHeaders, err := json.Marshal(entry.Request.Headers)
	if err != nil {
		return fmt.Errorf("marshal request headers: %w", err)
	}
	respHeaders, err := json.Marshal(entry.Response.Headers)
	if err != nil {
		return fmt.Errorf("marshal response headers: %w", err)
	}

	urlStr := ""
	if entry.Request.URL != nil {
		urlStr = entry.Request.URL.String()
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.Protocol,
		entry.Request.Method,
		urlStr,
		string(reqHeaders),
		entry.Request.Body,
		entry.Response.StatusCode,
		string(respHeaders),
		entry.Response.Body,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Duration.Milliseconds(),
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// Save persists a session entry asynchronously via the writer goroutine.
func (s *SQLiteStore) Save(ctx context.Context, entry *Entry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	result := make(chan error, 1)
	select {
	case s.writeCh <- writeOp{ctx: ctx, entry: entry, result: result}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Get retrieves a session entry by ID.
func (s *SQLiteStore) Get(ctx context.Context, id string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms
		 FROM sessions WHERE id = ?`, id)
	return scanEntry(row)
}

// List returns session entries matching the given options.
func (s *SQLiteStore) List(ctx context.Context, opts ListOptions) ([]*Entry, error) {
	var conditions []string
	var args []interface{}

	if opts.Protocol != "" {
		conditions = append(conditions, "protocol = ?")
		args = append(args, opts.Protocol)
	}
	if opts.Method != "" {
		conditions = append(conditions, "method = ?")
		args = append(args, opts.Method)
	}
	if opts.URLPattern != "" {
		// Escape LIKE wildcards to prevent unintended pattern matching.
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.URLPattern)
		conditions = append(conditions, "url LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escaped+"%")
	}
	if opts.StatusCode != 0 {
		conditions = append(conditions, "response_status = ?")
		args = append(args, opts.StatusCode)
	}

	query := "SELECT id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms FROM sessions"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var entries []*Entry
	for rows.Next() {
		entry, err := scanEntryFromRows(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// Delete removes a session entry by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete session %s: %w", id, err)
	}
	return nil
}

// DeleteAll removes all session entries and returns the number of deleted rows.
func (s *SQLiteStore) DeleteAll(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions")
	if err != nil {
		return 0, fmt.Errorf("delete all sessions: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// Close shuts down the writer goroutine and closes the database.
func (s *SQLiteStore) Close() error {
	close(s.done)
	s.wg.Wait()
	return s.db.Close()
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanEntry(row scannable) (*Entry, error) {
	var (
		entry       Entry
		urlStr      string
		reqHeaders  string
		respHeaders string
		tsStr       string
		durationMs  int64
	)

	err := row.Scan(
		&entry.ID,
		&entry.Protocol,
		&entry.Request.Method,
		&urlStr,
		&reqHeaders,
		&entry.Request.Body,
		&entry.Response.StatusCode,
		&respHeaders,
		&entry.Response.Body,
		&tsStr,
		&durationMs,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}

	if urlStr != "" {
		parsed, err := parseURL(urlStr)
		if err == nil {
			entry.Request.URL = parsed
		}
	}

	if err := json.Unmarshal([]byte(reqHeaders), &entry.Request.Headers); err != nil {
		entry.Request.Headers = make(map[string][]string)
	}
	if err := json.Unmarshal([]byte(respHeaders), &entry.Response.Headers); err != nil {
		entry.Response.Headers = make(map[string][]string)
	}

	entry.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
	entry.Duration = time.Duration(durationMs) * time.Millisecond

	return &entry, nil
}

func scanEntryFromRows(rows *sql.Rows) (*Entry, error) {
	return scanEntry(rows)
}

func parseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
