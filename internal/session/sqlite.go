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

	// Run schema migrations.
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
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

	tags := "{}"
	if entry.Tags != nil {
		tagsJSON, err := json.Marshal(entry.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		tags = string(tagsJSON)
	}

	urlStr := ""
	if entry.Request.URL != nil {
		urlStr = entry.Request.URL.String()
	}

	// Extract connection info fields, defaulting to empty strings.
	var clientAddr, serverAddr, tlsVersion, tlsCipher, tlsALPN, tlsCertSubject string
	if entry.ConnInfo != nil {
		clientAddr = entry.ConnInfo.ClientAddr
		serverAddr = entry.ConnInfo.ServerAddr
		tlsVersion = entry.ConnInfo.TLSVersion
		tlsCipher = entry.ConnInfo.TLSCipher
		tlsALPN = entry.ConnInfo.TLSALPN
		tlsCertSubject = entry.ConnInfo.TLSServerCertSubject
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, conn_id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms, request_body_truncated, response_body_truncated, tags, raw_request, raw_response, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.ConnID,
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
		boolToInt(entry.Request.BodyTruncated),
		boolToInt(entry.Response.BodyTruncated),
		tags,
		entry.RawRequest,
		entry.RawResponse,
		clientAddr,
		serverAddr,
		tlsVersion,
		tlsCipher,
		tlsALPN,
		tlsCertSubject,
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

// sessionColumns is the list of columns selected in Get and List queries.
const sessionColumns = `id, conn_id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms, request_body_truncated, response_body_truncated, tags, raw_request, raw_response, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject`

// Get retrieves a session entry by ID.
func (s *SQLiteStore) Get(ctx context.Context, id string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id)
	return scanEntry(row)
}

// buildWhereClause constructs a SQL WHERE clause and argument list from the
// filter fields in ListOptions (Protocol, Method, URLPattern, StatusCode).
// It returns the clause string (including "WHERE" prefix if non-empty) and
// the corresponding positional arguments.
func buildWhereClause(opts ListOptions) (string, []interface{}) {
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

	clause := ""
	if len(conditions) > 0 {
		clause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return clause, args
}

// List returns session entries matching the given options.
func (s *SQLiteStore) List(ctx context.Context, opts ListOptions) ([]*Entry, error) {
	whereClause, args := buildWhereClause(opts)

	query := "SELECT " + sessionColumns + " FROM sessions" + whereClause
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
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// Count returns the total number of session entries matching the given filter
// options. Unlike List, it ignores Limit and Offset fields.
func (s *SQLiteStore) Count(ctx context.Context, opts ListOptions) (int, error) {
	whereClause, args := buildWhereClause(opts)

	query := "SELECT COUNT(*) FROM sessions" + whereClause

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return count, nil
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

// DeleteOlderThan removes sessions with timestamps before the given cutoff.
// It returns the number of deleted rows.
func (s *SQLiteStore) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE timestamp < ?",
		before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete sessions older than %s: %w", before.Format(time.RFC3339), err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteExcess removes the oldest sessions exceeding maxCount,
// keeping only the most recent maxCount sessions.
func (s *SQLiteStore) DeleteExcess(ctx context.Context, maxCount int) (int64, error) {
	if maxCount <= 0 {
		return 0, fmt.Errorf("maxCount must be > 0, got %d", maxCount)
	}
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE id NOT IN (SELECT id FROM sessions ORDER BY timestamp DESC LIMIT ?)",
		maxCount)
	if err != nil {
		return 0, fmt.Errorf("delete excess sessions: %w", err)
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
		entry          Entry
		urlStr         string
		reqHeaders     string
		respHeaders    string
		tsStr          string
		durationMs     int64
		reqTruncated   int
		respTruncated  int
		tagsStr        string
		clientAddr     string
		serverAddr     string
		tlsVersion     string
		tlsCipher      string
		tlsALPN        string
		tlsCertSubject string
	)

	err := row.Scan(
		&entry.ID,
		&entry.ConnID,
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
		&reqTruncated,
		&respTruncated,
		&tagsStr,
		&entry.RawRequest,
		&entry.RawResponse,
		&clientAddr,
		&serverAddr,
		&tlsVersion,
		&tlsCipher,
		&tlsALPN,
		&tlsCertSubject,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}

	if urlStr != "" {
		parsed, err := url.Parse(urlStr)
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
	if tagsStr != "" && tagsStr != "{}" {
		if err := json.Unmarshal([]byte(tagsStr), &entry.Tags); err != nil {
			entry.Tags = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse session timestamp (possible bug)", "value", tsStr, "error", err)
	}
	entry.Timestamp = ts
	entry.Duration = time.Duration(durationMs) * time.Millisecond

	entry.Request.BodyTruncated = reqTruncated != 0
	entry.Response.BodyTruncated = respTruncated != 0

	// Populate ConnectionInfo if any connection metadata is present.
	if clientAddr != "" || serverAddr != "" || tlsVersion != "" || tlsCipher != "" || tlsALPN != "" || tlsCertSubject != "" {
		entry.ConnInfo = &ConnectionInfo{
			ClientAddr:           clientAddr,
			ServerAddr:           serverAddr,
			TLSVersion:           tlsVersion,
			TLSCipher:            tlsCipher,
			TLSALPN:              tlsALPN,
			TLSServerCertSubject: tlsCertSubject,
		}
	}

	return &entry, nil
}

// boolToInt converts a boolean to an integer (0 or 1) for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
