package flow

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
	fn     func(ctx context.Context) error
	result chan error
}

// NewSQLiteStore opens (or creates) a SQLite database at path and initializes the schema.
func NewSQLiteStore(ctx context.Context, path string, logger *slog.Logger) (*SQLiteStore, error) {
	// Apply PRAGMAs via DSN so they are set on every connection in the pool,
	// not just the first one. Without this, Go's sql.DB may open new pooled
	// connections that lack foreign_keys=ON, causing ON DELETE CASCADE to
	// silently not fire (see BUG-001).
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
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
	logger.Info("flow store initialized", "db_path", path)
	return s, nil
}

// DB returns the underlying *sql.DB connection.
// This allows other subsystems (e.g. plugin store) to share the same database
// and benefit from WAL mode and connection pool settings.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) writeLoop() {
	defer s.wg.Done()
	for {
		select {
		case op, ok := <-s.writeCh:
			if !ok {
				return
			}
			err := op.fn(op.ctx)
			if err != nil {
				s.logger.Warn("flow write failed", "error", err)
			}
			op.result <- err
		case <-s.done:
			// Drain remaining writes with a timeout.
			drainCtx, drainCancel := context.WithTimeout(context.Background(), drainTimeout)
			defer drainCancel()
			for {
				select {
				case op := <-s.writeCh:
					err := op.fn(drainCtx)
					if err != nil {
						s.logger.Warn("flow write failed during drain", "error", err)
					}
					op.result <- err
				default:
					return
				}
			}
		}
	}
}

// enqueueWrite sends a write operation to the writer goroutine and waits for the result.
func (s *SQLiteStore) enqueueWrite(ctx context.Context, fn func(ctx context.Context) error) error {
	result := make(chan error, 1)
	select {
	case s.writeCh <- writeOp{ctx: ctx, fn: fn, result: result}:
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

// SaveStream persists a new stream.
func (s *SQLiteStore) SaveStream(ctx context.Context, st *Stream) error {
	if st.ID == "" {
		st.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		return s.saveStreamSync(ctx, st)
	})
}

func (s *SQLiteStore) saveStreamSync(ctx context.Context, st *Stream) error {
	tags := "{}"
	if st.Tags != nil {
		tagsJSON, err := json.Marshal(st.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		tags = string(tagsJSON)
	}

	var clientAddr, serverAddr, tlsVersion, tlsCipher, tlsALPN, tlsCertSubject string
	if st.ConnInfo != nil {
		clientAddr = st.ConnInfo.ClientAddr
		serverAddr = st.ConnInfo.ServerAddr
		tlsVersion = st.ConnInfo.TLSVersion
		tlsCipher = st.ConnInfo.TLSCipher
		tlsALPN = st.ConnInfo.TLSALPN
		tlsCertSubject = st.ConnInfo.TLSServerCertSubject
	}

	state := st.State
	if state == "" {
		state = "complete"
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO streams (id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.ID,
		st.ConnID,
		st.Protocol,
		st.Scheme,
		state,
		st.Timestamp.UTC().Format(time.RFC3339Nano),
		st.Duration.Milliseconds(),
		tags,
		clientAddr,
		serverAddr,
		tlsVersion,
		tlsCipher,
		tlsALPN,
		tlsCertSubject,
		st.BlockedBy,
		st.SendMs,
		st.WaitMs,
		st.ReceiveMs,
		st.FailureReason,
	)
	if err != nil {
		return fmt.Errorf("insert stream: %w", err)
	}
	return nil
}

// UpdateStream applies partial updates to an existing stream.
func (s *SQLiteStore) UpdateStream(ctx context.Context, id string, update StreamUpdate) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		sets, args, err := buildStreamUpdateSets(update)
		if err != nil {
			return err
		}
		if len(sets) == 0 {
			return nil
		}

		args = append(args, id)
		query := fmt.Sprintf("UPDATE streams SET %s WHERE id = ?", strings.Join(sets, ", "))
		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("update stream %s: %w", id, err)
		}
		return nil
	})
}

// buildStreamUpdateSets translates a StreamUpdate into SQL SET clauses and
// their bind arguments. Empty / zero values are skipped so partial updates
// do not clobber existing columns (contract relied on by every caller —
// RecordStep's per-Receive TLS projection, Session's OnComplete State
// transition, and USK-620's FailureReason classification).
func buildStreamUpdateSets(update StreamUpdate) ([]string, []interface{}, error) {
	var sets []string
	var args []interface{}
	addString := func(column, value string) {
		if value == "" {
			return
		}
		sets = append(sets, column+" = ?")
		args = append(args, value)
	}
	addInt64 := func(column string, value *int64) {
		if value == nil {
			return
		}
		sets = append(sets, column+" = ?")
		args = append(args, *value)
	}

	addString("state", update.State)
	addString("failure_reason", update.FailureReason)
	if update.Duration != 0 {
		sets = append(sets, "duration_ms = ?")
		args = append(args, update.Duration.Milliseconds())
	}
	if update.Tags != nil {
		tagsJSON, err := json.Marshal(update.Tags)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal tags: %w", err)
		}
		sets = append(sets, "tags = ?")
		args = append(args, string(tagsJSON))
	}
	addString("server_addr", update.ServerAddr)
	addString("tls_version", update.TLSVersion)
	addString("tls_cipher", update.TLSCipher)
	addString("tls_alpn", update.TLSALPN)
	addString("tls_server_cert_subject", update.TLSServerCertSubject)
	addInt64("send_ms", update.SendMs)
	addInt64("wait_ms", update.WaitMs)
	addInt64("receive_ms", update.ReceiveMs)

	return sets, args, nil
}

// GetStream retrieves a stream by ID. It accepts either a full UUID (36 chars)
// or an 8-character prefix. For prefix lookups, the ID must match exactly
// one stream; ambiguous prefixes return an error.
func (s *SQLiteStore) GetStream(ctx context.Context, id string) (*Stream, error) {
	// Try exact match first.
	row := s.db.QueryRowContext(ctx,
		`SELECT `+streamColumns+` FROM streams WHERE id = ?`, id)
	st, err := scanStream(row)
	if err == nil {
		return st, nil
	}

	// If the input is exactly 8 characters and exact match failed,
	// attempt prefix resolution.
	if len(id) == 8 {
		resolved, resolveErr := s.resolveStreamPrefix(ctx, id)
		if resolveErr != nil {
			return nil, resolveErr
		}
		row = s.db.QueryRowContext(ctx,
			`SELECT `+streamColumns+` FROM streams WHERE id = ?`, resolved)
		return scanStream(row)
	}

	return nil, err
}

// resolveStreamPrefix searches for streams matching the given 8-character ID prefix.
// Returns the full ID if exactly one stream matches, or an error otherwise.
func (s *SQLiteStore) resolveStreamPrefix(ctx context.Context, prefix string) (string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM streams WHERE id LIKE ? LIMIT 2`, prefix+"%")
	if err != nil {
		return "", fmt.Errorf("resolve stream ID prefix: %w", err)
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var matchID string
		if err := rows.Scan(&matchID); err != nil {
			return "", fmt.Errorf("scan stream ID: %w", err)
		}
		matches = append(matches, matchID)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("resolve stream ID prefix: %w", err)
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("stream not found")
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous stream ID prefix %q: matched %d streams", prefix, len(matches))
	}
}

// ValidateStreamID checks that the given ID is a valid stream ID format:
// either a full UUID (36 chars) or an 8-character prefix.
// Returns an error for lengths 1-7 and 9-35.
func ValidateStreamID(id string) error {
	n := len(id)
	if n == 36 || n == 8 {
		return nil
	}
	return fmt.Errorf("invalid stream ID: must be full UUID (36 chars) or 8-char prefix")
}

// streamColumns is the list of columns selected in stream queries.
const streamColumns = `id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason`

// buildStreamWhereClause constructs a SQL WHERE clause from StreamListOptions.
// Method, URLPattern, and StatusCode are matched via EXISTS subqueries on flows.
func buildStreamWhereClause(opts StreamListOptions) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if opts.Protocol != "" {
		conditions = append(conditions, "s.protocol = ?")
		args = append(args, opts.Protocol)
	}
	if opts.Scheme != "" {
		conditions = append(conditions, "s.scheme = ?")
		args = append(args, opts.Scheme)
	}
	if opts.Method != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'send' AND m.method = ?)")
		args = append(args, opts.Method)
	}
	if opts.URLPattern != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.URLPattern)
		conditions = append(conditions, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'send' AND m.url LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	if opts.StatusCode != 0 {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'receive' AND m.status_code = ?)")
		args = append(args, opts.StatusCode)
	}
	if opts.BlockedBy != "" {
		conditions = append(conditions, "s.blocked_by = ?")
		args = append(args, opts.BlockedBy)
	}
	if opts.State != "" {
		conditions = append(conditions, "s.state = ?")
		args = append(args, opts.State)
	}
	if opts.Technology != "" {
		// Match technology name inside the JSON-encoded "technologies" tag value.
		// Tags column stores JSON-marshaled map[string]string. The technologies
		// value is a nested JSON array encoded as a string value, so it appears
		// with escaped quotes in the outer JSON: \"name\":\"nginx\".
		// We use SQLite's INSTR on the lowercased column for reliable matching
		// without LIKE escape complexity.
		conditions = append(conditions, "INSTR(LOWER(s.tags), ?) > 0")
		args = append(args, strings.ToLower(opts.Technology))
	}
	if opts.ConnID != "" {
		conditions = append(conditions, "s.conn_id = ?")
		args = append(args, opts.ConnID)
	}
	if opts.Host != "" {
		// Match against server_addr (host:port or host) or the host portion
		// of the URL stored in send flows. server_addr may contain a port,
		// so we check both exact match and host-prefix match (host:*).
		// For URL-based matching, we use multiple LIKE patterns with right-side
		// boundary anchoring to avoid subdomain false positives:
		//   %://host/  — path follows
		//   %://host?  — query string follows (no path)
		//   %://host:  — port number follows
		//   %://host   — end of string (bare host)
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.Host)
		conditions = append(conditions, "(s.server_addr = ? OR s.server_addr LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'send' AND (m.url LIKE ? ESCAPE '\\' OR m.url LIKE ? ESCAPE '\\' OR m.url LIKE ? ESCAPE '\\' OR m.url LIKE ? ESCAPE '\\')))")
		args = append(args, opts.Host, escaped+":%", "%://"+escaped+"/%", "%://"+escaped+"?%", "%://"+escaped+":%", "%://"+escaped)
	}

	clause := ""
	if len(conditions) > 0 {
		clause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return clause, args
}

// validStreamSortColumns maps allowed SortBy values to SQL column expressions.
var validStreamSortColumns = map[string]string{
	"timestamp":   "s.timestamp",
	"duration_ms": "s.duration_ms",
}

// streamOrderClause returns the ORDER BY clause for stream list queries.
// Invalid or empty sortBy values fall back to timestamp descending.
func streamOrderClause(sortBy string) string {
	if col, ok := validStreamSortColumns[sortBy]; ok {
		return " ORDER BY " + col + " DESC"
	}
	return " ORDER BY s.timestamp DESC"
}

// ListStreams returns streams matching the given options.
func (s *SQLiteStore) ListStreams(ctx context.Context, opts StreamListOptions) ([]*Stream, error) {
	whereClause, args := buildStreamWhereClause(opts)

	query := "SELECT " + streamColumns + " FROM streams s" + whereClause
	query += streamOrderClause(opts.SortBy)

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list streams: %w", err)
	}
	defer rows.Close()

	var streams []*Stream
	for rows.Next() {
		st, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		streams = append(streams, st)
	}
	return streams, rows.Err()
}

// CountStreams returns the total number of streams matching the given filter options.
func (s *SQLiteStore) CountStreams(ctx context.Context, opts StreamListOptions) (int, error) {
	whereClause, args := buildStreamWhereClause(opts)

	query := "SELECT COUNT(*) FROM streams s" + whereClause

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count streams: %w", err)
	}
	return count, nil
}

// DeleteStream removes a stream by ID (flows are cascade-deleted).
func (s *SQLiteStore) DeleteStream(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM streams WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete stream %s: %w", id, err)
	}
	return nil
}

// DeleteAllStreams removes all streams and returns the number of deleted rows.
func (s *SQLiteStore) DeleteAllStreams(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM streams")
	if err != nil {
		return 0, fmt.Errorf("delete all streams: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteStreamsByProtocol removes streams matching the given protocol.
func (s *SQLiteStore) DeleteStreamsByProtocol(ctx context.Context, protocol string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM streams WHERE protocol = ?", protocol)
	if err != nil {
		return 0, fmt.Errorf("delete streams by protocol %q: %w", protocol, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteStreamsOlderThan removes streams with timestamps before the given cutoff.
func (s *SQLiteStore) DeleteStreamsOlderThan(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM streams WHERE timestamp < ?",
		before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete streams older than %s: %w", before.Format(time.RFC3339), err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteExcessStreams removes the oldest streams exceeding maxCount.
func (s *SQLiteStore) DeleteExcessStreams(ctx context.Context, maxCount int) (int64, error) {
	if maxCount <= 0 {
		return 0, fmt.Errorf("maxCount must be > 0, got %d", maxCount)
	}
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM streams WHERE id NOT IN (SELECT id FROM streams ORDER BY timestamp DESC LIMIT ?)",
		maxCount)
	if err != nil {
		return 0, fmt.Errorf("delete excess streams: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// SaveFlow persists a new flow associated with a stream.
func (s *SQLiteStore) SaveFlow(ctx context.Context, f *Flow) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		return s.saveFlowSync(ctx, f)
	})
}

func (s *SQLiteStore) saveFlowSync(ctx context.Context, f *Flow) error {
	headers := "{}"
	if f.Headers != nil {
		headersJSON, err := json.Marshal(f.Headers)
		if err != nil {
			return fmt.Errorf("marshal headers: %w", err)
		}
		headers = string(headersJSON)
	}

	metadata := "{}"
	if f.Metadata != nil {
		metaJSON, err := json.Marshal(f.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		metadata = string(metaJSON)
	}

	urlStr := ""
	if f.URL != nil {
		urlStr = f.URL.String()
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO flows (id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID,
		f.StreamID,
		f.Sequence,
		f.Direction,
		f.Timestamp.UTC().Format(time.RFC3339Nano),
		headers,
		f.Body,
		f.RawBytes,
		boolToInt(f.BodyTruncated),
		f.Method,
		urlStr,
		f.StatusCode,
		metadata,
	)
	if err != nil {
		return fmt.Errorf("insert flow: %w", err)
	}
	return nil
}

// flowColumns is the list of columns selected in flow queries.
const flowColumns = `id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata`

// GetFlow retrieves a flow by ID.
func (s *SQLiteStore) GetFlow(ctx context.Context, id string) (*Flow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+flowColumns+` FROM flows WHERE id = ?`, id)
	return scanFlow(row)
}

// GetFlows retrieves flows for a stream, optionally filtered by direction.
func (s *SQLiteStore) GetFlows(ctx context.Context, streamID string, opts FlowListOptions) ([]*Flow, error) {
	query := "SELECT " + flowColumns + " FROM flows WHERE stream_id = ?"
	args := []interface{}{streamID}

	if opts.Direction != "" {
		query += " AND direction = ?"
		args = append(args, opts.Direction)
	}

	query += " ORDER BY sequence ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get flows: %w", err)
	}
	defer rows.Close()

	var flows []*Flow
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, f)
	}
	return flows, rows.Err()
}

// CountFlows returns the number of flows for a stream.
func (s *SQLiteStore) CountFlows(ctx context.Context, streamID string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM flows WHERE stream_id = ?", streamID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count flows: %w", err)
	}
	return count, nil
}

// SaveMacro persists a macro definition using upsert semantics.
// If a macro with the same name exists, it is updated; otherwise a new one is created.
func (s *SQLiteStore) SaveMacro(ctx context.Context, name, description, configJSON string) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO macros (name, description, config, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET description = excluded.description, config = excluded.config, updated_at = excluded.updated_at`,
			name, description, configJSON, now, now,
		)
		if err != nil {
			return fmt.Errorf("upsert macro %q: %w", name, err)
		}
		return nil
	})
}

// GetMacro retrieves a macro definition by name.
func (s *SQLiteStore) GetMacro(ctx context.Context, name string) (*MacroRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT name, description, config, created_at, updated_at FROM macros WHERE name = ?`, name)

	var rec MacroRecord
	var createdStr, updatedStr string
	err := row.Scan(&rec.Name, &rec.Description, &rec.ConfigJSON, &createdStr, &updatedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("macro %q not found", name)
		}
		return nil, fmt.Errorf("scan macro: %w", err)
	}

	var parseErr error
	rec.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdStr)
	if parseErr != nil {
		slog.Warn("failed to parse macro created_at timestamp", "macro", rec.Name, "value", createdStr, "error", parseErr)
	}
	rec.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedStr)
	if parseErr != nil {
		slog.Warn("failed to parse macro updated_at timestamp", "macro", rec.Name, "value", updatedStr, "error", parseErr)
	}
	return &rec, nil
}

// ListMacros returns all stored macro definitions ordered by name.
func (s *SQLiteStore) ListMacros(ctx context.Context) ([]*MacroRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, description, config, created_at, updated_at FROM macros ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list macros: %w", err)
	}
	defer rows.Close()

	var records []*MacroRecord
	for rows.Next() {
		var rec MacroRecord
		var createdStr, updatedStr string
		if err := rows.Scan(&rec.Name, &rec.Description, &rec.ConfigJSON, &createdStr, &updatedStr); err != nil {
			return nil, fmt.Errorf("scan macro row: %w", err)
		}
		var parseErr error
		rec.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdStr)
		if parseErr != nil {
			slog.Warn("failed to parse macro created_at timestamp", "macro", rec.Name, "value", createdStr, "error", parseErr)
		}
		rec.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedStr)
		if parseErr != nil {
			slog.Warn("failed to parse macro updated_at timestamp", "macro", rec.Name, "value", updatedStr, "error", parseErr)
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// DeleteMacro removes a macro definition by name.
func (s *SQLiteStore) DeleteMacro(ctx context.Context, name string) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		result, err := s.db.ExecContext(ctx, "DELETE FROM macros WHERE name = ?", name)
		if err != nil {
			return fmt.Errorf("delete macro %q: %w", name, err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("macro %q not found", name)
		}
		return nil
	})
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

func scanStream(row scannable) (*Stream, error) {
	var (
		st             Stream
		tsStr          string
		durationMs     int64
		tagsStr        string
		clientAddr     string
		serverAddr     string
		tlsVersion     string
		tlsCipher      string
		tlsALPN        string
		tlsCertSubject string
		blockedBy      string
		sendMs         sql.NullInt64
		waitMs         sql.NullInt64
		receiveMs      sql.NullInt64
		failureReason  string
	)

	err := row.Scan(
		&st.ID,
		&st.ConnID,
		&st.Protocol,
		&st.Scheme,
		&st.State,
		&tsStr,
		&durationMs,
		&tagsStr,
		&clientAddr,
		&serverAddr,
		&tlsVersion,
		&tlsCipher,
		&tlsALPN,
		&tlsCertSubject,
		&blockedBy,
		&sendMs,
		&waitMs,
		&receiveMs,
		&failureReason,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("stream not found")
		}
		return nil, fmt.Errorf("scan stream: %w", err)
	}

	if tagsStr != "" && tagsStr != "{}" {
		if err := json.Unmarshal([]byte(tagsStr), &st.Tags); err != nil {
			slog.Warn("failed to parse stream tags", "stream_id", st.ID, "value", tagsStr, "error", err)
			st.Tags = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse stream timestamp (possible bug)", "value", tsStr, "error", err)
	}
	st.Timestamp = ts
	st.Duration = time.Duration(durationMs) * time.Millisecond

	if clientAddr != "" || serverAddr != "" || tlsVersion != "" || tlsCipher != "" || tlsALPN != "" || tlsCertSubject != "" {
		st.ConnInfo = &ConnectionInfo{
			ClientAddr:           clientAddr,
			ServerAddr:           serverAddr,
			TLSVersion:           tlsVersion,
			TLSCipher:            tlsCipher,
			TLSALPN:              tlsALPN,
			TLSServerCertSubject: tlsCertSubject,
		}
	}

	st.BlockedBy = blockedBy
	st.FailureReason = failureReason
	st.SendMs = nullInt64ToPtr(sendMs)
	st.WaitMs = nullInt64ToPtr(waitMs)
	st.ReceiveMs = nullInt64ToPtr(receiveMs)

	return &st, nil
}

func scanFlow(row scannable) (*Flow, error) {
	var (
		f             Flow
		tsStr         string
		headersStr    string
		urlStr        string
		bodyTruncated int
		metadataStr   string
	)

	err := row.Scan(
		&f.ID,
		&f.StreamID,
		&f.Sequence,
		&f.Direction,
		&tsStr,
		&headersStr,
		&f.Body,
		&f.RawBytes,
		&bodyTruncated,
		&f.Method,
		&urlStr,
		&f.StatusCode,
		&metadataStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("flow not found")
		}
		return nil, fmt.Errorf("scan flow: %w", err)
	}

	if urlStr != "" {
		parsed, err := url.Parse(urlStr)
		if err == nil {
			f.URL = parsed
		}
	}

	if err := json.Unmarshal([]byte(headersStr), &f.Headers); err != nil {
		f.Headers = make(map[string][]string)
	}
	if metadataStr != "" && metadataStr != "{}" {
		if err := json.Unmarshal([]byte(metadataStr), &f.Metadata); err != nil {
			f.Metadata = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse flow timestamp (possible bug)", "value", tsStr, "error", err)
	}
	f.Timestamp = ts
	f.BodyTruncated = bodyTruncated != 0

	return &f, nil
}

// boolToInt converts a boolean to an integer (0 or 1) for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullInt64ToPtr converts a sql.NullInt64 to a *int64.
// Returns nil if the value is not valid (NULL in the database).
func nullInt64ToPtr(n sql.NullInt64) *int64 {
	if n.Valid {
		return &n.Int64
	}
	return nil
}
