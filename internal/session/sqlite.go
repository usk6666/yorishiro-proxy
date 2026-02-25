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
	fn     func(ctx context.Context) error
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

	// Enable foreign keys for cascade delete.
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
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
			err := op.fn(op.ctx)
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
					err := op.fn(drainCtx)
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

// SaveSession persists a new session.
func (s *SQLiteStore) SaveSession(ctx context.Context, sess *Session) error {
	if sess.ID == "" {
		sess.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		return s.saveSessionSync(ctx, sess)
	})
}

func (s *SQLiteStore) saveSessionSync(ctx context.Context, sess *Session) error {
	tags := "{}"
	if sess.Tags != nil {
		tagsJSON, err := json.Marshal(sess.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		tags = string(tagsJSON)
	}

	var clientAddr, serverAddr, tlsVersion, tlsCipher, tlsALPN, tlsCertSubject string
	if sess.ConnInfo != nil {
		clientAddr = sess.ConnInfo.ClientAddr
		serverAddr = sess.ConnInfo.ServerAddr
		tlsVersion = sess.ConnInfo.TLSVersion
		tlsCipher = sess.ConnInfo.TLSCipher
		tlsALPN = sess.ConnInfo.TLSALPN
		tlsCertSubject = sess.ConnInfo.TLSServerCertSubject
	}

	sessionType := sess.SessionType
	if sessionType == "" {
		sessionType = "unary"
	}
	state := sess.State
	if state == "" {
		state = "complete"
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, conn_id, protocol, session_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID,
		sess.ConnID,
		sess.Protocol,
		sessionType,
		state,
		sess.Timestamp.UTC().Format(time.RFC3339Nano),
		sess.Duration.Milliseconds(),
		tags,
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

// UpdateSession applies partial updates to an existing session.
func (s *SQLiteStore) UpdateSession(ctx context.Context, id string, update SessionUpdate) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		var sets []string
		var args []interface{}

		if update.State != "" {
			sets = append(sets, "state = ?")
			args = append(args, update.State)
		}
		if update.Duration != 0 {
			sets = append(sets, "duration_ms = ?")
			args = append(args, update.Duration.Milliseconds())
		}
		if update.Tags != nil {
			tagsJSON, err := json.Marshal(update.Tags)
			if err != nil {
				return fmt.Errorf("marshal tags: %w", err)
			}
			sets = append(sets, "tags = ?")
			args = append(args, string(tagsJSON))
		}

		if len(sets) == 0 {
			return nil
		}

		args = append(args, id)
		query := fmt.Sprintf("UPDATE sessions SET %s WHERE id = ?", strings.Join(sets, ", "))
		_, err := s.db.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("update session %s: %w", id, err)
		}
		return nil
	})
}

// GetSession retrieves a session by ID.
func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

// sessionColumns is the list of columns selected in session queries.
const sessionColumns = `id, conn_id, protocol, session_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject`

// buildSessionWhereClause constructs a SQL WHERE clause from ListOptions.
// Method, URLPattern, and StatusCode are matched via EXISTS subqueries on messages.
func buildSessionWhereClause(opts ListOptions) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if opts.Protocol != "" {
		conditions = append(conditions, "s.protocol = ?")
		args = append(args, opts.Protocol)
	}
	if opts.Method != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.session_id = s.id AND m.direction = 'send' AND m.method = ?)")
		args = append(args, opts.Method)
	}
	if opts.URLPattern != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.URLPattern)
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.session_id = s.id AND m.direction = 'send' AND m.url LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	if opts.StatusCode != 0 {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.session_id = s.id AND m.direction = 'receive' AND m.status_code = ?)")
		args = append(args, opts.StatusCode)
	}

	clause := ""
	if len(conditions) > 0 {
		clause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return clause, args
}

// ListSessions returns sessions matching the given options.
func (s *SQLiteStore) ListSessions(ctx context.Context, opts ListOptions) ([]*Session, error) {
	whereClause, args := buildSessionWhereClause(opts)

	query := "SELECT " + sessionColumns + " FROM sessions s" + whereClause
	query += " ORDER BY s.timestamp DESC"

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

	var sessions []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// CountSessions returns the total number of sessions matching the given filter options.
func (s *SQLiteStore) CountSessions(ctx context.Context, opts ListOptions) (int, error) {
	whereClause, args := buildSessionWhereClause(opts)

	query := "SELECT COUNT(*) FROM sessions s" + whereClause

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return count, nil
}

// DeleteSession removes a session by ID (messages are cascade-deleted).
func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete session %s: %w", id, err)
	}
	return nil
}

// DeleteAllSessions removes all sessions and returns the number of deleted rows.
func (s *SQLiteStore) DeleteAllSessions(ctx context.Context) (int64, error) {
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

// DeleteSessionsOlderThan removes sessions with timestamps before the given cutoff.
func (s *SQLiteStore) DeleteSessionsOlderThan(ctx context.Context, before time.Time) (int64, error) {
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

// DeleteExcessSessions removes the oldest sessions exceeding maxCount.
func (s *SQLiteStore) DeleteExcessSessions(ctx context.Context, maxCount int) (int64, error) {
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

// AppendMessage persists a new message associated with a session.
func (s *SQLiteStore) AppendMessage(ctx context.Context, msg *Message) error {
	if msg.ID == "" {
		msg.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		return s.appendMessageSync(ctx, msg)
	})
}

func (s *SQLiteStore) appendMessageSync(ctx context.Context, msg *Message) error {
	headers := "{}"
	if msg.Headers != nil {
		headersJSON, err := json.Marshal(msg.Headers)
		if err != nil {
			return fmt.Errorf("marshal headers: %w", err)
		}
		headers = string(headersJSON)
	}

	metadata := "{}"
	if msg.Metadata != nil {
		metaJSON, err := json.Marshal(msg.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		metadata = string(metaJSON)
	}

	urlStr := ""
	if msg.URL != nil {
		urlStr = msg.URL.String()
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO messages (id, session_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID,
		msg.SessionID,
		msg.Sequence,
		msg.Direction,
		msg.Timestamp.UTC().Format(time.RFC3339Nano),
		headers,
		msg.Body,
		msg.RawBytes,
		boolToInt(msg.BodyTruncated),
		msg.Method,
		urlStr,
		msg.StatusCode,
		metadata,
	)
	if err != nil {
		return fmt.Errorf("insert message: %w", err)
	}
	return nil
}

// messageColumns is the list of columns selected in message queries.
const messageColumns = `id, session_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata`

// GetMessages retrieves messages for a session, optionally filtered by direction.
func (s *SQLiteStore) GetMessages(ctx context.Context, sessionID string, opts MessageListOptions) ([]*Message, error) {
	query := "SELECT " + messageColumns + " FROM messages WHERE session_id = ?"
	args := []interface{}{sessionID}

	if opts.Direction != "" {
		query += " AND direction = ?"
		args = append(args, opts.Direction)
	}

	query += " ORDER BY sequence ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	return messages, rows.Err()
}

// CountMessages returns the number of messages for a session.
func (s *SQLiteStore) CountMessages(ctx context.Context, sessionID string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages WHERE session_id = ?", sessionID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count messages: %w", err)
	}
	return count, nil
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

func scanSession(row scannable) (*Session, error) {
	var (
		sess           Session
		tsStr          string
		durationMs     int64
		tagsStr        string
		clientAddr     string
		serverAddr     string
		tlsVersion     string
		tlsCipher      string
		tlsALPN        string
		tlsCertSubject string
	)

	err := row.Scan(
		&sess.ID,
		&sess.ConnID,
		&sess.Protocol,
		&sess.SessionType,
		&sess.State,
		&tsStr,
		&durationMs,
		&tagsStr,
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

	if tagsStr != "" && tagsStr != "{}" {
		if err := json.Unmarshal([]byte(tagsStr), &sess.Tags); err != nil {
			sess.Tags = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse session timestamp (possible bug)", "value", tsStr, "error", err)
	}
	sess.Timestamp = ts
	sess.Duration = time.Duration(durationMs) * time.Millisecond

	if clientAddr != "" || serverAddr != "" || tlsVersion != "" || tlsCipher != "" || tlsALPN != "" || tlsCertSubject != "" {
		sess.ConnInfo = &ConnectionInfo{
			ClientAddr:           clientAddr,
			ServerAddr:           serverAddr,
			TLSVersion:           tlsVersion,
			TLSCipher:            tlsCipher,
			TLSALPN:              tlsALPN,
			TLSServerCertSubject: tlsCertSubject,
		}
	}

	return &sess, nil
}

func scanMessage(row scannable) (*Message, error) {
	var (
		msg           Message
		tsStr         string
		headersStr    string
		urlStr        string
		bodyTruncated int
		metadataStr   string
	)

	err := row.Scan(
		&msg.ID,
		&msg.SessionID,
		&msg.Sequence,
		&msg.Direction,
		&tsStr,
		&headersStr,
		&msg.Body,
		&msg.RawBytes,
		&bodyTruncated,
		&msg.Method,
		&urlStr,
		&msg.StatusCode,
		&metadataStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("message not found")
		}
		return nil, fmt.Errorf("scan message: %w", err)
	}

	if urlStr != "" {
		parsed, err := url.Parse(urlStr)
		if err == nil {
			msg.URL = parsed
		}
	}

	if err := json.Unmarshal([]byte(headersStr), &msg.Headers); err != nil {
		msg.Headers = make(map[string][]string)
	}
	if metadataStr != "" && metadataStr != "{}" {
		if err := json.Unmarshal([]byte(metadataStr), &msg.Metadata); err != nil {
			msg.Metadata = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse message timestamp (possible bug)", "value", tsStr, "error", err)
	}
	msg.Timestamp = ts
	msg.BodyTruncated = bodyTruncated != 0

	return &msg, nil
}

// boolToInt converts a boolean to an integer (0 or 1) for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
