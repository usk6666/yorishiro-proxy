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

// SaveFlow persists a new flow.
func (s *SQLiteStore) SaveFlow(ctx context.Context, fl *Flow) error {
	if fl.ID == "" {
		fl.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		return s.saveFlowSync(ctx, fl)
	})
}

func (s *SQLiteStore) saveFlowSync(ctx context.Context, fl *Flow) error {
	tags := "{}"
	if fl.Tags != nil {
		tagsJSON, err := json.Marshal(fl.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
		tags = string(tagsJSON)
	}

	var clientAddr, serverAddr, tlsVersion, tlsCipher, tlsALPN, tlsCertSubject string
	if fl.ConnInfo != nil {
		clientAddr = fl.ConnInfo.ClientAddr
		serverAddr = fl.ConnInfo.ServerAddr
		tlsVersion = fl.ConnInfo.TLSVersion
		tlsCipher = fl.ConnInfo.TLSCipher
		tlsALPN = fl.ConnInfo.TLSALPN
		tlsCertSubject = fl.ConnInfo.TLSServerCertSubject
	}

	flowType := fl.FlowType
	if flowType == "" {
		flowType = "unary"
	}
	state := fl.State
	if state == "" {
		state = "complete"
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO flows (id, conn_id, protocol, flow_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fl.ID,
		fl.ConnID,
		fl.Protocol,
		flowType,
		state,
		fl.Timestamp.UTC().Format(time.RFC3339Nano),
		fl.Duration.Milliseconds(),
		tags,
		clientAddr,
		serverAddr,
		tlsVersion,
		tlsCipher,
		tlsALPN,
		tlsCertSubject,
		fl.BlockedBy,
	)
	if err != nil {
		return fmt.Errorf("insert flow: %w", err)
	}
	return nil
}

// UpdateFlow applies partial updates to an existing flow.
func (s *SQLiteStore) UpdateFlow(ctx context.Context, id string, update FlowUpdate) error {
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
		if update.ServerAddr != "" {
			sets = append(sets, "server_addr = ?")
			args = append(args, update.ServerAddr)
		}
		if update.TLSServerCertSubject != "" {
			sets = append(sets, "tls_server_cert_subject = ?")
			args = append(args, update.TLSServerCertSubject)
		}

		if len(sets) == 0 {
			return nil
		}

		args = append(args, id)
		query := fmt.Sprintf("UPDATE flows SET %s WHERE id = ?", strings.Join(sets, ", "))
		_, err := s.db.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("update flow %s: %w", id, err)
		}
		return nil
	})
}

// GetFlow retrieves a flow by ID. It accepts either a full UUID (36 chars)
// or an 8-character prefix. For prefix lookups, the ID must match exactly
// one flow; ambiguous prefixes return an error.
func (s *SQLiteStore) GetFlow(ctx context.Context, id string) (*Flow, error) {
	// Try exact match first.
	row := s.db.QueryRowContext(ctx,
		`SELECT `+flowColumns+` FROM flows WHERE id = ?`, id)
	fl, err := scanFlow(row)
	if err == nil {
		return fl, nil
	}

	// If the input is exactly 8 characters and exact match failed,
	// attempt prefix resolution.
	if len(id) == 8 {
		resolved, resolveErr := s.resolvePrefix(ctx, id)
		if resolveErr != nil {
			return nil, resolveErr
		}
		row = s.db.QueryRowContext(ctx,
			`SELECT `+flowColumns+` FROM flows WHERE id = ?`, resolved)
		return scanFlow(row)
	}

	return nil, err
}

// resolvePrefix searches for flows matching the given 8-character ID prefix.
// Returns the full ID if exactly one flow matches, or an error otherwise.
func (s *SQLiteStore) resolvePrefix(ctx context.Context, prefix string) (string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM flows WHERE id LIKE ? LIMIT 2`, prefix+"%")
	if err != nil {
		return "", fmt.Errorf("resolve flow ID prefix: %w", err)
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var matchID string
		if err := rows.Scan(&matchID); err != nil {
			return "", fmt.Errorf("scan flow ID: %w", err)
		}
		matches = append(matches, matchID)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("resolve flow ID prefix: %w", err)
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("flow not found")
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous flow ID prefix %q: matched %d flows", prefix, len(matches))
	}
}

// ValidateFlowID checks that the given ID is a valid flow ID format:
// either a full UUID (36 chars) or an 8-character prefix.
// Returns an error for lengths 1-7 and 9-35.
func ValidateFlowID(id string) error {
	n := len(id)
	if n == 36 || n == 8 {
		return nil
	}
	return fmt.Errorf("invalid flow ID: must be full UUID (36 chars) or 8-char prefix")
}

// flowColumns is the list of columns selected in flow queries.
const flowColumns = `id, conn_id, protocol, flow_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by`

// buildFlowWhereClause constructs a SQL WHERE clause from ListOptions.
// Method, URLPattern, and StatusCode are matched via EXISTS subqueries on messages.
func buildFlowWhereClause(opts ListOptions) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if opts.Protocol != "" {
		conditions = append(conditions, "s.protocol = ?")
		args = append(args, opts.Protocol)
	}
	if opts.Method != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.flow_id = s.id AND m.direction = 'send' AND m.method = ?)")
		args = append(args, opts.Method)
	}
	if opts.URLPattern != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.URLPattern)
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.flow_id = s.id AND m.direction = 'send' AND m.url LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	if opts.StatusCode != 0 {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM messages m WHERE m.flow_id = s.id AND m.direction = 'receive' AND m.status_code = ?)")
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
		// of the URL stored in send messages. server_addr may contain a port,
		// so we check both exact match and host-prefix match (host:*).
		// For URL-based matching, we extract the host via an EXISTS subquery
		// using SQLite string functions on the message url column.
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.Host)
		conditions = append(conditions, "(s.server_addr = ? OR s.server_addr LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM messages m WHERE m.flow_id = s.id AND m.direction = 'send' AND (m.url LIKE ? ESCAPE '\\' OR m.url LIKE ? ESCAPE '\\')))")
		args = append(args, opts.Host, escaped+":%", "%://"+escaped+"/%", "%://"+escaped)
	}

	clause := ""
	if len(conditions) > 0 {
		clause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return clause, args
}

// ListFlows returns flows matching the given options.
func (s *SQLiteStore) ListFlows(ctx context.Context, opts ListOptions) ([]*Flow, error) {
	whereClause, args := buildFlowWhereClause(opts)

	query := "SELECT " + flowColumns + " FROM flows s" + whereClause
	query += " ORDER BY s.timestamp DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()

	var flows []*Flow
	for rows.Next() {
		fl, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, fl)
	}
	return flows, rows.Err()
}

// CountFlows returns the total number of flows matching the given filter options.
func (s *SQLiteStore) CountFlows(ctx context.Context, opts ListOptions) (int, error) {
	whereClause, args := buildFlowWhereClause(opts)

	query := "SELECT COUNT(*) FROM flows s" + whereClause

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count flows: %w", err)
	}
	return count, nil
}

// DeleteFlow removes a flow by ID (messages are cascade-deleted).
func (s *SQLiteStore) DeleteFlow(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM flows WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete flow %s: %w", id, err)
	}
	return nil
}

// DeleteAllFlows removes all flows and returns the number of deleted rows.
func (s *SQLiteStore) DeleteAllFlows(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM flows")
	if err != nil {
		return 0, fmt.Errorf("delete all flows: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteFlowsByProtocol removes flows matching the given protocol.
func (s *SQLiteStore) DeleteFlowsByProtocol(ctx context.Context, protocol string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM flows WHERE protocol = ?", protocol)
	if err != nil {
		return 0, fmt.Errorf("delete flows by protocol %q: %w", protocol, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteFlowsOlderThan removes flows with timestamps before the given cutoff.
func (s *SQLiteStore) DeleteFlowsOlderThan(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM flows WHERE timestamp < ?",
		before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete flows older than %s: %w", before.Format(time.RFC3339), err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// DeleteExcessFlows removes the oldest flows exceeding maxCount.
func (s *SQLiteStore) DeleteExcessFlows(ctx context.Context, maxCount int) (int64, error) {
	if maxCount <= 0 {
		return 0, fmt.Errorf("maxCount must be > 0, got %d", maxCount)
	}
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM flows WHERE id NOT IN (SELECT id FROM flows ORDER BY timestamp DESC LIMIT ?)",
		maxCount)
	if err != nil {
		return 0, fmt.Errorf("delete excess flows: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// AppendMessage persists a new message associated with a flow.
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
		`INSERT INTO messages (id, flow_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID,
		msg.FlowID,
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
const messageColumns = `id, flow_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata`

// GetMessages retrieves messages for a flow, optionally filtered by direction.
func (s *SQLiteStore) GetMessages(ctx context.Context, flowID string, opts MessageListOptions) ([]*Message, error) {
	query := "SELECT " + messageColumns + " FROM messages WHERE flow_id = ?"
	args := []interface{}{flowID}

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

// CountMessages returns the number of messages for a flow.
func (s *SQLiteStore) CountMessages(ctx context.Context, flowID string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM messages WHERE flow_id = ?", flowID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count messages: %w", err)
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

func scanFlow(row scannable) (*Flow, error) {
	var (
		fl             Flow
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
	)

	err := row.Scan(
		&fl.ID,
		&fl.ConnID,
		&fl.Protocol,
		&fl.FlowType,
		&fl.State,
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
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("flow not found")
		}
		return nil, fmt.Errorf("scan flow: %w", err)
	}

	if tagsStr != "" && tagsStr != "{}" {
		if err := json.Unmarshal([]byte(tagsStr), &fl.Tags); err != nil {
			slog.Warn("failed to parse flow tags", "flow_id", fl.ID, "value", tagsStr, "error", err)
			fl.Tags = nil
		}
	}

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		slog.Warn("failed to parse flow timestamp (possible bug)", "value", tsStr, "error", err)
	}
	fl.Timestamp = ts
	fl.Duration = time.Duration(durationMs) * time.Millisecond

	if clientAddr != "" || serverAddr != "" || tlsVersion != "" || tlsCipher != "" || tlsALPN != "" || tlsCertSubject != "" {
		fl.ConnInfo = &ConnectionInfo{
			ClientAddr:           clientAddr,
			ServerAddr:           serverAddr,
			TLSVersion:           tlsVersion,
			TLSCipher:            tlsCipher,
			TLSALPN:              tlsALPN,
			TLSServerCertSubject: tlsCertSubject,
		}
	}

	fl.BlockedBy = blockedBy

	return &fl, nil
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
		&msg.FlowID,
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
