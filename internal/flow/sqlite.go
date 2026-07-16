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

	var clientAddr, serverAddr, tlsVersion, tlsCipher, tlsALPN, tlsCertSubject, tlsClientJA3, tlsClientJA4 string
	if st.ConnInfo != nil {
		clientAddr = st.ConnInfo.ClientAddr
		serverAddr = st.ConnInfo.ServerAddr
		tlsVersion = st.ConnInfo.TLSVersion
		tlsCipher = st.ConnInfo.TLSCipher
		tlsALPN = st.ConnInfo.TLSALPN
		tlsCertSubject = st.ConnInfo.TLSServerCertSubject
		tlsClientJA3 = st.ConnInfo.TLSClientJA3
		tlsClientJA4 = st.ConnInfo.TLSClientJA4
	}

	state := st.State
	if state == "" {
		state = "complete"
	}

	// Default unset Origin to OriginProxy so the column never holds the
	// empty string. The schemaV12 default 'proxy' would also cover this
	// at the storage layer, but stamping it here keeps in-memory Stream
	// values consistent with what readers see after a roundtrip.
	origin := st.Origin
	if origin == "" {
		origin = OriginProxy
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO streams (id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason, origin, tls_client_ja3, tls_client_ja4)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		string(origin),
		tlsClientJA3,
		tlsClientJA4,
	)
	if err != nil {
		return fmt.Errorf("insert stream: %w", err)
	}
	return nil
}

// UpdateStream applies partial updates to an existing stream.
//
// When update.AppendTags is non-nil and non-empty, the existing tags JSON
// blob is read inside the single-writer goroutine, the supplied entries
// are merged on top of the existing map (later keys win), and the merged
// JSON is written back. AppendTags is mutually exclusive with Tags; an
// update that sets both is rejected to avoid ambiguous semantics
// (USK-797). When the row is missing a tags blob the merge starts from
// an empty map; AppendTags also writes when the row currently has no
// tags so the classification "error" tag is not lost.
func (s *SQLiteStore) UpdateStream(ctx context.Context, id string, update StreamUpdate) error {
	if update.Tags != nil && len(update.AppendTags) > 0 {
		return fmt.Errorf("update stream %s: Tags and AppendTags are mutually exclusive", id)
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		// Resolve AppendTags into a concrete Tags assignment by reading
		// the current row and merging. Performed inside the write
		// goroutine so the read+write is atomic with respect to other
		// queued writes; concurrent reads from outside the goroutine
		// only see the post-commit state.
		if len(update.AppendTags) > 0 {
			merged, err := s.mergeStreamTagsLocked(ctx, id, update.AppendTags)
			if err != nil {
				return err
			}
			update.AppendTags = nil
			update.Tags = merged
		}

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

// mergeStreamTagsLocked reads the current tags column for id, decodes
// the JSON blob into a map, overlays the supplied entries on top, and
// returns the merged map. A missing row, an empty / "{}" tags value, or
// a malformed JSON blob all degrade to "treat the existing tags as
// empty"; the caller's writes still land. Errors are reserved for SQL
// driver failures so the queued write can surface them up.
//
// Must be called from inside the SQLiteStore.writeLoop goroutine — the
// caller is responsible for the single-writer discipline that makes the
// read+merge+write atomic.
func (s *SQLiteStore) mergeStreamTagsLocked(ctx context.Context, id string, overlay map[string]string) (map[string]string, error) {
	var current string
	row := s.db.QueryRowContext(ctx, `SELECT tags FROM streams WHERE id = ?`, id)
	if err := row.Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			// Row missing: nothing to merge against. The downstream
			// UPDATE will be a no-op (rowcount 0), but returning the
			// overlay here keeps the write path uniform.
			merged := make(map[string]string, len(overlay))
			for k, v := range overlay {
				merged[k] = v
			}
			return merged, nil
		}
		return nil, fmt.Errorf("read tags for stream %s: %w", id, err)
	}
	merged := make(map[string]string, len(overlay))
	if current != "" && current != "{}" {
		if err := json.Unmarshal([]byte(current), &merged); err != nil {
			// Treat a corrupt blob as "no prior tags" — the alternative
			// is dropping the operator-visible "error" tag the caller is
			// trying to record, which is strictly worse for diagnostics.
			s.logger.Warn("failed to parse stream tags during merge",
				"stream_id", id,
				"value", current,
				"error", err,
			)
			merged = make(map[string]string, len(overlay))
		}
	}
	if merged == nil {
		// Unmarshal of literal JSON "null" (or any future blob that decodes
		// to a nil map) leaves merged == nil; the overlay assignment below
		// would then panic inside the writeLoop goroutine. Re-init so the
		// caller's writes still land.
		merged = make(map[string]string, len(overlay))
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged, nil
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

	addString("protocol", update.Protocol)
	addString("state", update.State)
	addString("failure_reason", update.FailureReason)
	addString("blocked_by", update.BlockedBy)
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
	addString("tls_client_ja3", update.TLSClientJA3)
	addString("tls_client_ja4", update.TLSClientJA4)
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
const streamColumns = `id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason, origin, tls_client_ja3, tls_client_ja4`

// buildStreamWhereClause constructs a SQL WHERE clause from StreamListOptions.
// Method, URLPattern, StatusCode, and HTTPVersion are matched via EXISTS
// subqueries on flows. The simple-equality predicates (Scheme, BlockedBy,
// State, Origin) are factored into appendStreamSimplePredicates to keep this
// function under the gocyclo threshold.
func buildStreamWhereClause(opts StreamListOptions) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	conditions, args = appendStreamProtocolPredicate(conditions, args, opts)
	conditions, args = appendStreamSimplePredicates(conditions, args, opts)
	conditions, args = appendStreamFlowExistsPredicates(conditions, args, opts)
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

// appendStreamProtocolPredicate adds the Protocols-list / single-Protocol
// predicate. Protocols (multi) takes precedence over Protocol (single) when
// both are set.
func appendStreamProtocolPredicate(conds []string, args []interface{}, opts StreamListOptions) ([]string, []interface{}) {
	switch {
	case len(opts.Protocols) > 0:
		placeholders := strings.Repeat("?,", len(opts.Protocols))
		placeholders = placeholders[:len(placeholders)-1]
		conds = append(conds, "s.protocol IN ("+placeholders+")")
		for _, p := range opts.Protocols {
			args = append(args, p)
		}
	case opts.Protocol != "":
		conds = append(conds, "s.protocol = ?")
		args = append(args, opts.Protocol)
	}
	return conds, args
}

// appendStreamSimplePredicates adds equality predicates that map a single
// option field to a single column on streams. Extracted to keep
// buildStreamWhereClause under the gocyclo threshold.
func appendStreamSimplePredicates(conds []string, args []interface{}, opts StreamListOptions) ([]string, []interface{}) {
	if opts.Scheme != "" {
		conds = append(conds, "s.scheme = ?")
		args = append(args, opts.Scheme)
	}
	if opts.BlockedBy != "" {
		conds = append(conds, "s.blocked_by = ?")
		args = append(args, opts.BlockedBy)
	}
	if opts.State != "" {
		conds = append(conds, "s.state = ?")
		args = append(args, opts.State)
	}
	if opts.Origin != "" {
		conds = append(conds, "s.origin = ?")
		args = append(args, string(opts.Origin))
	}
	return conds, args
}

// appendStreamFlowExistsPredicates adds HTTPVersion / Method / URLPattern /
// StatusCode predicates, all of which match via an EXISTS subquery on flows.
// HTTPVersion (USK-792, schemaV13) treats nil as "no filter" and an explicit
// empty string as "match pre-USK-788 rows".
func appendStreamFlowExistsPredicates(conds []string, args []interface{}, opts StreamListOptions) ([]string, []interface{}) {
	if opts.HTTPVersion != nil {
		// EXISTS subquery: any flow on the stream matching the
		// http_version value selects the stream. Empty string matches
		// pre-USK-788 rows (schemaV13's DEFAULT ''). The
		// idx_flows_http_version index makes the subquery cheap.
		conds = append(conds, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.http_version = ?)")
		args = append(args, *opts.HTTPVersion)
	}
	if opts.Method != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'send' AND m.method = ?)")
		args = append(args, opts.Method)
	}
	if opts.URLPattern != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(opts.URLPattern)
		conds = append(conds, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'send' AND m.url LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	if opts.StatusCode != 0 {
		conds = append(conds, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = s.id AND m.direction = 'receive' AND m.status_code = ?)")
		args = append(args, opts.StatusCode)
	}
	return conds, args
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
//
// Deprecated: callers should migrate to DeleteStreamsByFilter so they
// can compose protocol with scheme / http_version (USK-792). This shim
// is implemented over DeleteStreamsByFilter to avoid divergent SQL.
func (s *SQLiteStore) DeleteStreamsByProtocol(ctx context.Context, protocol string) (int64, error) {
	return s.DeleteStreamsByFilter(ctx, StreamDeleteFilter{Protocol: protocol})
}

// DeleteStreamsByFilter removes streams matching all non-zero fields of
// filter (AND-combined). It rejects a fully zero filter to avoid an
// accidental DELETE that erases every stream — callers must use
// DeleteAllStreams for that explicit case.
//
// The query is parameterised throughout; no filter value is ever
// interpolated into the SQL string. The http_version predicate is an
// EXISTS subquery on the flows table because http_version lives there
// (schemaV13). The idx_flows_http_version index makes the subquery
// cheap. The url_pattern predicate is an EXISTS subquery on the flows
// table mirroring the SELECT-side URL-pattern predicate
// (appendStreamFlowExistsPredicates). Time bounds use the same
// RFC3339Nano lex-comparable string format DeleteStreamsOlderThan uses
// (USK-822). Cascade deletion of associated flows is handled by the
// foreign key (ON DELETE CASCADE), the same way DeleteStream does it.
func (s *SQLiteStore) DeleteStreamsByFilter(ctx context.Context, filter StreamDeleteFilter) (int64, error) {
	if filter.IsZero() {
		return 0, fmt.Errorf("delete streams by filter: filter must specify at least one of protocol, scheme, http_version, url_pattern, time_after, time_before")
	}

	var conditions []string
	var args []interface{}
	if filter.Protocol != "" {
		conditions = append(conditions, "protocol = ?")
		args = append(args, filter.Protocol)
	}
	if filter.Scheme != "" {
		conditions = append(conditions, "scheme = ?")
		args = append(args, filter.Scheme)
	}
	if filter.HTTPVersion != nil {
		// streams.id (not an alias) — DELETE has no FROM-alias slot, so the
		// subquery references the table by name. Mirrors the
		// idx_flows_http_version-backed predicate used in
		// buildStreamWhereClause (which aliases as s.id under SELECT).
		conditions = append(conditions, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = streams.id AND m.http_version = ?)")
		args = append(args, *filter.HTTPVersion)
	}
	if filter.URLPattern != "" {
		// Mirror appendStreamFlowExistsPredicates: substring match on
		// send-direction flows.url with `\\` as the LIKE escape so
		// callers' literal '%' / '_' / '\\' characters do not become
		// wildcards. Substring boundaries (% on each side) match the
		// SELECT-path semantics analysts already exercise via
		// query / export.
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(filter.URLPattern)
		conditions = append(conditions, "EXISTS (SELECT 1 FROM flows m WHERE m.stream_id = streams.id AND m.direction = 'send' AND m.url LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escaped+"%")
	}
	if filter.TimeAfter != nil {
		// streams.timestamp is an RFC3339Nano string; lex compare ==
		// chronological compare. Same shape as DeleteStreamsOlderThan.
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.TimeAfter.UTC().Format(time.RFC3339Nano))
	}
	if filter.TimeBefore != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.TimeBefore.UTC().Format(time.RFC3339Nano))
	}

	query := "DELETE FROM streams WHERE " + strings.Join(conditions, " AND ")
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("delete streams by filter: %w", err)
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

	trailers := "{}"
	if f.Trailers != nil {
		trailersJSON, err := json.Marshal(f.Trailers)
		if err != nil {
			return fmt.Errorf("marshal trailers: %w", err)
		}
		trailers = string(trailersJSON)
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

	// Project Metadata["variant"] into the dedicated column so the V11
	// UNIQUE(stream_id, sequence, direction, variant) constraint can
	// distinguish the original and modified records of an intercepted
	// flow. Non-variant flows persist as variant='' (V8 behavior).
	//
	// The variant value is intentionally duplicated into both the column
	// (for the UNIQUE constraint) and the metadata JSON column (for read
	// consumers — flowColumns SELECT does not project the variant column,
	// so all readers go through Metadata["variant"]). The column is the
	// source of truth for the constraint; metadata remains the single
	// source of truth for read paths (see categorizeMessages /
	// resolveVariantPair in internal/mcp/query_tool.go).
	variant := ""
	if f.Metadata != nil {
		variant = f.Metadata["variant"]
	}

	// USK-889: schemaV14 wire_level column. Default to WireLevelSemantic
	// for any Flow that arrives without an explicit value so all existing
	// call sites (RecordStep main Pipeline + import path + tests) keep
	// recording under the canonical semantic discriminator without code
	// changes. Frame-record callers (session.runUpgrade* h2 detach
	// callbacks) stamp WireLevelH2Frame explicitly.
	wireLevel := f.WireLevel
	if wireLevel == "" {
		wireLevel = WireLevelSemantic
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO flows (id, stream_id, sequence, direction, variant, wire_level, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata, trailers, http_version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID,
		f.StreamID,
		f.Sequence,
		f.Direction,
		variant,
		wireLevel,
		f.Timestamp.UTC().Format(time.RFC3339Nano),
		headers,
		f.Body,
		f.RawBytes,
		boolToInt(f.BodyTruncated),
		f.Method,
		urlStr,
		f.StatusCode,
		metadata,
		trailers,
		f.HTTPVersion,
	)
	if err != nil {
		return fmt.Errorf("insert flow: %w", err)
	}
	return nil
}

// flowColumns is the list of columns selected in flow queries. http_version
// (USK-788) and wire_level (USK-889) are appended at the tail so any future
// flow column added by migrations stays grouped with this scan/projection
// list.
const flowColumns = `id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata, trailers, http_version, wire_level`

// GetFlow retrieves a flow by ID.
func (s *SQLiteStore) GetFlow(ctx context.Context, id string) (*Flow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+flowColumns+` FROM flows WHERE id = ?`, id)
	return scanFlow(row)
}

// GetFlows retrieves flows for a stream, optionally filtered by direction
// or wire_level (USK-889).
func (s *SQLiteStore) GetFlows(ctx context.Context, streamID string, opts FlowListOptions) ([]*Flow, error) {
	query := "SELECT " + flowColumns + " FROM flows WHERE stream_id = ?"
	args := []interface{}{streamID}

	if opts.Direction != "" {
		query += " AND direction = ?"
		args = append(args, opts.Direction)
	}
	if opts.WireLevel != "" {
		// USK-889: wire_level discriminator. Empty value disables the
		// predicate (caller wants every layer of recording for the stream).
		query += " AND wire_level = ?"
		args = append(args, opts.WireLevel)
	}

	// USK-935: order by (timestamp, sequence, direction) so the read-time
	// order matches the wire-observed order. gRPC, gRPC-Web, and WebSocket
	// Channels use a per-direction sequence counter — sequence values for
	// SEND and RECV collide (both start at 0), and SQLite's tie-break on
	// "ORDER BY sequence ASC" alone is non-deterministic. Sorting by
	// timestamp first reproduces the wire arrival order; the (sequence,
	// direction) tail keeps the order deterministic when two rows share
	// the same RFC3339Nano timestamp (e.g. variants written back-to-back).
	// envelopeToFlow stamps Timestamp via time.Now() for every flow,
	// including overlay (h2-frame, grpc-lpm-frame) rows; sqlite.go writes
	// it as RFC3339Nano UTC. Two time.Now() calls on modern Linux
	// always produce monotonically increasing nanoseconds (clock_gettime
	// CLOCK_REALTIME ~100ns resolution), and the RFC3339Nano fractional
	// part is therefore consistently 7-9 digits wide across same-stream
	// flow inserts, so BINARY collation preserves chronological order in
	// the live data path. The Sequence + Direction tie-break covers the
	// edge case where two writes within the same nanosecond share a
	// rendered timestamp. The per-direction Sequence field values on the
	// Layer Channel are unchanged; only the read-time ORDER BY moves.
	query += " ORDER BY timestamp ASC, sequence ASC, direction ASC"

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

// CountFlowsByWireLevel implements the FlowReader contract. SQL is a
// single GROUP BY on the wire_level column so we never load per-flow
// payloads just to count them. Empty-string wire_level rows (pre-V14
// backfill) are folded into the semantic bucket at scan time so the
// returned map only carries canonical keys.
func (s *SQLiteStore) CountFlowsByWireLevel(ctx context.Context, streamID string, opts FlowListOptions) (map[string]int, error) {
	query := "SELECT wire_level, COUNT(*) FROM flows WHERE stream_id = ?"
	args := []interface{}{streamID}
	if opts.Direction != "" {
		query += " AND direction = ?"
		args = append(args, opts.Direction)
	}
	query += " GROUP BY wire_level"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("count flows by wire_level: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var wl string
		var n int
		if err := rows.Scan(&wl, &n); err != nil {
			return nil, fmt.Errorf("scan wire_level count: %w", err)
		}
		// Backward compat: pre-V14 backfilled rows or rows whose
		// producer never stamped wire_level fold into the semantic
		// bucket per the column-default contract.
		if wl == "" {
			wl = WireLevelSemantic
		}
		out[wl] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter wire_level rows: %w", err)
	}
	return out, nil
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

// SaveGRPCSchema persists a gRPC schema entry using upsert semantics
// (USK-923). If a row with the same service exists, descriptor_set,
// source_label, and updated_at are overwritten while registered_at is
// preserved.
func (s *SQLiteStore) SaveGRPCSchema(ctx context.Context, service string, descriptorSet []byte, sourceLabel string) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO grpc_schemas (service, descriptor_set, source_label, registered_at, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(service) DO UPDATE SET descriptor_set = excluded.descriptor_set, source_label = excluded.source_label, updated_at = excluded.updated_at`,
			service, descriptorSet, sourceLabel, now, now,
		)
		if err != nil {
			return fmt.Errorf("upsert grpc_schema %q: %w", service, err)
		}
		return nil
	})
}

// GetGRPCSchema retrieves a stored schema entry by service name.
func (s *SQLiteStore) GetGRPCSchema(ctx context.Context, service string) (*GRPCSchemaRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT service, descriptor_set, source_label, registered_at, updated_at FROM grpc_schemas WHERE service = ?`, service)

	var rec GRPCSchemaRecord
	var registeredStr, updatedStr string
	err := row.Scan(&rec.Service, &rec.DescriptorSet, &rec.SourceLabel, &registeredStr, &updatedStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("grpc_schema %q not found", service)
		}
		return nil, fmt.Errorf("scan grpc_schema: %w", err)
	}
	var parseErr error
	rec.RegisteredAt, parseErr = time.Parse(time.RFC3339Nano, registeredStr)
	if parseErr != nil {
		slog.Warn("failed to parse grpc_schema registered_at timestamp", "service", rec.Service, "value", registeredStr, "error", parseErr)
	}
	rec.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedStr)
	if parseErr != nil {
		slog.Warn("failed to parse grpc_schema updated_at timestamp", "service", rec.Service, "value", updatedStr, "error", parseErr)
	}
	return &rec, nil
}

// ListGRPCSchemas returns all stored schema entries ordered by service name.
func (s *SQLiteStore) ListGRPCSchemas(ctx context.Context) ([]*GRPCSchemaRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT service, descriptor_set, source_label, registered_at, updated_at FROM grpc_schemas ORDER BY service ASC`)
	if err != nil {
		return nil, fmt.Errorf("list grpc_schemas: %w", err)
	}
	defer rows.Close()

	var records []*GRPCSchemaRecord
	for rows.Next() {
		var rec GRPCSchemaRecord
		var registeredStr, updatedStr string
		if err := rows.Scan(&rec.Service, &rec.DescriptorSet, &rec.SourceLabel, &registeredStr, &updatedStr); err != nil {
			return nil, fmt.Errorf("scan grpc_schema row: %w", err)
		}
		var parseErr error
		rec.RegisteredAt, parseErr = time.Parse(time.RFC3339Nano, registeredStr)
		if parseErr != nil {
			slog.Warn("failed to parse grpc_schema registered_at timestamp", "service", rec.Service, "value", registeredStr, "error", parseErr)
		}
		rec.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedStr)
		if parseErr != nil {
			slog.Warn("failed to parse grpc_schema updated_at timestamp", "service", rec.Service, "value", updatedStr, "error", parseErr)
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// DeleteGRPCSchema removes a schema entry by service name.
func (s *SQLiteStore) DeleteGRPCSchema(ctx context.Context, service string) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		result, err := s.db.ExecContext(ctx, "DELETE FROM grpc_schemas WHERE service = ?", service)
		if err != nil {
			return fmt.Errorf("delete grpc_schema %q: %w", service, err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("grpc_schema %q not found", service)
		}
		return nil
	})
}

// ClearGRPCSchemas deletes every schema entry; returns the number of
// rows removed.
func (s *SQLiteStore) ClearGRPCSchemas(ctx context.Context) (int64, error) {
	var deleted int64
	err := s.enqueueWrite(ctx, func(ctx context.Context) error {
		result, err := s.db.ExecContext(ctx, "DELETE FROM grpc_schemas")
		if err != nil {
			return fmt.Errorf("clear grpc_schemas: %w", err)
		}
		n, rerr := result.RowsAffected()
		if rerr != nil {
			return fmt.Errorf("rows affected: %w", rerr)
		}
		deleted = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
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

// connInfoFromColumns returns a pointer to ci when any field is populated,
// or nil when the row carried no connection metadata at all. Kept out of
// scanStream to bound that function's cyclomatic complexity as the TLS
// column set grows.
func connInfoFromColumns(ci ConnectionInfo) *ConnectionInfo {
	if ci == (ConnectionInfo{}) {
		return nil
	}
	return &ci
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
		origin         string
		tlsClientJA3   string
		tlsClientJA4   string
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
		&origin,
		&tlsClientJA3,
		&tlsClientJA4,
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

	st.ConnInfo = connInfoFromColumns(ConnectionInfo{
		ClientAddr:           clientAddr,
		ServerAddr:           serverAddr,
		TLSVersion:           tlsVersion,
		TLSCipher:            tlsCipher,
		TLSALPN:              tlsALPN,
		TLSServerCertSubject: tlsCertSubject,
		TLSClientJA3:         tlsClientJA3,
		TLSClientJA4:         tlsClientJA4,
	})

	st.BlockedBy = blockedBy
	st.FailureReason = failureReason
	// Materialize the origin column. The schemaV12 NOT NULL DEFAULT 'proxy'
	// ensures rows from any migration baseline produce a non-empty value;
	// fall back defensively to OriginProxy if a future migration leaves the
	// column blank (e.g. ALTER TABLE backfill divergence).
	if origin == "" {
		st.Origin = OriginProxy
	} else {
		st.Origin = Origin(origin)
	}
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
		trailersStr   string
		httpVersion   string
		wireLevel     string
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
		&trailersStr,
		&httpVersion,
		&wireLevel,
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
	if trailersStr != "" && trailersStr != "{}" {
		if err := json.Unmarshal([]byte(trailersStr), &f.Trailers); err != nil {
			f.Trailers = nil
		}
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
	f.HTTPVersion = httpVersion
	// USK-889: backstop empty wire_level reads to the semantic default.
	// schemaV14 stamps DEFAULT 'semantic' on the column so backfilled rows
	// always read as 'semantic'; this guard handles a future migration that
	// might leave the column blank without going through the column default.
	if wireLevel == "" {
		f.WireLevel = WireLevelSemantic
	} else {
		f.WireLevel = wireLevel
	}

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
