package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// FuzzJob represents a fuzzing job with its metadata and progress.
type FuzzJob struct {
	// ID is the unique identifier of the fuzz job.
	ID string
	// SessionID is the template session used for fuzzing.
	SessionID string
	// Config is the JSON-encoded job configuration (positions, payload sets, etc.).
	Config string
	// Status is the current job status: "running", "paused", "completed", "cancelled", "error".
	Status string
	// Tag is an optional user-defined label for the job.
	Tag string
	// CreatedAt is the time the job was created.
	CreatedAt time.Time
	// CompletedAt is the time the job finished (nil if still running).
	CompletedAt *time.Time
	// Total is the total number of requests to send.
	Total int
	// CompletedCount is the number of completed requests.
	CompletedCount int
	// ErrorCount is the number of failed requests.
	ErrorCount int
}

// FuzzResult represents the outcome of a single fuzz iteration.
type FuzzResult struct {
	// ID is the unique identifier of the result.
	ID string
	// FuzzID is the ID of the parent fuzz job.
	FuzzID string
	// IndexNum is the 0-based iteration index within the job.
	IndexNum int
	// SessionID is the ID of the session recorded for this iteration.
	SessionID string
	// Payloads is the JSON-encoded map of position ID to payload value.
	Payloads string
	// StatusCode is the HTTP response status code (may be 0 on error).
	StatusCode int
	// ResponseLength is the response body length in bytes.
	ResponseLength int
	// DurationMs is the request duration in milliseconds.
	DurationMs int
	// Error is the error message if the request failed.
	Error string
}

// FuzzStore defines the interface for fuzz job and result persistence.
type FuzzStore interface {
	// SaveFuzzJob persists a new fuzz job.
	SaveFuzzJob(ctx context.Context, job *FuzzJob) error

	// UpdateFuzzJob updates the mutable fields of a fuzz job.
	UpdateFuzzJob(ctx context.Context, job *FuzzJob) error

	// GetFuzzJob retrieves a fuzz job by ID.
	GetFuzzJob(ctx context.Context, id string) (*FuzzJob, error)

	// SaveFuzzResult persists a single fuzz result.
	SaveFuzzResult(ctx context.Context, result *FuzzResult) error

	// ListFuzzResults retrieves results for a fuzz job with optional filtering.
	ListFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) ([]*FuzzResult, error)
}

// FuzzResultListOptions configures fuzz result listing behavior.
type FuzzResultListOptions struct {
	// StatusCode filters results by HTTP status code (0 means no filter).
	StatusCode int
	// Limit is the maximum number of results to return (0 means no limit).
	Limit int
	// Offset is the number of results to skip for pagination.
	Offset int
}

// SaveFuzzJob persists a new fuzz job.
func (s *SQLiteStore) SaveFuzzJob(ctx context.Context, job *FuzzJob) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		var completedAt *string
		if job.CompletedAt != nil {
			t := job.CompletedAt.UTC().Format(time.RFC3339Nano)
			completedAt = &t
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO fuzz_jobs (id, session_id, config, status, tag, created_at, completed_at, total, completed_count, error_count)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			job.ID,
			job.SessionID,
			job.Config,
			job.Status,
			job.Tag,
			job.CreatedAt.UTC().Format(time.RFC3339Nano),
			completedAt,
			job.Total,
			job.CompletedCount,
			job.ErrorCount,
		)
		if err != nil {
			return fmt.Errorf("insert fuzz job: %w", err)
		}
		return nil
	})
}

// UpdateFuzzJob updates the mutable fields of a fuzz job.
func (s *SQLiteStore) UpdateFuzzJob(ctx context.Context, job *FuzzJob) error {
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		var completedAt *string
		if job.CompletedAt != nil {
			t := job.CompletedAt.UTC().Format(time.RFC3339Nano)
			completedAt = &t
		}
		_, err := s.db.ExecContext(ctx,
			`UPDATE fuzz_jobs SET status = ?, completed_at = ?, total = ?, completed_count = ?, error_count = ? WHERE id = ?`,
			job.Status,
			completedAt,
			job.Total,
			job.CompletedCount,
			job.ErrorCount,
			job.ID,
		)
		if err != nil {
			return fmt.Errorf("update fuzz job %s: %w", job.ID, err)
		}
		return nil
	})
}

// GetFuzzJob retrieves a fuzz job by ID.
func (s *SQLiteStore) GetFuzzJob(ctx context.Context, id string) (*FuzzJob, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, session_id, config, status, tag, created_at, completed_at, total, completed_count, error_count FROM fuzz_jobs WHERE id = ?`, id)
	return scanFuzzJob(row)
}

// SaveFuzzResult persists a single fuzz result.
func (s *SQLiteStore) SaveFuzzResult(ctx context.Context, result *FuzzResult) error {
	if result.ID == "" {
		result.ID = uuid.New().String()
	}
	return s.enqueueWrite(ctx, func(ctx context.Context) error {
		var errStr *string
		if result.Error != "" {
			errStr = &result.Error
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO fuzz_results (id, fuzz_id, index_num, session_id, payloads, status_code, response_length, duration_ms, error)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			result.ID,
			result.FuzzID,
			result.IndexNum,
			result.SessionID,
			result.Payloads,
			result.StatusCode,
			result.ResponseLength,
			result.DurationMs,
			errStr,
		)
		if err != nil {
			return fmt.Errorf("insert fuzz result: %w", err)
		}
		return nil
	})
}

// ListFuzzResults retrieves results for a fuzz job with optional filtering.
func (s *SQLiteStore) ListFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) ([]*FuzzResult, error) {
	query := `SELECT id, fuzz_id, index_num, session_id, payloads, status_code, response_length, duration_ms, error FROM fuzz_results WHERE fuzz_id = ?`
	args := []interface{}{fuzzID}

	if opts.StatusCode != 0 {
		query += " AND status_code = ?"
		args = append(args, opts.StatusCode)
	}

	query += " ORDER BY index_num ASC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list fuzz results: %w", err)
	}
	defer rows.Close()

	var results []*FuzzResult
	for rows.Next() {
		r, err := scanFuzzResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func scanFuzzJob(row scannable) (*FuzzJob, error) {
	var (
		job          FuzzJob
		createdAtStr string
		completedAt  sql.NullString
	)

	err := row.Scan(
		&job.ID,
		&job.SessionID,
		&job.Config,
		&job.Status,
		&job.Tag,
		&createdAtStr,
		&completedAt,
		&job.Total,
		&job.CompletedCount,
		&job.ErrorCount,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("fuzz job not found")
		}
		return nil, fmt.Errorf("scan fuzz job: %w", err)
	}

	ts, err := time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	job.CreatedAt = ts

	if completedAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, completedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse completed_at: %w", err)
		}
		job.CompletedAt = &t
	}

	return &job, nil
}

func scanFuzzResult(row scannable) (*FuzzResult, error) {
	var (
		result FuzzResult
		errStr sql.NullString
	)

	err := row.Scan(
		&result.ID,
		&result.FuzzID,
		&result.IndexNum,
		&result.SessionID,
		&result.Payloads,
		&result.StatusCode,
		&result.ResponseLength,
		&result.DurationMs,
		&errStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("fuzz result not found")
		}
		return nil, fmt.Errorf("scan fuzz result: %w", err)
	}

	if errStr.Valid {
		result.Error = errStr.String
	}

	return &result, nil
}

// PayloadsToJSON converts a map of position ID to payload value into JSON string.
func PayloadsToJSON(payloads map[string]string) string {
	b, err := json.Marshal(payloads)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// PayloadsFromJSON parses a JSON string into a map of position ID to payload value.
func PayloadsFromJSON(s string) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("parse payloads JSON: %w", err)
	}
	return m, nil
}
