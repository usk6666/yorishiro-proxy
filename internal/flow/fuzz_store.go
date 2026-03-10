package flow

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
	// FlowID is the template flow used for fuzzing.
	FlowID string
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
	// FlowID is the ID of the flow recorded for this iteration.
	FlowID string
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

	// ListFuzzJobs retrieves fuzz jobs with optional filtering and pagination.
	ListFuzzJobs(ctx context.Context, opts FuzzJobListOptions) ([]*FuzzJob, error)

	// CountFuzzJobs returns the total number of fuzz jobs matching the given options,
	// ignoring Limit and Offset.
	CountFuzzJobs(ctx context.Context, opts FuzzJobListOptions) (int, error)

	// SaveFuzzResult persists a single fuzz result.
	SaveFuzzResult(ctx context.Context, result *FuzzResult) error

	// ListFuzzResults retrieves results for a fuzz job with optional filtering.
	ListFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) ([]*FuzzResult, error)

	// CountFuzzResults returns the total number of results for a fuzz job
	// matching the given filter options, ignoring Limit and Offset.
	CountFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) (int, error)
}

// FuzzResultListOptions configures fuzz result listing behavior.
type FuzzResultListOptions struct {
	// StatusCode filters results by HTTP status code (0 means no filter).
	StatusCode int
	// BodyContains filters results whose response body (in the linked flow message)
	// contains this substring. Empty string means no filter.
	BodyContains string
	// ResultIDs filters results to only those whose ID is in this set.
	// When non-nil and non-empty, an IN clause is added to the query.
	ResultIDs []string
	// SortBy specifies the column to sort results by (e.g. "status_code", "duration_ms", "index_num").
	// Default is "index_num".
	SortBy string
	// Limit is the maximum number of results to return (0 means no limit).
	Limit int
	// Offset is the number of results to skip for pagination.
	Offset int
}

// FuzzJobListOptions configures fuzz job listing behavior.
type FuzzJobListOptions struct {
	// Status filters jobs by status (e.g. "running", "completed").
	Status string
	// Tag filters jobs by tag (exact match).
	Tag string
	// Limit is the maximum number of jobs to return (0 means no limit).
	Limit int
	// Offset is the number of jobs to skip for pagination.
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
			`INSERT INTO fuzz_jobs (id, flow_id, config, status, tag, created_at, completed_at, total, completed_count, error_count)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			job.ID,
			job.FlowID,
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
		`SELECT id, flow_id, config, status, tag, created_at, completed_at, total, completed_count, error_count FROM fuzz_jobs WHERE id = ?`, id)
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
			`INSERT INTO fuzz_results (id, fuzz_id, index_num, flow_id, payloads, status_code, response_length, duration_ms, error)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			result.ID,
			result.FuzzID,
			result.IndexNum,
			result.FlowID,
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

// validFuzzResultSortColumns maps allowed sort_by values to SQL column names.
var validFuzzResultSortColumns = map[string]string{
	"index_num":       "index_num",
	"status_code":     "status_code",
	"duration_ms":     "duration_ms",
	"response_length": "response_length",
}

// fuzzResultWhereClause builds the WHERE clause and args for fuzz result queries.
func fuzzResultWhereClause(fuzzID string, opts FuzzResultListOptions) (string, []interface{}) {
	where := " WHERE fuzz_id = ?"
	args := []interface{}{fuzzID}

	if opts.StatusCode != 0 {
		where += " AND status_code = ?"
		args = append(args, opts.StatusCode)
	}
	if opts.BodyContains != "" {
		// Join with messages table to filter by response body content.
		// Use CAST to convert BLOB body to TEXT for substring matching.
		where += ` AND EXISTS (
			SELECT 1 FROM messages m
			WHERE m.flow_id = fuzz_results.flow_id
			  AND m.direction = 'receive'
			  AND INSTR(CAST(m.body AS TEXT), ?) > 0
		)`
		args = append(args, opts.BodyContains)
	}
	if len(opts.ResultIDs) > 0 {
		placeholders := ""
		for i, id := range opts.ResultIDs {
			if i > 0 {
				placeholders += ", "
			}
			placeholders += "?"
			args = append(args, id)
		}
		where += " AND id IN (" + placeholders + ")"
	}
	return where, args
}

// fuzzResultOrderClause returns the ORDER BY clause for fuzz result queries.
func fuzzResultOrderClause(sortBy string) string {
	if col, ok := validFuzzResultSortColumns[sortBy]; ok {
		return " ORDER BY " + col + " ASC"
	}
	return " ORDER BY index_num ASC"
}

// ListFuzzResults retrieves results for a fuzz job with optional filtering.
func (s *SQLiteStore) ListFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) ([]*FuzzResult, error) {
	where, args := fuzzResultWhereClause(fuzzID, opts)
	query := `SELECT id, fuzz_id, index_num, flow_id, payloads, status_code, response_length, duration_ms, error FROM fuzz_results` + where
	query += fuzzResultOrderClause(opts.SortBy)

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

// CountFuzzResults returns the total number of results for a fuzz job
// matching the given filter options, ignoring Limit and Offset.
func (s *SQLiteStore) CountFuzzResults(ctx context.Context, fuzzID string, opts FuzzResultListOptions) (int, error) {
	where, args := fuzzResultWhereClause(fuzzID, opts)
	query := `SELECT COUNT(*) FROM fuzz_results` + where

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count fuzz results: %w", err)
	}
	return count, nil
}

// ListFuzzJobs retrieves fuzz jobs with optional filtering and pagination.
func (s *SQLiteStore) ListFuzzJobs(ctx context.Context, opts FuzzJobListOptions) ([]*FuzzJob, error) {
	query := `SELECT id, flow_id, config, status, tag, created_at, completed_at, total, completed_count, error_count FROM fuzz_jobs WHERE 1=1`
	args := []interface{}{}

	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.Tag != "" {
		query += " AND tag = ?"
		args = append(args, opts.Tag)
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list fuzz jobs: %w", err)
	}
	defer rows.Close()

	var jobs []*FuzzJob
	for rows.Next() {
		j, err := scanFuzzJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// CountFuzzJobs returns the total number of fuzz jobs matching the given options,
// ignoring Limit and Offset.
func (s *SQLiteStore) CountFuzzJobs(ctx context.Context, opts FuzzJobListOptions) (int, error) {
	query := `SELECT COUNT(*) FROM fuzz_jobs WHERE 1=1`
	args := []interface{}{}

	if opts.Status != "" {
		query += " AND status = ?"
		args = append(args, opts.Status)
	}
	if opts.Tag != "" {
		query += " AND tag = ?"
		args = append(args, opts.Tag)
	}

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count fuzz jobs: %w", err)
	}
	return count, nil
}

func scanFuzzJob(row scannable) (*FuzzJob, error) {
	var (
		job          FuzzJob
		createdAtStr string
		completedAt  sql.NullString
	)

	err := row.Scan(
		&job.ID,
		&job.FlowID,
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
		&result.FlowID,
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
