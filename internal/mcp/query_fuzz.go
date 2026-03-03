package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- fuzz_jobs resource ---

// queryFuzzJobEntry is a single fuzz job entry in the fuzz_jobs query response.
type queryFuzzJobEntry struct {
	ID             string  `json:"id"`
	SessionID      string  `json:"session_id"`
	Status         string  `json:"status"`
	Tag            string  `json:"tag"`
	Total          int     `json:"total"`
	CompletedCount int     `json:"completed_count"`
	ErrorCount     int     `json:"error_count"`
	CreatedAt      string  `json:"created_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
}

// queryFuzzJobsResult is the response for the fuzz_jobs resource.
type queryFuzzJobsResult struct {
	Jobs  []queryFuzzJobEntry `json:"jobs"`
	Count int                 `json:"count"`
	Total int                 `json:"total"`
}

// handleQueryFuzzJobs returns a paginated list of fuzz jobs with optional filtering.
func (s *Server) handleQueryFuzzJobs(ctx context.Context, input queryInput) (*gomcp.CallToolResult, any, error) {
	if s.deps.fuzzStore == nil {
		return nil, nil, fmt.Errorf("fuzz store is not initialized")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := session.FuzzJobListOptions{
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.Status = input.Filter.Status
		opts.Tag = input.Filter.Tag
	}

	jobs, err := s.deps.fuzzStore.ListFuzzJobs(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list fuzz jobs: %w", err)
	}

	total, err := s.deps.fuzzStore.CountFuzzJobs(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count fuzz jobs: %w", err)
	}

	entries := make([]queryFuzzJobEntry, 0, len(jobs))
	for _, job := range jobs {
		entry := queryFuzzJobEntry{
			ID:             job.ID,
			SessionID:      job.SessionID,
			Status:         job.Status,
			Tag:            job.Tag,
			Total:          job.Total,
			CompletedCount: job.CompletedCount,
			ErrorCount:     job.ErrorCount,
			CreatedAt:      job.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if job.CompletedAt != nil {
			s := job.CompletedAt.UTC().Format("2006-01-02T15:04:05Z")
			entry.CompletedAt = &s
		}
		entries = append(entries, entry)
	}

	result := &queryFuzzJobsResult{
		Jobs:  entries,
		Count: len(entries),
		Total: total,
	}

	if len(input.Fields) > 0 {
		return nil, filterFields(result, input.Fields), nil
	}
	return nil, result, nil
}

// --- fuzz_results resource ---

// queryFuzzResultEntry is a single fuzz result entry in the fuzz_results query response.
type queryFuzzResultEntry struct {
	ID             string            `json:"id"`
	FuzzID         string            `json:"fuzz_id"`
	IndexNum       int               `json:"index"`
	SessionID      string            `json:"session_id"`
	Payloads       map[string]string `json:"payloads"`
	StatusCode     int               `json:"status_code"`
	ResponseLength int               `json:"response_length"`
	DurationMs     int               `json:"duration_ms"`
	Error          string            `json:"error,omitempty"`
}

// queryFuzzResultsSummary provides aggregate stats for fuzz results.
type queryFuzzResultsSummary struct {
	StatusDistribution map[string]int `json:"status_distribution"`
	AvgDurationMs      int            `json:"avg_duration_ms"`
	TotalDurationMs    int            `json:"total_duration_ms"`
}

// queryFuzzResultsResult is the response for the fuzz_results resource.
type queryFuzzResultsResult struct {
	Results []queryFuzzResultEntry   `json:"results"`
	Count   int                      `json:"count"`
	Total   int                      `json:"total"`
	Summary *queryFuzzResultsSummary `json:"summary"`
}

// handleQueryFuzzResults returns fuzz results for a specific job with filtering, sorting, and summary.
func (s *Server) handleQueryFuzzResults(ctx context.Context, input queryInput) (*gomcp.CallToolResult, any, error) {
	if s.deps.fuzzStore == nil {
		return nil, nil, fmt.Errorf("fuzz store is not initialized")
	}

	if input.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_results resource")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := session.FuzzResultListOptions{
		SortBy: input.SortBy,
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.StatusCode = input.Filter.StatusCode
		opts.BodyContains = input.Filter.BodyContains
	}

	results, err := s.deps.fuzzStore.ListFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list fuzz results: %w", err)
	}

	total, err := s.deps.fuzzStore.CountFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count fuzz results: %w", err)
	}

	// Build summary from all matching results (not just the current page).
	summary, err := s.buildFuzzResultsSummary(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("build fuzz results summary: %w", err)
	}

	entries := make([]queryFuzzResultEntry, 0, len(results))
	for _, r := range results {
		payloads := make(map[string]string)
		if r.Payloads != "" {
			// Best-effort parse; if it fails, return empty map.
			if err := json.Unmarshal([]byte(r.Payloads), &payloads); err != nil {
				slog.Warn("failed to parse fuzz result payloads", "result_id", r.ID, "error", err)
			}
		}

		entries = append(entries, queryFuzzResultEntry{
			ID:             r.ID,
			FuzzID:         r.FuzzID,
			IndexNum:       r.IndexNum,
			SessionID:      r.SessionID,
			Payloads:       payloads,
			StatusCode:     r.StatusCode,
			ResponseLength: r.ResponseLength,
			DurationMs:     r.DurationMs,
			Error:          r.Error,
		})
	}

	result := &queryFuzzResultsResult{
		Results: entries,
		Count:   len(entries),
		Total:   total,
		Summary: summary,
	}

	if len(input.Fields) > 0 {
		return nil, filterFields(result, input.Fields), nil
	}
	return nil, result, nil
}

// buildFuzzResultsSummary computes aggregate statistics for fuzz results.
// It fetches all matching results (without pagination) to compute the summary.
func (s *Server) buildFuzzResultsSummary(ctx context.Context, fuzzID string, opts session.FuzzResultListOptions) (*queryFuzzResultsSummary, error) {
	// Fetch all matching results without pagination for summary computation.
	allOpts := opts
	allOpts.Limit = 0
	allOpts.Offset = 0
	// Use default sort for summary; we don't need specific ordering.
	allOpts.SortBy = ""

	allResults, err := s.deps.fuzzStore.ListFuzzResults(ctx, fuzzID, allOpts)
	if err != nil {
		return nil, fmt.Errorf("list all fuzz results for summary: %w", err)
	}

	summary := &queryFuzzResultsSummary{
		StatusDistribution: make(map[string]int),
	}

	totalDuration := 0
	for _, r := range allResults {
		key := fmt.Sprintf("%d", r.StatusCode)
		summary.StatusDistribution[key]++
		totalDuration += r.DurationMs
	}

	summary.TotalDurationMs = totalDuration
	if len(allResults) > 0 {
		summary.AvgDurationMs = totalDuration / len(allResults)
	}

	return summary, nil
}

// filterFields converts the result to a map and removes fields not in the requested list.
// It preserves "summary", "count", and "total" metadata fields regardless of the fields list.
func filterFields(result any, fields []string) any {
	data, err := json.Marshal(result)
	if err != nil {
		return result
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return result
	}

	// Build a set of requested fields.
	requested := make(map[string]bool, len(fields))
	for _, f := range fields {
		requested[f] = true
	}

	// Metadata fields that are always preserved.
	metadataFields := map[string]bool{
		"summary": true,
		"count":   true,
		"total":   true,
	}

	// For collections (jobs, results), filter the array items' fields.
	// Identify the collection key (jobs or results).
	collectionKeys := []string{"jobs", "results"}
	for _, key := range collectionKeys {
		raw, ok := m[key]
		if !ok {
			continue
		}

		var items []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			continue
		}

		filtered := make([]map[string]json.RawMessage, 0, len(items))
		for _, item := range items {
			newItem := make(map[string]json.RawMessage)
			for k, v := range item {
				if requested[k] {
					newItem[k] = v
				}
			}
			filtered = append(filtered, newItem)
		}

		filteredData, err := json.Marshal(filtered)
		if err != nil {
			continue
		}
		m[key] = filteredData
	}

	// Remove top-level keys that are not metadata and not in the collection.
	for k := range m {
		if metadataFields[k] {
			continue
		}
		isCollection := false
		for _, ck := range collectionKeys {
			if k == ck {
				isCollection = true
				break
			}
		}
		if !isCollection {
			delete(m, k)
		}
	}

	return m
}
