package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- fuzz_jobs resource ---

// queryFuzzJobEntry is a single fuzz job entry in the fuzz_jobs query response.
type queryFuzzJobEntry struct {
	ID             string  `json:"id"`
	FlowID         string  `json:"flow_id"`
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

	opts := flow.FuzzJobListOptions{
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
			FlowID:         job.FlowID,
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
	FlowID         string            `json:"flow_id"`
	Payloads       map[string]string `json:"payloads"`
	StatusCode     int               `json:"status_code"`
	ResponseLength int               `json:"response_length"`
	DurationMs     int               `json:"duration_ms"`
	Error          string            `json:"error,omitempty"`
}

// distributionStats holds min, max, median, and standard deviation for a numeric metric.
type distributionStats struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Median float64 `json:"median"`
	Stddev float64 `json:"stddev"`
}

// outlierSets holds result IDs grouped by the outlier detection criteria.
type outlierSets struct {
	ByStatusCode []string `json:"by_status_code"`
	ByBodyLength []string `json:"by_body_length"`
	ByTiming     []string `json:"by_timing"`
}

// queryFuzzResultsSummary provides aggregate stats for fuzz results.
type queryFuzzResultsSummary struct {
	TotalResults           int                `json:"total_results"`
	StatusCodeDistribution map[string]int     `json:"status_code_distribution"`
	BodyLength             *distributionStats `json:"body_length"`
	TimingMs               *distributionStats `json:"timing_ms"`
	Outliers               *outlierSets       `json:"outliers"`
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

	// Build summary from all results for the job (pre-filter).
	summary, err := s.buildFuzzResultsSummary(ctx, input.FuzzID)
	if err != nil {
		return nil, nil, fmt.Errorf("build fuzz results summary: %w", err)
	}

	opts := flow.FuzzResultListOptions{
		SortBy: input.SortBy,
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.StatusCode = input.Filter.StatusCode
		opts.BodyContains = input.Filter.BodyContains
		if input.Filter.OutliersOnly {
			opts.OutliersOnly = true
			opts.OutlierIDs = collectAllOutlierIDs(summary)
		}
	}

	results, err := s.deps.fuzzStore.ListFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list fuzz results: %w", err)
	}

	total, err := s.deps.fuzzStore.CountFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count fuzz results: %w", err)
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
			FlowID:         r.FlowID,
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

// collectAllOutlierIDs merges all outlier ID lists into a single set.
func collectAllOutlierIDs(summary *queryFuzzResultsSummary) map[string]bool {
	if summary == nil || summary.Outliers == nil {
		return nil
	}
	ids := make(map[string]bool)
	for _, id := range summary.Outliers.ByStatusCode {
		ids[id] = true
	}
	for _, id := range summary.Outliers.ByBodyLength {
		ids[id] = true
	}
	for _, id := range summary.Outliers.ByTiming {
		ids[id] = true
	}
	return ids
}

// buildFuzzResultsSummary computes aggregate statistics and outlier detection
// for all results in a fuzz job using the efficient raw stats query.
func (s *Server) buildFuzzResultsSummary(ctx context.Context, fuzzID string) (*queryFuzzResultsSummary, error) {
	rawRows, err := s.deps.fuzzStore.GetFuzzResultRawStats(ctx, fuzzID)
	if err != nil {
		return nil, fmt.Errorf("get fuzz result raw stats: %w", err)
	}

	summary := &queryFuzzResultsSummary{
		TotalResults:           len(rawRows),
		StatusCodeDistribution: make(map[string]int),
		Outliers:               &outlierSets{},
	}

	if len(rawRows) == 0 {
		return summary, nil
	}

	// Collect data for distribution computation.
	bodyLengths := make([]float64, len(rawRows))
	timings := make([]float64, len(rawRows))
	statusCounts := make(map[int]int)

	for i, r := range rawRows {
		statusCounts[r.StatusCode]++
		bodyLengths[i] = float64(r.ResponseLength)
		timings[i] = float64(r.DurationMs)
	}

	// Status code distribution.
	for code, count := range statusCounts {
		summary.StatusCodeDistribution[fmt.Sprintf("%d", code)] = count
	}

	// Body length stats.
	summary.BodyLength = computeDistributionStats(bodyLengths)

	// Timing stats.
	summary.TimingMs = computeDistributionStats(timings)

	// Outlier detection.
	summary.Outliers = detectOutliers(rawRows, statusCounts, summary.BodyLength, summary.TimingMs)

	return summary, nil
}

// detectOutliers identifies outlier results by status code, body length, and timing.
func detectOutliers(rows []flow.FuzzResultRawRow, statusCounts map[int]int, bodyStats, timingStats *distributionStats) *outlierSets {
	out := &outlierSets{
		ByStatusCode: []string{},
		ByBodyLength: []string{},
		ByTiming:     []string{},
	}

	// Status code: baseline is the most frequent status code; others are outliers.
	baselineStatus := findMostFrequent(statusCounts)
	for _, r := range rows {
		if r.StatusCode != baselineStatus {
			out.ByStatusCode = append(out.ByStatusCode, r.ID)
		}
	}

	// Body length: median +/- 2*stddev.
	out.ByBodyLength = detectNumericOutliers(rows, bodyStats, func(r flow.FuzzResultRawRow) float64 {
		return float64(r.ResponseLength)
	})

	// Timing: median +/- 2*stddev.
	out.ByTiming = detectNumericOutliers(rows, timingStats, func(r flow.FuzzResultRawRow) float64 {
		return float64(r.DurationMs)
	})

	return out
}

// detectNumericOutliers returns IDs of rows whose value (extracted by valueFunc)
// falls outside median +/- 2*stddev. Returns empty slice if stats is nil or stddev is 0.
func detectNumericOutliers(rows []flow.FuzzResultRawRow, stats *distributionStats, valueFunc func(flow.FuzzResultRawRow) float64) []string {
	if stats == nil || stats.Stddev <= 0 {
		return []string{}
	}
	low := stats.Median - 2*stats.Stddev
	high := stats.Median + 2*stats.Stddev
	var ids []string
	for _, r := range rows {
		v := valueFunc(r)
		if v < low || v > high {
			ids = append(ids, r.ID)
		}
	}
	if ids == nil {
		return []string{}
	}
	return ids
}

// computeDistributionStats computes min, max, median, and standard deviation
// for the given values. Returns nil if values is empty.
func computeDistributionStats(values []float64) *distributionStats {
	n := len(values)
	if n == 0 {
		return nil
	}

	sorted := make([]float64, n)
	copy(sorted, values)
	sort.Float64s(sorted)

	minVal := sorted[0]
	maxVal := sorted[n-1]

	var median float64
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		median = sorted[n/2]
	}

	// Standard deviation (population).
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(n)

	var varianceSum float64
	for _, v := range values {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev := math.Sqrt(varianceSum / float64(n))

	return &distributionStats{
		Min:    minVal,
		Max:    maxVal,
		Median: median,
		Stddev: math.Round(stddev*10) / 10, // round to 1 decimal place
	}
}

// findMostFrequent returns the key with the highest count in the map.
func findMostFrequent(counts map[int]int) int {
	var maxKey, maxCount int
	for k, c := range counts {
		if c > maxCount || (c == maxCount && k < maxKey) {
			maxKey = k
			maxCount = c
		}
	}
	return maxKey
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

	// For collections (jobs, results), filter the array items' fields.
	collectionKeys := map[string]bool{"jobs": true, "results": true}
	for key := range collectionKeys {
		filterCollectionFields(m, key, requested)
	}

	// Remove top-level keys that are not metadata and not in the collection.
	removeNonMetadataKeys(m, collectionKeys)

	return m
}

// filterCollectionFields filters the fields of array items within a collection key.
func filterCollectionFields(m map[string]json.RawMessage, key string, requested map[string]bool) {
	raw, ok := m[key]
	if !ok {
		return
	}

	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return
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
		return
	}
	m[key] = filteredData
}

// metadataFields are top-level fields that are always preserved by filterFields.
var metadataFields = map[string]bool{
	"summary": true,
	"count":   true,
	"total":   true,
}

// removeNonMetadataKeys removes top-level keys that are not metadata and not collection keys.
func removeNonMetadataKeys(m map[string]json.RawMessage, collectionKeys map[string]bool) {
	for k := range m {
		if !metadataFields[k] && !collectionKeys[k] {
			delete(m, k)
		}
	}
}
