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

// distributionStats holds min/max/median/stddev statistics for a numeric field.
type distributionStats struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Median float64 `json:"median"`
	Stddev float64 `json:"stddev"`
}

// fuzzStatistics holds aggregate statistics for fuzz results.
type fuzzStatistics struct {
	StatusCodeDistribution map[string]int     `json:"status_code_distribution"`
	BodyLength             *distributionStats `json:"body_length"`
	TimingMs               *distributionStats `json:"timing_ms"`
}

// fuzzOutliers holds IDs of fuzz results that are outliers.
type fuzzOutliers struct {
	ByStatusCode []string `json:"by_status_code"`
	ByBodyLength []string `json:"by_body_length"`
	ByTiming     []string `json:"by_timing"`
}

// queryFuzzResultsSummary provides aggregate stats for fuzz results.
type queryFuzzResultsSummary struct {
	TotalResults int             `json:"total_results"`
	Statistics   *fuzzStatistics `json:"statistics"`
	Outliers     *fuzzOutliers   `json:"outliers"`
}

// queryFuzzResultsResult is the response for the fuzz_results resource.
type queryFuzzResultsResult struct {
	Results []queryFuzzResultEntry   `json:"results"`
	Count   int                      `json:"count"`
	Total   int                      `json:"total"`
	Summary *queryFuzzResultsSummary `json:"summary"`
}

// buildFuzzResultListOptions constructs FuzzResultListOptions from query input.
func buildFuzzResultListOptions(input queryInput) flow.FuzzResultListOptions {
	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	opts := flow.FuzzResultListOptions{
		SortBy: input.SortBy,
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.StatusCode = input.Filter.StatusCode
		opts.BodyContains = input.Filter.BodyContains
	}
	return opts
}

// fuzzResultToEntry converts a flow.FuzzResult to a queryFuzzResultEntry.
func fuzzResultToEntry(r *flow.FuzzResult) queryFuzzResultEntry {
	payloads := make(map[string]string)
	if r.Payloads != "" {
		if err := json.Unmarshal([]byte(r.Payloads), &payloads); err != nil {
			slog.Warn("failed to parse fuzz result payloads", "result_id", r.ID, "error", err)
		}
	}
	return queryFuzzResultEntry{
		ID:             r.ID,
		FuzzID:         r.FuzzID,
		IndexNum:       r.IndexNum,
		FlowID:         r.FlowID,
		Payloads:       payloads,
		StatusCode:     r.StatusCode,
		ResponseLength: r.ResponseLength,
		DurationMs:     r.DurationMs,
		Error:          r.Error,
	}
}

// filterByOutliers filters results to only include those in the outlier ID set.
func filterByOutliers(results []*flow.FuzzResult, outlierIDSet map[string]bool) []queryFuzzResultEntry {
	entries := make([]queryFuzzResultEntry, 0)
	for _, r := range results {
		if outlierIDSet[r.ID] {
			entries = append(entries, fuzzResultToEntry(r))
		}
	}
	return entries
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

	opts := buildFuzzResultListOptions(input)

	summary, err := s.buildFuzzResultsSummary(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("build fuzz results summary: %w", err)
	}

	results, err := s.deps.fuzzStore.ListFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list fuzz results: %w", err)
	}

	total, err := s.deps.fuzzStore.CountFuzzResults(ctx, input.FuzzID, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count fuzz results: %w", err)
	}

	outliersOnly := input.Filter != nil && input.Filter.OutliersOnly
	var entries []queryFuzzResultEntry
	if outliersOnly && summary.Outliers != nil {
		entries = filterByOutliers(results, buildOutlierIDSet(summary.Outliers))
		total = len(entries)
	} else {
		entries = make([]queryFuzzResultEntry, 0, len(results))
		for _, r := range results {
			entries = append(entries, fuzzResultToEntry(r))
		}
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

// buildOutlierIDSet collects all outlier result IDs into a set.
func buildOutlierIDSet(outliers *fuzzOutliers) map[string]bool {
	set := make(map[string]bool)
	for _, id := range outliers.ByStatusCode {
		set[id] = true
	}
	for _, id := range outliers.ByBodyLength {
		set[id] = true
	}
	for _, id := range outliers.ByTiming {
		set[id] = true
	}
	return set
}

// buildFuzzResultsSummary computes aggregate statistics and outlier detection for fuzz results.
// It fetches all matching results (without pagination) to compute the summary.
func (s *Server) buildFuzzResultsSummary(ctx context.Context, fuzzID string, opts flow.FuzzResultListOptions) (*queryFuzzResultsSummary, error) {
	// Fetch all matching results without pagination for summary computation.
	allOpts := opts
	allOpts.Limit = 0
	allOpts.Offset = 0
	allOpts.SortBy = ""

	allResults, err := s.deps.fuzzStore.ListFuzzResults(ctx, fuzzID, allOpts)
	if err != nil {
		return nil, fmt.Errorf("list all fuzz results for summary: %w", err)
	}

	stats := &fuzzStatistics{
		StatusCodeDistribution: make(map[string]int),
	}

	if len(allResults) == 0 {
		return &queryFuzzResultsSummary{
			TotalResults: 0,
			Statistics:   stats,
			Outliers: &fuzzOutliers{
				ByStatusCode: []string{},
				ByBodyLength: []string{},
				ByTiming:     []string{},
			},
		}, nil
	}

	// Collect values for distribution computation.
	bodyLengths := make([]float64, 0, len(allResults))
	timings := make([]float64, 0, len(allResults))

	for _, r := range allResults {
		key := fmt.Sprintf("%d", r.StatusCode)
		stats.StatusCodeDistribution[key]++
		bodyLengths = append(bodyLengths, float64(r.ResponseLength))
		timings = append(timings, float64(r.DurationMs))
	}

	stats.BodyLength = computeDistribution(bodyLengths)
	stats.TimingMs = computeDistribution(timings)

	// Detect outliers.
	outliers := detectOutliers(allResults, stats)

	return &queryFuzzResultsSummary{
		TotalResults: len(allResults),
		Statistics:   stats,
		Outliers:     outliers,
	}, nil
}

// computeDistribution calculates min, max, median, and stddev for a set of values.
func computeDistribution(values []float64) *distributionStats {
	if len(values) == 0 {
		return &distributionStats{}
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	n := len(sorted)
	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(n)

	// Median.
	var median float64
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2.0
	} else {
		median = sorted[n/2]
	}

	// Standard deviation (population).
	variance := 0.0
	for _, v := range sorted {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(n)
	stddev := math.Sqrt(variance)

	return &distributionStats{
		Min:    sorted[0],
		Max:    sorted[n-1],
		Median: math.Round(median*100) / 100,
		Stddev: math.Round(stddev*100) / 100,
	}
}

// detectOutliers identifies fuzz results that deviate from the baseline.
// Status code: any result with a status code different from the most frequent one.
// Body length: results outside median +/- 2*stddev.
// Timing: results outside median +/- 2*stddev.
func detectOutliers(results []*flow.FuzzResult, stats *fuzzStatistics) *fuzzOutliers {
	outliers := &fuzzOutliers{
		ByStatusCode: []string{},
		ByBodyLength: []string{},
		ByTiming:     []string{},
	}

	// Find the most frequent status code (baseline).
	baselineStatus := ""
	maxCount := 0
	for code, count := range stats.StatusCodeDistribution {
		if count > maxCount {
			maxCount = count
			baselineStatus = code
		}
	}

	for _, r := range results {
		code := fmt.Sprintf("%d", r.StatusCode)
		if code != baselineStatus {
			outliers.ByStatusCode = append(outliers.ByStatusCode, r.ID)
		}

		if stats.BodyLength != nil && stats.BodyLength.Stddev > 0 {
			bl := float64(r.ResponseLength)
			if bl < stats.BodyLength.Median-2*stats.BodyLength.Stddev || bl > stats.BodyLength.Median+2*stats.BodyLength.Stddev {
				outliers.ByBodyLength = append(outliers.ByBodyLength, r.ID)
			}
		}

		if stats.TimingMs != nil && stats.TimingMs.Stddev > 0 {
			t := float64(r.DurationMs)
			if t < stats.TimingMs.Median-2*stats.TimingMs.Stddev || t > stats.TimingMs.Median+2*stats.TimingMs.Stddev {
				outliers.ByTiming = append(outliers.ByTiming, r.ID)
			}
		}
	}

	return outliers
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
