package mcp

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/usk6666/yorishiro-proxy/internal/bodydecode"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// fuzz_results filter.body_contains is evaluated here rather than in SQL.
// flows.body stores the wire bytes, still Content-Encoded (gzip / deflate /
// br / zstd), so a substring match has to look at the decoded form as well.
// Decoding mirrors the read path of the query tool (findContentEncoding +
// bodydecode.Decode with the same 16 MiB cap); the stored bytes are never
// modified.

// filterFuzzResultsByBody returns, in input order, the results whose variant
// stream has at least one receive flow whose body contains needle — either in
// the raw stored bytes or in the Content-Encoding-decoded bytes. A store error
// for any candidate aborts the filter: silently dropping a candidate would
// turn into a missed reflection.
func (s *Server) filterFuzzResultsByBody(ctx context.Context, results []*flow.FuzzResult, needle string) ([]*flow.FuzzResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("body_contains: flow store is not initialized")
	}
	n := []byte(needle)
	matched := make([]*flow.FuzzResult, 0, len(results))
	for _, r := range results {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("body_contains: %w", err)
		}
		if r.StreamID == "" {
			continue
		}
		ok, err := s.streamReceiveBodyContains(ctx, r.StreamID, n)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, r)
		}
	}
	return matched, nil
}

// streamReceiveBodyContains reports whether any receive-direction flow of the
// stream carries needle in its raw or decoded body. It stops at the first hit.
func (s *Server) streamReceiveBodyContains(ctx context.Context, streamID string, needle []byte) (bool, error) {
	flows, err := s.flowStore.store.GetFlows(ctx, streamID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		return false, fmt.Errorf("body_contains: get flows %s: %w", streamID, err)
	}
	for _, f := range flows {
		if bodyContainsDecoded(f.Body, f.Headers, needle) {
			return true, nil
		}
	}
	return false, nil
}

// bodyContainsDecoded matches needle against the raw body first, then against
// the Content-Encoding-decoded body. On a decode anomaly (stacked or unknown
// coding, malformed or truncated stream, size cap exceeded) only the raw bytes
// are searched, exactly as the query tool falls back to the wire form.
func bodyContainsDecoded(raw []byte, headers map[string][]string, needle []byte) bool {
	if bytes.Contains(raw, needle) {
		return true
	}
	if len(raw) == 0 {
		return false
	}
	ce := findContentEncoding(headers)
	if ce == "" {
		return false
	}
	decoded, applied, anomaly := bodydecode.Decode(raw, ce, bodydecode.DefaultMaxDecodedSize)
	if anomaly != nil || applied == "" {
		return false
	}
	return bytes.Contains(decoded, needle)
}

// paginateFuzzResults returns results[offset:offset+limit], bounds-safe.
// limit <= 0 means no limit.
func paginateFuzzResults(results []*flow.FuzzResult, offset, limit int) []*flow.FuzzResult {
	if offset >= len(results) {
		return nil
	}
	end := len(results)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return results[offset:end]
}

// handleQueryFuzzResultsByBody serves fuzz_results when filter.body_contains is
// set. Candidates come from the store with the SQL-expressible predicates and
// the requested sort order but without pagination; the body filter runs in Go,
// and total / summary / outliers_only / pagination are all computed over the
// matched set so they stay consistent with each other.
func (s *Server) handleQueryFuzzResultsByBody(ctx context.Context, input queryInput, opts flow.FuzzResultListOptions, needle string, outliersOnly bool) (any, error) {
	limit, offset := opts.Limit, opts.Offset
	allOpts := opts
	allOpts.Limit = 0
	allOpts.Offset = 0

	candidates, err := s.jobRunner.fuzzStore.ListFuzzResults(ctx, input.FuzzID, allOpts)
	if err != nil {
		return nil, fmt.Errorf("list fuzz results: %w", err)
	}
	matched, err := s.filterFuzzResultsByBody(ctx, candidates, needle)
	if err != nil {
		return nil, err
	}

	// The summary is computed in index order, as buildFuzzResultsSummary
	// does, so outlier ID lists do not depend on sort_by.
	byIndex := make([]*flow.FuzzResult, len(matched))
	copy(byIndex, matched)
	sort.SliceStable(byIndex, func(i, j int) bool { return byIndex[i].IndexNum < byIndex[j].IndexNum })
	summary := summarizeFuzzResults(byIndex)

	if outliersOnly && summary.Outliers != nil {
		ids := collectOutlierIDs(summary.Outliers)
		keep := make(map[string]bool, len(ids))
		for _, id := range ids {
			keep[id] = true
		}
		outliers := matched[:0:0]
		for _, r := range matched {
			if keep[r.ID] {
				outliers = append(outliers, r)
			}
		}
		matched = outliers
	}

	page := paginateFuzzResults(matched, offset, limit)
	entries := make([]queryFuzzResultEntry, 0, len(page))
	for _, r := range page {
		entries = append(entries, fuzzResultToEntry(r))
	}
	result := &queryFuzzResultsResult{
		Results: entries,
		Count:   len(entries),
		Total:   len(matched),
		Summary: summary,
	}
	return applyFieldsFilter(result, input.Fields), nil
}
