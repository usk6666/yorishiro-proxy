package mcp

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// fuzzBodyNeedle is the reflected marker the body_contains tests search for.
const fuzzBodyNeedle = "YP_XSS_7f3a<script>"

// fuzzBodyPlain returns a response body that contains the needle (when
// withNeedle is true) surrounded by repetitive padding, so every codec
// actually compresses it and the needle cannot survive verbatim in the
// encoded bytes (see assertNeedleHidden).
func fuzzBodyPlain(withNeedle bool) []byte {
	pad := strings.Repeat("lorem ipsum dolor sit amet ", 40)
	if withNeedle {
		return []byte("<html><body>" + pad + "<p>q=" + fuzzBodyNeedle + "</p>" + pad + "</body></html>")
	}
	return []byte("<html><body>" + pad + "<p>q=nothing-here</p>" + pad + "</body></html>")
}

// deflateForTest produces the spec-compliant HTTP deflate form (zlib-wrapped).
// Mirrors internal/bodydecode/decode_test.go deflateBytes.
func deflateForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// brotliForTest mirrors internal/bodydecode/decode_test.go brotliBytes.
func brotliForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// zstdForTest mirrors internal/bodydecode/decode_test.go zstdBytes.
func zstdForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// assertNeedleHidden guards the fixture precondition: the encoded wire bytes
// must not contain the needle verbatim, otherwise a raw-bytes match would make
// the test pass without exercising decoding.
func assertNeedleHidden(t *testing.T, encoded []byte) {
	t.Helper()
	if bytes.Contains(encoded, []byte(fuzzBodyNeedle)) {
		t.Fatalf("fixture precondition: encoded body contains the needle verbatim")
	}
}

// seedFuzzResultWire creates a fuzz result whose receive flow carries the
// given response headers and wire body bytes, in the shape RecordStep writes
// (Flow.Headers map + Flow.Body holding the still Content-Encoded bytes).
func seedFuzzResultWire(t *testing.T, store *flow.SQLiteStore, fuzzID string, index, statusCode, durationMs int, headers map[string][]string, body []byte) *flow.FuzzResult {
	t.Helper()
	ctx := context.Background()

	st := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	msg := &flow.Flow{
		ID:         st.ID + "-recv",
		StreamID:   st.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
	if err := store.SaveFlow(ctx, msg); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	result := &flow.FuzzResult{
		FuzzID:         fuzzID,
		IndexNum:       index,
		StreamID:       st.ID,
		Payloads:       fmt.Sprintf(`{"pos-0":"payload-%d"}`, index),
		StatusCode:     statusCode,
		ResponseLength: 100,
		DurationMs:     durationMs,
	}
	if err := store.SaveFuzzResult(ctx, result); err != nil {
		t.Fatalf("SaveFuzzResult: %v", err)
	}
	return result
}

// seedGzipFuzzResult seeds a gzip-encoded receive flow, with or without the needle.
func seedGzipFuzzResult(t *testing.T, store *flow.SQLiteStore, fuzzID string, index, statusCode int, withNeedle bool) *flow.FuzzResult {
	t.Helper()
	enc := gzipForTest(t, fuzzBodyPlain(withNeedle))
	assertNeedleHidden(t, enc)
	return seedFuzzResultWire(t, store, fuzzID, index, statusCode, 50,
		map[string][]string{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, enc)
}

// TestQuery_FuzzResults_BodyContains_Gzip covers AC1: a reflected payload
// inside a gzip-compressed response is found by filter.body_contains, and
// count / total / summary.total_results all agree.
func TestQuery_FuzzResults_BodyContains_Gzip(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	want := seedGzipFuzzResult(t, store, job.ID, 0, 200, true)
	seedGzipFuzzResult(t, store, job.ID, 1, 200, false)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"body_contains": fuzzBodyNeedle},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}
	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1 (gzip-encoded reflection must match)", out.Count)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Summary == nil || out.Summary.TotalResults != 1 {
		t.Errorf("summary.total_results = %+v, want 1", out.Summary)
	}
	if out.Results[0].ID != want.ID {
		t.Errorf("result id = %q, want %q", out.Results[0].ID, want.ID)
	}
}

// TestQuery_FuzzResults_BodyContains_Codecs covers every Content-Encoding the
// MCP read path decodes (gzip / x-gzip / deflate / br / zstd), including an
// HTTP/2-style lowercase header name.
func TestQuery_FuzzResults_BodyContains_Codecs(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		ce         string
		encode     func(*testing.T, []byte) []byte
	}{
		{"gzip", "Content-Encoding", "gzip", gzipForTest},
		{"x-gzip", "Content-Encoding", "x-gzip", gzipForTest},
		{"deflate", "Content-Encoding", "deflate", deflateForTest},
		{"br", "Content-Encoding", "br", brotliForTest},
		{"zstd", "Content-Encoding", "zstd", zstdForTest},
		{"h2_lowercase_gzip", "content-encoding", "gzip", gzipForTest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestFuzzStore(t)
			cs := setupFuzzQueryTestSession(t, store, store)
			job := seedFuzzJob(t, store, "completed", "test")

			for i, withNeedle := range []bool{false, true, false} {
				enc := tt.encode(t, fuzzBodyPlain(withNeedle))
				assertNeedleHidden(t, enc)
				seedFuzzResultWire(t, store, job.ID, i, 200, 50,
					map[string][]string{tt.headerName: {tt.ce}}, enc)
			}

			result := callQueryRaw(t, cs, map[string]any{
				"resource": "fuzz_results",
				"fuzz_id":  job.ID,
				"filter":   map[string]any{"body_contains": fuzzBodyNeedle},
			})
			if result.IsError {
				t.Fatalf("expected success: %v", result.Content)
			}
			var out queryFuzzResultsResult
			unmarshalQueryResultRaw(t, result, &out)
			if out.Count != 1 || out.Total != 1 {
				t.Fatalf("count=%d total=%d, want 1/1 for %s", out.Count, out.Total, tt.ce)
			}
			if out.Results[0].IndexNum != 1 {
				t.Errorf("index = %d, want 1", out.Results[0].IndexNum)
			}
		})
	}
}

// TestQuery_FuzzResults_BodyContains_Pagination checks that limit / offset /
// total / summary are computed over the decoded-filtered set and that the
// SQL sort order survives the Go-side filter.
func TestQuery_FuzzResults_BodyContains_Pagination(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)
	job := seedFuzzJob(t, store, "completed", "test")

	// Matches: index 0 (500), 2 (200), 4 (404). Non-matches: 1, 3.
	seedGzipFuzzResult(t, store, job.ID, 0, 500, true)
	seedGzipFuzzResult(t, store, job.ID, 1, 200, false)
	seedGzipFuzzResult(t, store, job.ID, 2, 200, true)
	seedGzipFuzzResult(t, store, job.ID, 3, 200, false)
	seedGzipFuzzResult(t, store, job.ID, 4, 404, true)

	query := func(t *testing.T, extra map[string]any) queryFuzzResultsResult {
		t.Helper()
		args := map[string]any{
			"resource": "fuzz_results",
			"fuzz_id":  job.ID,
			"filter":   map[string]any{"body_contains": fuzzBodyNeedle},
		}
		for k, v := range extra {
			args[k] = v
		}
		result := callQueryRaw(t, cs, args)
		if result.IsError {
			t.Fatalf("expected success: %v", result.Content)
		}
		var out queryFuzzResultsResult
		unmarshalQueryResultRaw(t, result, &out)
		return out
	}

	indexes := func(out queryFuzzResultsResult) []int {
		got := make([]int, 0, len(out.Results))
		for _, r := range out.Results {
			got = append(got, r.IndexNum)
		}
		return got
	}

	tests := []struct {
		name      string
		extra     map[string]any
		wantIndex []int
	}{
		{"second_match_in_index_order", map[string]any{"limit": 1, "offset": 1}, []int{2}},
		{"default_limit", nil, []int{0, 2, 4}},
		{"sort_by_status_code", map[string]any{"sort_by": "status_code"}, []int{2, 4, 0}},
		{"sort_by_status_code_paged", map[string]any{"sort_by": "status_code", "limit": 2, "offset": 1}, []int{4, 0}},
		{"offset_beyond_matches", map[string]any{"offset": 10}, []int{}},
		{"offset_at_end", map[string]any{"offset": 3}, []int{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := query(t, tt.extra)
			if out.Total != 3 {
				t.Errorf("total = %d, want 3", out.Total)
			}
			if out.Summary == nil || out.Summary.TotalResults != 3 {
				t.Errorf("summary.total_results = %+v, want 3", out.Summary)
			}
			got := indexes(out)
			if fmt.Sprint(got) != fmt.Sprint(tt.wantIndex) {
				t.Errorf("indexes = %v, want %v", got, tt.wantIndex)
			}
			if out.Count != len(tt.wantIndex) {
				t.Errorf("count = %d, want %d", out.Count, len(tt.wantIndex))
			}
		})
	}
}

// TestQuery_FuzzResults_BodyContains_OutliersOnly checks that with
// outliers_only the summary (and therefore the outlier baseline) is computed
// over the body-matched set only, not the whole job.
func TestQuery_FuzzResults_BodyContains_OutliersOnly(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)
	job := seedFuzzJob(t, store, "completed", "test")

	// Non-matching 500s dominate the whole job: over all 11 rows the
	// baseline would be 500 and the 200s would be the outliers.
	for i := 0; i < 6; i++ {
		seedGzipFuzzResult(t, store, job.ID, i, 500, false)
	}
	// Matched set: four 200s and one 500 — baseline 200, outlier = the 500.
	for i := 6; i < 10; i++ {
		seedGzipFuzzResult(t, store, job.ID, i, 200, true)
	}
	outlier := seedGzipFuzzResult(t, store, job.ID, 10, 500, true)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"body_contains": fuzzBodyNeedle, "outliers_only": true},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}
	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Summary == nil || out.Summary.TotalResults != 5 {
		t.Fatalf("summary.total_results = %+v, want 5 (matched set)", out.Summary)
	}
	if out.Count != 1 || out.Total != 1 {
		t.Fatalf("count=%d total=%d, want 1/1 (results=%+v)", out.Count, out.Total, out.Results)
	}
	if out.Results[0].ID != outlier.ID {
		t.Errorf("outlier id = %q, want %q", out.Results[0].ID, outlier.ID)
	}
}

// TestQuery_FuzzResults_BodyContains_RawBytesStillMatch is a backward-compat
// guard: needles present in the raw stored bytes keep matching, both for an
// identity body and for an unknown Content-Encoding the decoder cannot handle.
func TestQuery_FuzzResults_BodyContains_RawBytesStillMatch(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)
	job := seedFuzzJob(t, store, "completed", "test")

	seedFuzzResultWire(t, store, job.ID, 0, 200, 50,
		map[string][]string{"Content-Type": {"text/html"}}, fuzzBodyPlain(true))
	seedFuzzResultWire(t, store, job.ID, 1, 200, 50,
		map[string][]string{"Content-Encoding": {"x-custom"}}, fuzzBodyPlain(true))
	seedFuzzResultWire(t, store, job.ID, 2, 200, 50,
		map[string][]string{"Content-Encoding": {"x-custom"}}, fuzzBodyPlain(false))
	// Malformed gzip whose raw bytes carry the needle: decode fails, raw matches.
	seedFuzzResultWire(t, store, job.ID, 3, 200, 50,
		map[string][]string{"Content-Encoding": {"gzip"}}, fuzzBodyPlain(true))

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"body_contains": fuzzBodyNeedle},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}
	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)
	if out.Total != 3 || out.Count != 3 {
		t.Fatalf("count=%d total=%d, want 3/3 (results=%+v)", out.Count, out.Total, out.Results)
	}
	for i, want := range []int{0, 1, 3} {
		if out.Results[i].IndexNum != want {
			t.Errorf("results[%d].index = %d, want %d", i, out.Results[i].IndexNum, want)
		}
	}
}

// getFlowsErrStore wraps a flow.Store and fails every GetFlows call.
type getFlowsErrStore struct {
	flow.Store
}

var errGetFlowsInjected = errors.New("injected get flows failure")

func (s getFlowsErrStore) GetFlows(context.Context, string, flow.FlowListOptions) ([]*flow.Flow, error) {
	return nil, errGetFlowsInjected
}

// TestQuery_FuzzResults_BodyContains_GetFlowsError checks that a store error
// while loading a candidate's receive flows surfaces as a tool error rather
// than silently dropping the candidate.
func TestQuery_FuzzResults_BodyContains_GetFlowsError(t *testing.T) {
	sqlStore := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, getFlowsErrStore{Store: sqlStore}, sqlStore)
	job := seedFuzzJob(t, sqlStore, "completed", "test")
	seedGzipFuzzResult(t, sqlStore, job.ID, 0, 200, true)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"body_contains": fuzzBodyNeedle},
	})
	if !result.IsError {
		t.Fatalf("expected tool error when GetFlows fails, got success: %v", result.Content)
	}
}
