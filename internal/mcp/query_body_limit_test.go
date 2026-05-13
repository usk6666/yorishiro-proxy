package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-869 — query include_bodies / body_max_bytes behaviour.
//
// Covers the messages and flow resources, the wire-form body / decoded body
// independent capping, record-time vs response-time truncation flags, the
// 256 KiB Advisory hint, OriginalRequest / OriginalResponse variant flows,
// and rejection of negative body_max_bytes input.

// seedFlowBodies creates a flow with the given request / response body bytes
// and headers. Used by the body-limit tests; mirrors seedFlowWithEncodedBody
// but lets the caller fully control both sides of the exchange and adds a
// truncated-flag hook.
func seedFlowBodies(t *testing.T, store flow.Store, id string, reqBody, respBody []byte, respHeaders map[string][]string, respRecordTruncated bool) {
	t.Helper()
	ctx := context.Background()

	stream := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "http",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  150 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	parsedURL, _ := url.Parse("https://example.com/api")
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:        id + "-send",
		StreamID:  id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      reqBody,
	}); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:            id + "-recv",
		StreamID:      id,
		Sequence:      1,
		Direction:     "receive",
		Timestamp:     time.Now().UTC(),
		StatusCode:    200,
		Headers:       respHeaders,
		Body:          respBody,
		BodyTruncated: respRecordTruncated,
	}); err != nil {
		t.Fatalf("SaveFlow(recv): %v", err)
	}
}

// firstReceiveEntry returns the first entry with direction=receive from a
// messages query result.
func firstReceiveEntry(t *testing.T, msgs []queryMessageEntry) queryMessageEntry {
	t.Helper()
	for _, m := range msgs {
		if m.Direction == "receive" {
			return m
		}
	}
	t.Fatalf("no receive entry in messages")
	return queryMessageEntry{}
}

// --- messages resource ---

// TestQueryMessages_DefaultReturnsFullBody verifies the no-params path is
// lossless: include_bodies defaults true, body_max_bytes defaults 0 (uncapped),
// truncation flags are clear, advisory absent.
func TestQueryMessages_DefaultReturnsFullBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := []byte(`{"hello":"world"}`)
	seedFlowBodies(t, store, "m-default", nil, body, map[string][]string{
		"Content-Type": {"application/json"},
	}, false)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-default"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	got := firstReceiveEntry(t, out.Messages)
	if got.Body != string(body) {
		t.Errorf("Body = %q, want %q", got.Body, string(body))
	}
	if got.BodyEncoding != "text" {
		t.Errorf("BodyEncoding = %q, want text", got.BodyEncoding)
	}
	if got.BodyTruncated {
		t.Errorf("BodyTruncated = true, want false")
	}
	if got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = true, want false")
	}
	if got.BodyOriginalSize != 0 {
		t.Errorf("BodyOriginalSize = %d, want 0", got.BodyOriginalSize)
	}
	if out.Advisory != "" {
		t.Errorf("Advisory = %q, want empty", out.Advisory)
	}
}

// TestQueryMessages_IncludeBodiesFalse_SuppressesBody asserts AC: include_bodies=false
// drops all body fields, preserves metadata, sets body_truncated_by_query=true with
// the original size, and keeps record-time body_truncated.
func TestQueryMessages_IncludeBodiesFalse_SuppressesBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := []byte("the secret big body")
	seedFlowBodies(t, store, "m-nobody", nil, body, map[string][]string{
		"Content-Type": {"text/plain"},
	}, false)

	off := false
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-nobody", IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	got := firstReceiveEntry(t, out.Messages)
	if got.Body != "" {
		t.Errorf("Body = %q, want empty", got.Body)
	}
	if got.BodyEncoding != "" {
		t.Errorf("BodyEncoding = %q, want empty", got.BodyEncoding)
	}
	if got.BodyDecoded != "" {
		t.Errorf("BodyDecoded = %q, want empty", got.BodyDecoded)
	}
	if !got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = false, want true")
	}
	if got.BodyOriginalSize != len(body) {
		t.Errorf("BodyOriginalSize = %d, want %d", got.BodyOriginalSize, len(body))
	}
	// Headers and metadata preserved.
	if len(got.Headers) == 0 {
		t.Errorf("Headers dropped on include_bodies=false; want preserved")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", got.StatusCode)
	}
	if out.Advisory != "" {
		t.Errorf("Advisory set unexpectedly: %q", out.Advisory)
	}
}

// TestQueryMessages_BodyMaxBytes_CapsLargeBody asserts AC: body_max_bytes=N
// truncates the body bytes, sets body_truncated_by_query, and reports the
// original size.
func TestQueryMessages_BodyMaxBytes_CapsLargeBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := bytes.Repeat([]byte("A"), 10_000)
	seedFlowBodies(t, store, "m-cap", nil, body, map[string][]string{
		"Content-Type": {"text/plain"},
	}, false)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-cap", BodyMaxBytes: 1024})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	got := firstReceiveEntry(t, out.Messages)
	if !got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = false, want true")
	}
	if got.BodyOriginalSize != len(body) {
		t.Errorf("BodyOriginalSize = %d, want %d", got.BodyOriginalSize, len(body))
	}
	if got.BodyEncoding != "text" {
		t.Errorf("BodyEncoding = %q, want text", got.BodyEncoding)
	}
	if len(got.Body) != 1024 {
		t.Errorf("Body length = %d, want 1024", len(got.Body))
	}
}

// TestQueryMessages_BodyMaxBytes_BelowCapNoTruncation asserts: when the body
// fits under the cap, no truncation flags are set and the body is returned
// in full.
func TestQueryMessages_BodyMaxBytes_BelowCapNoTruncation(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := []byte("tiny body")
	seedFlowBodies(t, store, "m-undercap", nil, body, map[string][]string{
		"Content-Type": {"text/plain"},
	}, false)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-undercap", BodyMaxBytes: 1024})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	got := firstReceiveEntry(t, out.Messages)
	if got.Body != string(body) {
		t.Errorf("Body = %q, want %q", got.Body, string(body))
	}
	if got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = true, want false")
	}
	if got.BodyOriginalSize != 0 {
		t.Errorf("BodyOriginalSize = %d, want 0", got.BodyOriginalSize)
	}
}

// TestQueryMessages_BodyMaxBytes_BinaryRawBytesPath verifies the RawBytes
// fallback (binary protocols with empty Body) is also capped.
func TestQueryMessages_BodyMaxBytes_BinaryRawBytesPath(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	raw := bytes.Repeat([]byte{0xff}, 5000)
	ctx := context.Background()
	if err := store.SaveStream(ctx, &flow.Stream{
		ID:        "m-bin",
		ConnID:    "conn-m-bin",
		Protocol:  "ws",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:        "m-bin-1",
		StreamID:  "m-bin",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		RawBytes:  raw,
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-bin", BodyMaxBytes: 256})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if len(out.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(out.Messages))
	}
	got := out.Messages[0]
	if got.BodyEncoding != "base64" {
		t.Errorf("BodyEncoding = %q, want base64 (binary raw bytes)", got.BodyEncoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Body)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 256 {
		t.Errorf("decoded length = %d, want 256", len(decoded))
	}
	if !got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = false, want true")
	}
	if got.BodyOriginalSize != len(raw) {
		t.Errorf("BodyOriginalSize = %d, want %d", got.BodyOriginalSize, len(raw))
	}
}

// TestQueryMessages_GzipBody_CapsDecodedSize verifies gzip case: small wire-form
// body but large decoded body. body_max_bytes caps body_decoded independently
// and records body_decoded_original_size.
func TestQueryMessages_GzipBody_CapsDecodedSize(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Large compressible plaintext (~20 KiB after decode); compresses well.
	plaintext := bytes.Repeat([]byte("hello world "), 2000)
	compressed := gzipForTest(t, plaintext)
	if len(compressed) >= len(plaintext) {
		t.Fatalf("gzip did not compress test data (compressed=%d plaintext=%d)", len(compressed), len(plaintext))
	}
	seedFlowBodies(t, store, "m-gz", nil, compressed, map[string][]string{
		"Content-Encoding": {"gzip"},
		"Content-Type":     {"text/plain"},
	}, false)

	// Cap > wire size, < decoded size — ensure only the decoded side fires.
	cap := len(compressed) + 100
	if cap >= len(plaintext) {
		t.Fatalf("test cap %d too large; choose between wire (%d) and decoded (%d)", cap, len(compressed), len(plaintext))
	}
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-gz", BodyMaxBytes: cap})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	got := firstReceiveEntry(t, out.Messages)
	if got.BodyDecodedOriginalSize != len(plaintext) {
		t.Errorf("BodyDecodedOriginalSize = %d, want %d", got.BodyDecodedOriginalSize, len(plaintext))
	}
	if got.BodyOriginalSize != 0 {
		t.Errorf("wire-form BodyOriginalSize fired unexpectedly: %d", got.BodyOriginalSize)
	}
	if !got.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = false, want true (decoded side capped)")
	}
	if got.BodyEncodingApplied != "gzip" {
		t.Errorf("BodyEncodingApplied = %q, want gzip", got.BodyEncodingApplied)
	}
}

// TestQueryMessages_RecordTimeTruncatedAlwaysSurfaces asserts that
// Flow.BodyTruncated surfaces as body_truncated regardless of the response-time
// params.
func TestQueryMessages_RecordTimeTruncatedAlwaysSurfaces(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := []byte("partial")
	seedFlowBodies(t, store, "m-rt", nil, body, map[string][]string{
		"Content-Type": {"text/plain"},
	}, true)

	// Default params.
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-rt"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var outDefault queryMessagesResult
	unmarshalQueryResult(t, result, &outDefault)
	gotDefault := firstReceiveEntry(t, outDefault.Messages)
	if !gotDefault.BodyTruncated {
		t.Errorf("BodyTruncated = false, want true (record-time)")
	}

	// include_bodies=false also surfaces record-time flag.
	off := false
	result = callQuery(t, cs, queryInput{Resource: "messages", ID: "m-rt", IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var outSuppressed queryMessagesResult
	unmarshalQueryResult(t, result, &outSuppressed)
	gotSuppressed := firstReceiveEntry(t, outSuppressed.Messages)
	if !gotSuppressed.BodyTruncated {
		t.Errorf("BodyTruncated should still surface under include_bodies=false")
	}
	if !gotSuppressed.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery = false, want true")
	}
}

// TestQueryMessages_NegativeBodyMaxBytesRejected asserts negative input is
// rejected with a clear error.
func TestQueryMessages_NegativeBodyMaxBytesRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)
	seedFlowBodies(t, store, "m-neg", nil, []byte("ok"), nil, false)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-neg", BodyMaxBytes: -1})
	if !result.IsError {
		t.Fatalf("expected IsError=true for negative body_max_bytes")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T", result.Content[0])
	}
	if !strings.Contains(text.Text, "body_max_bytes") {
		t.Errorf("error message did not mention body_max_bytes: %q", text.Text)
	}
}

// TestQueryMessages_AdvisoryEmittedOnLargeBody asserts the advisory hint is
// set when no size param is passed and a stored body is above the heuristic
// threshold. Suppressing via include_bodies=false also suppresses the advisory.
func TestQueryMessages_AdvisoryEmittedOnLargeBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Slightly above the 256 KiB advisory threshold so the gate fires.
	big := bytes.Repeat([]byte{'X'}, oversizeAdvisoryThreshold+1024)
	seedFlowBodies(t, store, "m-big", nil, big, map[string][]string{
		"Content-Type": {"application/octet-stream"},
	}, false)

	// Unbounded: advisory should fire.
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "m-big"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var outUnbound queryMessagesResult
	unmarshalQueryResult(t, result, &outUnbound)
	if outUnbound.Advisory == "" {
		t.Errorf("Advisory empty; expected hint on >256 KiB body")
	}

	// include_bodies=false: advisory suppressed because caller bound the response.
	off := false
	result = callQuery(t, cs, queryInput{Resource: "messages", ID: "m-big", IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var outBoundedFalse queryMessagesResult
	unmarshalQueryResult(t, result, &outBoundedFalse)
	if outBoundedFalse.Advisory != "" {
		t.Errorf("Advisory set when caller explicitly bounded: %q", outBoundedFalse.Advisory)
	}

	// body_max_bytes=N: same — caller bounded.
	result = callQuery(t, cs, queryInput{Resource: "messages", ID: "m-big", BodyMaxBytes: 4096})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var outBoundedCap queryMessagesResult
	unmarshalQueryResult(t, result, &outBoundedCap)
	if outBoundedCap.Advisory != "" {
		t.Errorf("Advisory set when caller passed body_max_bytes: %q", outBoundedCap.Advisory)
	}
}

// --- flow resource ---

// TestQueryFlow_IncludeBodiesFalse_SuppressesBothSides asserts the flow
// resource honours include_bodies=false: both request_body and response_body
// are cleared, *_body_truncated_by_query is set, and *_body_original_size
// reports the pre-suppression length.
func TestQueryFlow_IncludeBodiesFalse_SuppressesBothSides(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	reqBody := []byte("request body")
	respBody := []byte("response body")
	seedFlowBodies(t, store, "fl-nobody", reqBody, respBody, map[string][]string{
		"Content-Type": {"text/plain"},
	}, false)

	off := false
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-nobody", IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.RequestBody != "" {
		t.Errorf("RequestBody = %q, want empty", fq.RequestBody)
	}
	if fq.ResponseBody != "" {
		t.Errorf("ResponseBody = %q, want empty", fq.ResponseBody)
	}
	if !fq.RequestBodyTruncatedByQuery {
		t.Errorf("RequestBodyTruncatedByQuery = false, want true")
	}
	if !fq.ResponseBodyTruncatedByQuery {
		t.Errorf("ResponseBodyTruncatedByQuery = false, want true")
	}
	if fq.RequestBodyOriginalSize != len(reqBody) {
		t.Errorf("RequestBodyOriginalSize = %d, want %d", fq.RequestBodyOriginalSize, len(reqBody))
	}
	if fq.ResponseBodyOriginalSize != len(respBody) {
		t.Errorf("ResponseBodyOriginalSize = %d, want %d", fq.ResponseBodyOriginalSize, len(respBody))
	}
	// Headers / metadata preserved.
	if len(fq.RequestHeaders) == 0 {
		t.Errorf("RequestHeaders empty; want preserved on include_bodies=false")
	}
	if fq.Method != "POST" {
		t.Errorf("Method = %q, want POST", fq.Method)
	}
}

// TestQueryFlow_BodyMaxBytes_CapsBothSides verifies cap applies independently
// to request and response.
func TestQueryFlow_BodyMaxBytes_CapsBothSides(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	reqBody := bytes.Repeat([]byte("Q"), 4000)
	respBody := bytes.Repeat([]byte("R"), 8000)
	seedFlowBodies(t, store, "fl-cap", reqBody, respBody, map[string][]string{
		"Content-Type": {"text/plain"},
	}, false)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-cap", BodyMaxBytes: 1000})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if len(fq.RequestBody) != 1000 {
		t.Errorf("RequestBody length = %d, want 1000", len(fq.RequestBody))
	}
	if len(fq.ResponseBody) != 1000 {
		t.Errorf("ResponseBody length = %d, want 1000", len(fq.ResponseBody))
	}
	if fq.RequestBodyOriginalSize != len(reqBody) {
		t.Errorf("RequestBodyOriginalSize = %d, want %d", fq.RequestBodyOriginalSize, len(reqBody))
	}
	if fq.ResponseBodyOriginalSize != len(respBody) {
		t.Errorf("ResponseBodyOriginalSize = %d, want %d", fq.ResponseBodyOriginalSize, len(respBody))
	}
	if !fq.RequestBodyTruncatedByQuery {
		t.Errorf("RequestBodyTruncatedByQuery = false, want true")
	}
	if !fq.ResponseBodyTruncatedByQuery {
		t.Errorf("ResponseBodyTruncatedByQuery = false, want true")
	}
}

// TestQueryFlow_DecodedSideCappedIndependently verifies the gzip case on the
// flow resource: small wire-form, large decoded — body_max_bytes caps the
// decoded body and reports body_decoded_original_size.
func TestQueryFlow_DecodedSideCappedIndependently(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	plaintext := bytes.Repeat([]byte("hello world "), 2000)
	compressed := gzipForTest(t, plaintext)
	if len(compressed) >= len(plaintext) {
		t.Fatalf("gzip did not compress test data")
	}
	seedFlowBodies(t, store, "fl-gz", nil, compressed, map[string][]string{
		"Content-Encoding": {"gzip"},
		"Content-Type":     {"text/plain"},
	}, false)

	cap := len(compressed) + 100
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-gz", BodyMaxBytes: cap})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecodedOriginalSize != len(plaintext) {
		t.Errorf("ResponseBodyDecodedOriginalSize = %d, want %d", fq.ResponseBodyDecodedOriginalSize, len(plaintext))
	}
	if !fq.ResponseBodyTruncatedByQuery {
		t.Errorf("ResponseBodyTruncatedByQuery = false, want true")
	}
	if fq.ResponseBodyOriginalSize != 0 {
		t.Errorf("ResponseBodyOriginalSize fired unexpectedly: %d", fq.ResponseBodyOriginalSize)
	}
	if fq.ResponseBodyEncodingApplied != "gzip" {
		t.Errorf("ResponseBodyEncodingApplied = %q, want gzip", fq.ResponseBodyEncodingApplied)
	}
}

// TestQueryFlow_RecordTimeTruncatedAlwaysSurfaces asserts the record-time
// response_body_truncated flag remains visible regardless of new params.
func TestQueryFlow_RecordTimeTruncatedAlwaysSurfaces(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedFlowBodies(t, store, "fl-rt", nil, []byte("partial"), map[string][]string{
		"Content-Type": {"text/plain"},
	}, true)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-rt"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqDefault queryFlowResult
	unmarshalQueryResult(t, result, &fqDefault)
	if !fqDefault.ResponseBodyTruncated {
		t.Errorf("ResponseBodyTruncated = false, want true (record-time)")
	}

	off := false
	result = callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-rt", IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqSuppressed queryFlowResult
	unmarshalQueryResult(t, result, &fqSuppressed)
	if !fqSuppressed.ResponseBodyTruncated {
		t.Errorf("ResponseBodyTruncated should still surface under include_bodies=false")
	}
	if !fqSuppressed.ResponseBodyTruncatedByQuery {
		t.Errorf("ResponseBodyTruncatedByQuery = false, want true")
	}
}

// TestQueryFlow_NegativeBodyMaxBytesRejected asserts negative input rejected
// on the flow resource.
func TestQueryFlow_NegativeBodyMaxBytesRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)
	seedFlowBodies(t, store, "fl-neg", nil, []byte("ok"), nil, false)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-neg", BodyMaxBytes: -1})
	if !result.IsError {
		t.Fatalf("expected IsError=true for negative body_max_bytes")
	}
}

// TestQueryFlow_AdvisoryHintOnLargeBody asserts the advisory hint fires on
// the flow resource when no size param is passed and a stored body exceeds
// the heuristic threshold.
func TestQueryFlow_AdvisoryHintOnLargeBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	big := bytes.Repeat([]byte{'Y'}, oversizeAdvisoryThreshold+512)
	seedFlowBodies(t, store, "fl-big", nil, big, map[string][]string{
		"Content-Type": {"application/octet-stream"},
	}, false)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-big"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqUnbound queryFlowResult
	unmarshalQueryResult(t, result, &fqUnbound)
	if fqUnbound.Advisory == "" {
		t.Errorf("Advisory empty; expected hint on >256 KiB body")
	}

	result = callQuery(t, cs, queryInput{Resource: "flow", ID: "fl-big", BodyMaxBytes: 4096})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqBounded queryFlowResult
	unmarshalQueryResult(t, result, &fqBounded)
	if fqBounded.Advisory != "" {
		t.Errorf("Advisory set when caller bounded: %q", fqBounded.Advisory)
	}
}

// TestQueryFlow_VariantFlow_HonorsLimits asserts the OriginalRequest /
// OriginalResponse variants on a modified flow also honour include_bodies
// and body_max_bytes.
func TestQueryFlow_VariantFlow_HonorsLimits(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	ctx := context.Background()
	id := "fl-variant"
	if err := store.SaveStream(ctx, &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "http",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	parsed, _ := url.Parse("https://example.com/api")
	originalBody := bytes.Repeat([]byte("orig"), 1000)
	modifiedBody := bytes.Repeat([]byte("mod-"), 1000)

	// Two send variants — original first then modified, both pointing at the
	// same flow row.
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:        id + "-send-orig",
		StreamID:  id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsed,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      originalBody,
		Metadata:  map[string]string{"variant": "original"},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:        id + "-send-mod",
		StreamID:  id,
		Sequence:  1,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsed,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      modifiedBody,
		Metadata:  map[string]string{"variant": "modified"},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:         id + "-recv",
		StreamID:   id,
		Sequence:   2,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"text/plain"}},
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// body_max_bytes caps both the modified (RequestBody) and original variant.
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: id, BodyMaxBytes: 512})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqCap queryFlowResult
	unmarshalQueryResult(t, result, &fqCap)
	if fqCap.OriginalRequest == nil {
		t.Fatalf("OriginalRequest nil; expected variant data")
	}
	if len(fqCap.OriginalRequest.Body) != 512 {
		t.Errorf("OriginalRequest.Body length = %d, want 512", len(fqCap.OriginalRequest.Body))
	}
	if len(fqCap.RequestBody) != 512 {
		t.Errorf("RequestBody length = %d, want 512", len(fqCap.RequestBody))
	}

	// include_bodies=false also suppresses the variant body.
	off := false
	result = callQuery(t, cs, queryInput{Resource: "flow", ID: id, IncludeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fqSuppressed queryFlowResult
	unmarshalQueryResult(t, result, &fqSuppressed)
	if fqSuppressed.OriginalRequest == nil {
		t.Fatalf("OriginalRequest nil; expected metadata-only variant")
	}
	if fqSuppressed.OriginalRequest.Body != "" {
		t.Errorf("OriginalRequest.Body = %q, want empty under include_bodies=false", fqSuppressed.OriginalRequest.Body)
	}
	if fqSuppressed.OriginalRequest.Method != "POST" {
		t.Errorf("OriginalRequest.Method = %q, want POST", fqSuppressed.OriginalRequest.Method)
	}
}
