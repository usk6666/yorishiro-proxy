package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// gzipForTest is a tiny inline helper to gzip-encode a byte slice in tests
// without pulling in the bodydecode package (avoids a circular self-test).
func gzipForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// seedFlowWithEncodedBody mirrors seedSession but lets the caller specify
// the response body bytes and headers so it can carry a Content-Encoding.
func seedFlowWithEncodedBody(t *testing.T, store flow.Store, id string, reqBody, respBody []byte, respHeaders map[string][]string) {
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
	sendMsg := &flow.Flow{
		ID:        id + "-send",
		StreamID:  id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      reqBody,
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}

	recvMsg := &flow.Flow{
		ID:         id + "-recv",
		StreamID:   id,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
		t.Fatalf("SaveFlow(recv): %v", err)
	}
}

// TestQueryFlow_GzipResponse_Decoded verifies that AC-1/AC-2:
//   - response body decode happens by default
//   - response_body_encoding_applied = "gzip"
//   - response_body_decoded contains the plaintext (text encoding)
//   - response_body (wire form) is preserved as base64 (gzip bytes are non-UTF-8)
//   - resend path-equivalent: store-side Body bytes are unchanged
func TestQueryFlow_GzipResponse_Decoded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	plaintext := []byte(`{"users":[{"id":1,"email":"alice@example.com"}]}`)
	compressed := gzipForTest(t, plaintext)
	seedFlowWithEncodedBody(t, store, "f1", nil, compressed, map[string][]string{
		"Content-Type":     {"application/json"},
		"Content-Encoding": {"gzip"},
	})

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f1"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	// Wire-form body unchanged (compressed bytes → base64).
	if fq.ResponseBodyEncoding != "base64" {
		t.Errorf("ResponseBodyEncoding = %q, want base64 (gzip is non-UTF-8)", fq.ResponseBodyEncoding)
	}
	wireBytes, err := base64.StdEncoding.DecodeString(fq.ResponseBody)
	if err != nil {
		t.Fatalf("decode wire-form body: %v", err)
	}
	if !bytes.Equal(wireBytes, compressed) {
		t.Errorf("wire-form ResponseBody not preserved byte-for-byte (resend fidelity broken)")
	}

	// Decoded form populated.
	if fq.ResponseBodyEncodingApplied != "gzip" {
		t.Errorf("ResponseBodyEncodingApplied = %q, want gzip", fq.ResponseBodyEncodingApplied)
	}
	if fq.ResponseBodyDecodedEncoding != "text" {
		t.Errorf("ResponseBodyDecodedEncoding = %q, want text", fq.ResponseBodyDecodedEncoding)
	}
	if fq.ResponseBodyDecoded != string(plaintext) {
		t.Errorf("ResponseBodyDecoded = %q, want %q", fq.ResponseBodyDecoded, string(plaintext))
	}
	if fq.ResponseBodyDecodeAnomaly != nil {
		t.Errorf("unexpected anomaly: %+v", fq.ResponseBodyDecodeAnomaly)
	}
}

// TestQueryFlow_DecodeBodiesFalse_SuppressesDecodedFields verifies AC: input
// flag `decode_bodies=false` skips decompression entirely; only wire-form is
// returned.
func TestQueryFlow_DecodeBodiesFalse_SuppressesDecodedFields(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	plaintext := []byte("decoded plaintext")
	compressed := gzipForTest(t, plaintext)
	seedFlowWithEncodedBody(t, store, "f2", nil, compressed, map[string][]string{
		"Content-Encoding": {"gzip"},
	})

	off := false
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f2", DecodeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecoded != "" {
		t.Errorf("ResponseBodyDecoded should be empty when decode_bodies=false, got %q", fq.ResponseBodyDecoded)
	}
	if fq.ResponseBodyEncodingApplied != "" {
		t.Errorf("ResponseBodyEncodingApplied should be empty when decode_bodies=false, got %q", fq.ResponseBodyEncodingApplied)
	}
}

// TestQueryFlow_NoContentEncoding_NoDecodedFields verifies AC: identity / no
// Content-Encoding leaves the additive fields empty (no duplication of the
// already-plaintext body).
func TestQueryFlow_NoContentEncoding_NoDecodedFields(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	plaintext := []byte("plain text body")
	seedFlowWithEncodedBody(t, store, "f3", nil, plaintext, map[string][]string{
		"Content-Type": {"text/plain"},
	})

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f3"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBody != string(plaintext) {
		t.Errorf("ResponseBody = %q, want %q", fq.ResponseBody, string(plaintext))
	}
	if fq.ResponseBodyDecoded != "" {
		t.Errorf("ResponseBodyDecoded should stay empty for identity bodies, got %q", fq.ResponseBodyDecoded)
	}
	if fq.ResponseBodyEncodingApplied != "" {
		t.Errorf("ResponseBodyEncodingApplied should stay empty for identity bodies, got %q", fq.ResponseBodyEncodingApplied)
	}
	if fq.ResponseBodyDecodeAnomaly != nil {
		t.Errorf("unexpected anomaly for identity body: %+v", fq.ResponseBodyDecodeAnomaly)
	}
}

// TestQueryFlow_UnknownEncoding_AnomalySurfaces verifies that an unrecognised
// codec name (e.g. "snappy") returns an unknown_encoding anomaly without
// fabricating decoded data.
func TestQueryFlow_UnknownEncoding_AnomalySurfaces(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := []byte("not actually compressed")
	seedFlowWithEncodedBody(t, store, "f4", nil, body, map[string][]string{
		"Content-Encoding": {"snappy"},
	})

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f4"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecodeAnomaly == nil {
		t.Fatal("expected unknown_encoding anomaly, got nil")
	}
	if fq.ResponseBodyDecodeAnomaly.Type != "unknown_encoding" {
		t.Errorf("anomaly type = %q, want unknown_encoding", fq.ResponseBodyDecodeAnomaly.Type)
	}
	if fq.ResponseBodyDecoded != "" {
		t.Errorf("decoded body should be empty on anomaly, got %q", fq.ResponseBodyDecoded)
	}
	if fq.ResponseBodyEncodingApplied != "" {
		t.Errorf("encoding_applied should be empty on anomaly, got %q", fq.ResponseBodyEncodingApplied)
	}
	// Wire-form body unchanged.
	if fq.ResponseBody != string(body) {
		t.Errorf("ResponseBody mutated on anomaly: got %q, want %q", fq.ResponseBody, string(body))
	}
}

// TestQueryFlow_MalformedGzip_AnomalySurfaces verifies that an invalid gzip
// stream surfaces a malformed anomaly and preserves the wire bytes.
func TestQueryFlow_MalformedGzip_AnomalySurfaces(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	corrupted := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	seedFlowWithEncodedBody(t, store, "f5", nil, corrupted, map[string][]string{
		"Content-Encoding": {"gzip"},
	})

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f5"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecodeAnomaly == nil {
		t.Fatal("expected malformed anomaly, got nil")
	}
	if fq.ResponseBodyDecodeAnomaly.Type != "malformed" {
		t.Errorf("anomaly type = %q, want malformed", fq.ResponseBodyDecodeAnomaly.Type)
	}
	wire, _ := base64.StdEncoding.DecodeString(fq.ResponseBody)
	if !bytes.Equal(wire, corrupted) {
		t.Errorf("wire-form body mutated on anomaly")
	}
}

// TestQueryFlow_ChainRejected verifies that comma-separated Content-Encoding
// values are rejected with a chain_rejected anomaly (chain decoding deferred).
func TestQueryFlow_ChainRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	body := gzipForTest(t, []byte("body"))
	seedFlowWithEncodedBody(t, store, "f6", nil, body, map[string][]string{
		"Content-Encoding": {"gzip, br"},
	})

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "f6"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecodeAnomaly == nil {
		t.Fatal("expected chain_rejected anomaly, got nil")
	}
	if fq.ResponseBodyDecodeAnomaly.Type != "chain_rejected" {
		t.Errorf("anomaly type = %q, want chain_rejected", fq.ResponseBodyDecodeAnomaly.Type)
	}
}

// TestQueryFlow_SafetyFilterAppliedAfterDecode is the security-bug regression
// test. Without decode-then-filter, a credit-card pattern inside a gzipped
// body bypasses the Output Filter (the regex never matches gzip bytes). With
// the fix, the pattern is masked in response_body_decoded.
func TestQueryFlow_SafetyFilterAppliedAfterDecode(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				Preset:      safety.PresetCreditCard,
				Action:      "mask",
				Targets:     []string{"body"},
				Replacement: "[CC_REDACTED]",
			},
		},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}

	ctx := context.Background()
	s := newServer(ctx, nil, store, nil, WithSafetyEngine(engine))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "decode-pii", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	plaintext := []byte(`{"card":"4111111111111111","name":"alice"}`)
	compressed := gzipForTest(t, plaintext)
	seedFlowWithEncodedBody(t, store, "f7", nil, compressed, map[string][]string{
		"Content-Encoding": {"gzip"},
	})

	data, err := json.Marshal(queryInput{Resource: "flow", ID: "f7"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal-to-map: %v", err)
	}
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{Name: "query", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content type: %T", result.Content[0])
	}
	var fq queryFlowResult
	if err := json.Unmarshal([]byte(text.Text), &fq); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Without decode-then-filter, gzip bytes never matched the credit-card
	// regex and the plaintext leaked. With the fix, the masked replacement
	// must appear in the decoded body.
	if strings.Contains(fq.ResponseBodyDecoded, "4111111111111111") {
		t.Errorf("Output Filter did not mask credit card in decoded body: %q", fq.ResponseBodyDecoded)
	}
	if !strings.Contains(fq.ResponseBodyDecoded, "alice") {
		t.Errorf("decoded body should still contain non-PII content; got %q", fq.ResponseBodyDecoded)
	}
	if !strings.Contains(fq.ResponseBodyDecoded, "[CC_REDACTED]") {
		t.Errorf("expected mask token in decoded body; got %q", fq.ResponseBodyDecoded)
	}
}
