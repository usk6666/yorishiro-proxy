// Package mcp query_decode_body_grpc_test.go covers the gRPC proto LPM
// schemaless decode wiring added in USK-922. The unit tier asserts:
//
//   - query messages on a gRPC Data envelope surfaces body_decoded as
//     proto-schemaless JSON when decode_bodies=true (the default).
//   - decode_bodies=false suppresses the new fields.
//   - Malformed proto payloads surface body_decode_anomaly{proto_malformed}
//     and leave the wire-form body intact.
//   - Empty bodies stay quiet.
//   - body_max_bytes caps body_decoded independently of the wire-form body.
//   - Output Filter masks PII inside the decoded JSON before it reaches the
//     MCP transport boundary (RFC-001 §3.7).
//   - gRPC Start / End envelopes (grpc_event != "data") are NOT decoded.
//   - The same dispatch fires through query flow's projectFlowSide
//     (unary RPC code path).
//
// gRPC-Web is covered query-side automatically: the record_step writes
// metadata grpc_event=data for both gRPC and gRPC-Web Data envelopes. A
// dedicated gRPC-Web flow fixture exercises that path.
package mcp

import (
	"context"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// protoBytesHi is the proto wire encoding of {field=1 (String) "hi"}.
// Tag byte 0x0A = (field 1 << 3) | wireLengthDelimited(2), length 0x02,
// then the ASCII bytes for "hi".
var protoBytesHi = []byte{0x0a, 0x02, 0x68, 0x69}

// protoBytesSecret encodes {field=1 (String) "secret-card 4111111111111111"}.
// Used by the Output Filter masking test — the credit-card pattern would
// survive a JSON-without-mask projection unless the filter ran on the
// decoded plaintext.
func protoBytesSecret(t *testing.T) []byte {
	t.Helper()
	// 0x0A length-delimited tag + len + value.
	payload := "card 4111111111111111"
	buf := []byte{0x0a, byte(len(payload))}
	buf = append(buf, []byte(payload)...)
	return buf
}

// seedGRPCDataFlow stores a single recv-direction gRPC Data envelope flow
// so query messages / query flow exercises the dispatcher. The Flow.Body is
// the L7 payload (proto wire bytes) — record_step.go strips the LPM prefix
// at record time.
func seedGRPCDataFlow(t *testing.T, store flow.Store, id string, payload []byte, extraMetadata map[string]string) {
	t.Helper()
	ctx := context.Background()

	stream := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "grpc",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	u, _ := url.Parse("https://example.com/pkg.Service/Method")
	send := &flow.Flow{
		ID:        id + "-send",
		StreamID:  id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{":path": {"/pkg.Service/Method"}},
		Metadata:  map[string]string{"grpc_event": "start", "grpc_service": "pkg.Service", "grpc_method": "Method"},
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}

	dataMeta := map[string]string{
		"grpc_event":   "data",
		"grpc_service": "pkg.Service",
		"grpc_method":  "Method",
	}
	for k, v := range extraMetadata {
		dataMeta[k] = v
	}
	data := &flow.Flow{
		ID:        id + "-data",
		StreamID:  id,
		Sequence:  1,
		Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      payload,
		Metadata:  dataMeta,
	}
	if err := store.SaveFlow(ctx, data); err != nil {
		t.Fatalf("SaveFlow(data): %v", err)
	}
}

// TestQueryMessages_GRPCData_BodyDecoded_ProtoSchemalessJSON is the
// happy-path: a Data envelope with simple proto payload yields
// body_decoded as JSON with the schemaless key shape.
func TestQueryMessages_GRPCData_BodyDecoded_ProtoSchemalessJSON(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCDataFlow(t, store, "g1", protoBytesHi, nil)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g1"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	var dataEntry *queryMessageEntry
	for i := range msgs.Messages {
		if msgs.Messages[i].Metadata["grpc_event"] == "data" {
			dataEntry = &msgs.Messages[i]
			break
		}
	}
	if dataEntry == nil {
		t.Fatal("no data envelope in messages list")
	}

	if dataEntry.BodyDecoded == "" {
		t.Fatalf("BodyDecoded empty; want proto JSON projection. Entry=%+v", dataEntry)
	}
	if dataEntry.BodyDecodedEncoding != "proto-schemaless-json" {
		t.Errorf("BodyDecodedEncoding = %q, want proto-schemaless-json", dataEntry.BodyDecodedEncoding)
	}
	if dataEntry.BodyEncodingApplied != "proto-schemaless" {
		t.Errorf("BodyEncodingApplied = %q, want proto-schemaless", dataEntry.BodyEncodingApplied)
	}
	if dataEntry.BodyDecodeAnomaly != nil {
		t.Errorf("unexpected anomaly: %+v", dataEntry.BodyDecodeAnomaly)
	}
	// Key format check: "0001:0000:String" + value "hi".
	if !strings.Contains(dataEntry.BodyDecoded, "0001:0000:String") {
		t.Errorf("BodyDecoded missing field key 0001:0000:String: %q", dataEntry.BodyDecoded)
	}
	if !strings.Contains(dataEntry.BodyDecoded, `"hi"`) {
		t.Errorf("BodyDecoded missing value 'hi': %q", dataEntry.BodyDecoded)
	}
}

// TestQueryMessages_GRPCData_DecodeBodiesFalse_Suppresses asserts the gRPC
// path honours the decode_bodies flag.
func TestQueryMessages_GRPCData_DecodeBodiesFalse_Suppresses(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCDataFlow(t, store, "g2", protoBytesHi, nil)

	off := false
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g2", DecodeBodies: &off})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	for _, m := range msgs.Messages {
		if m.Metadata["grpc_event"] != "data" {
			continue
		}
		if m.BodyDecoded != "" {
			t.Errorf("BodyDecoded should be empty when decode_bodies=false, got %q", m.BodyDecoded)
		}
		if m.BodyEncodingApplied != "" {
			t.Errorf("BodyEncodingApplied should be empty when decode_bodies=false, got %q", m.BodyEncodingApplied)
		}
	}
}

// TestQueryMessages_GRPCData_MalformedProto_Anomaly asserts that bogus
// proto wire bytes surface as proto_malformed and the wire-form body
// stays intact.
func TestQueryMessages_GRPCData_MalformedProto_Anomaly(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Bogus payload: tag byte advertising length-delimited but no length
	// data following. protobuf.Decode returns an error.
	corrupted, _ := hex.DecodeString("0a")
	seedGRPCDataFlow(t, store, "g3", corrupted, nil)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g3"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	var dataEntry *queryMessageEntry
	for i := range msgs.Messages {
		if msgs.Messages[i].Metadata["grpc_event"] == "data" {
			dataEntry = &msgs.Messages[i]
			break
		}
	}
	if dataEntry == nil {
		t.Fatal("no data envelope in messages list")
	}
	if dataEntry.BodyDecodeAnomaly == nil {
		t.Fatal("expected proto_malformed anomaly, got nil")
	}
	if dataEntry.BodyDecodeAnomaly.Type != "proto_malformed" {
		t.Errorf("anomaly type = %q, want proto_malformed", dataEntry.BodyDecodeAnomaly.Type)
	}
	if dataEntry.BodyDecoded != "" {
		t.Errorf("BodyDecoded should be empty on anomaly, got %q", dataEntry.BodyDecoded)
	}
	if dataEntry.BodyEncodingApplied != "" {
		t.Errorf("BodyEncodingApplied should be empty on anomaly, got %q", dataEntry.BodyEncodingApplied)
	}
	// Wire-form body preserved (base64 of the corrupted byte).
	if dataEntry.Body == "" {
		t.Errorf("wire-form body should still surface for diagnostic, got empty")
	}
}

// TestQueryMessages_GRPCData_EmptyBody_NoDecoded asserts the
// len(rawBody)==0 short-circuit.
func TestQueryMessages_GRPCData_EmptyBody_NoDecoded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCDataFlow(t, store, "g4", nil, nil)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g4"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	for _, m := range msgs.Messages {
		if m.Metadata["grpc_event"] != "data" {
			continue
		}
		if m.BodyDecoded != "" {
			t.Errorf("BodyDecoded should be empty for zero-length body, got %q", m.BodyDecoded)
		}
		if m.BodyEncodingApplied != "" {
			t.Errorf("BodyEncodingApplied should be empty for zero-length body, got %q", m.BodyEncodingApplied)
		}
		if m.BodyDecodeAnomaly != nil {
			t.Errorf("no anomaly expected for empty body, got %+v", m.BodyDecodeAnomaly)
		}
	}
}

// TestQueryMessages_GRPCData_BodyMaxBytes_CapsDecoded asserts the
// body_max_bytes cap fires on body_decoded independently of the wire-form
// body and records body_decoded_original_size.
func TestQueryMessages_GRPCData_BodyMaxBytes_CapsDecoded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCDataFlow(t, store, "g5", protoBytesHi, nil)

	// 10 bytes — well below the JSON output length, which includes the
	// key, whitespace, and value.
	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g5", BodyMaxBytes: 10})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	var dataEntry *queryMessageEntry
	for i := range msgs.Messages {
		if msgs.Messages[i].Metadata["grpc_event"] == "data" {
			dataEntry = &msgs.Messages[i]
			break
		}
	}
	if dataEntry == nil {
		t.Fatal("no data envelope in messages list")
	}
	if !dataEntry.BodyTruncatedByQuery {
		t.Errorf("BodyTruncatedByQuery should be true when decoded body exceeds cap")
	}
	if dataEntry.BodyDecodedOriginalSize == 0 {
		t.Errorf("BodyDecodedOriginalSize should record pre-cap length, got 0")
	}
}

// TestQueryMessages_GRPCStart_NoDecoded asserts only Data envelopes get
// the schemaless projection; Start envelopes (grpc_event="start") leave
// the additive fields empty.
func TestQueryMessages_GRPCStart_NoDecoded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCDataFlow(t, store, "g6", protoBytesHi, nil)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g6"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	for _, m := range msgs.Messages {
		if m.Metadata["grpc_event"] == "start" {
			if m.BodyDecoded != "" {
				t.Errorf("Start envelope must not get body_decoded, got %q", m.BodyDecoded)
			}
			if m.BodyEncodingApplied != "" {
				t.Errorf("Start envelope must not get body_encoding_applied, got %q", m.BodyEncodingApplied)
			}
		}
	}
}

// TestQueryFlow_GRPCData_BodyDecoded_UnaryProjection covers the
// projectFlowSide path: a single unary gRPC flow's response body should
// surface as response_body_decoded.
func TestQueryFlow_GRPCData_BodyDecoded_UnaryProjection(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Reuse the seed helper but treat the data envelope as the receive
	// flow for a unary RPC. The send flow (above) projects as the request
	// side; the data flow projects as the response side.
	seedGRPCDataFlow(t, store, "g7", protoBytesHi, nil)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "g7"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var fq queryFlowResult
	unmarshalQueryResult(t, result, &fq)

	if fq.ResponseBodyDecoded == "" {
		t.Fatalf("ResponseBodyDecoded empty; want proto JSON projection")
	}
	if fq.ResponseBodyDecodedEncoding != "proto-schemaless-json" {
		t.Errorf("ResponseBodyDecodedEncoding = %q, want proto-schemaless-json", fq.ResponseBodyDecodedEncoding)
	}
	if fq.ResponseBodyEncodingApplied != "proto-schemaless" {
		t.Errorf("ResponseBodyEncodingApplied = %q, want proto-schemaless", fq.ResponseBodyEncodingApplied)
	}
	if !strings.Contains(fq.ResponseBodyDecoded, "0001:0000:String") {
		t.Errorf("ResponseBodyDecoded missing schemaless field key: %q", fq.ResponseBodyDecoded)
	}
}

// TestQueryMessages_GRPCWeb_BodyDecoded_AutomaticDispatch asserts gRPC-Web
// Data envelopes route through the same dispatcher — record_step writes
// grpc_event=data for gRPC-Web too (RFC-001 §3.2.3 — gRPC-Web emits
// GRPCDataMessage). The query-side dispatch keys on metadata, not on
// Stream.Protocol, so the gRPC-Web stream gets the same proto-schemaless
// projection automatically.
func TestQueryMessages_GRPCWeb_BodyDecoded_AutomaticDispatch(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	ctx := context.Background()
	stream := &flow.Stream{
		ID:        "gw1",
		ConnID:    "conn-gw1",
		Protocol:  "grpc-web",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	data := &flow.Flow{
		ID:        "gw1-data",
		StreamID:  "gw1",
		Sequence:  0,
		Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      protoBytesHi,
		Metadata:  map[string]string{"grpc_event": "data"},
	}
	if err := store.SaveFlow(ctx, data); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "gw1"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	if len(msgs.Messages) == 0 {
		t.Fatal("no messages returned")
	}
	entry := msgs.Messages[0]
	if entry.BodyDecoded == "" {
		t.Fatalf("BodyDecoded empty on gRPC-Web Data envelope: %+v", entry)
	}
	if entry.BodyDecodedEncoding != "proto-schemaless-json" {
		t.Errorf("BodyDecodedEncoding = %q, want proto-schemaless-json", entry.BodyDecodedEncoding)
	}
	if entry.BodyEncodingApplied != "proto-schemaless" {
		t.Errorf("BodyEncodingApplied = %q, want proto-schemaless", entry.BodyEncodingApplied)
	}
}

// TestQueryMessages_GRPCData_OutputFilter_MasksDecoded is the security
// regression: PII inside the decoded JSON must be masked before the
// response leaves the MCP transport boundary. Mirrors the gzip-equivalent
// test for the HTTP path.
func TestQueryMessages_GRPCData_OutputFilter_MasksDecoded(t *testing.T) {
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
	client := gomcp.NewClient(&gomcp.Implementation{Name: "grpc-pii", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	seedGRPCDataFlow(t, store, "g8", protoBytesSecret(t), nil)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: "g8"})
	if result.IsError {
		t.Fatalf("query error: %v", result.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, result, &msgs)

	var dataEntry *queryMessageEntry
	for i := range msgs.Messages {
		if msgs.Messages[i].Metadata["grpc_event"] == "data" {
			dataEntry = &msgs.Messages[i]
			break
		}
	}
	if dataEntry == nil {
		t.Fatal("no data envelope in messages list")
	}
	if strings.Contains(dataEntry.BodyDecoded, "4111111111111111") {
		t.Errorf("Output Filter did not mask credit card in decoded body: %q", dataEntry.BodyDecoded)
	}
	if !strings.Contains(dataEntry.BodyDecoded, "[CC_REDACTED]") {
		t.Errorf("expected mask token in decoded body; got %q", dataEntry.BodyDecoded)
	}
}
