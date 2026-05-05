//go:build e2e

package mcp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestWireFidelity_LivePath_NoMask_MCP_Mask is the round-trip wire-fidelity
// test for USK-703. It validates the two-engine split documented in
// internal/safety/doc.go and internal/rules/{http,ws,grpc}/safety.go:
//
//  1. Live path: HostScope -> Safety (block-only, never mask) -> Record
//     ingests an HTTP request whose body contains PII (a Visa-format
//     credit-card number). The store must record the original body
//     byte-for-byte. RFC-001 Principle 1 (Wire fidelity).
//  2. MCP control plane: a separate safety.Engine configured with an
//     output mask rule for credit cards is wired into the MCP server.
//     A query tool call must return the body with the credit card
//     replaced by the configured replacement.
//  3. Re-read after the MCP call: the underlying flow.Store row must
//     still contain the original (unmasked) bytes — MCP-side masking
//     never touches recorded wire bytes.
//
// If a future regression accidentally hooks safety.Engine into the live
// path (or accidentally adds a mask method to internal/rules/http), this
// test fails on assertion (1) or (3).
func TestWireFidelity_LivePath_NoMask_MCP_Mask(t *testing.T) {
	ctx := context.Background()

	// --- Build the live-path SafetyEngine (block-only) ---
	// destructive-sql preset matches SQL DDL, NOT credit-card numbers, so
	// the credit card in the body must NOT trigger a Drop. Wire fidelity
	// guarantees that even if it did, the body would still be recorded
	// as-is (locked in by per-protocol guard tests in this PR).
	httpEngine := httprules.NewSafetyEngine()
	if err := httpEngine.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("LoadPreset destructive-sql: %v", err)
	}

	store := newTestStore(t)
	logger := testutil.DiscardLogger()

	// --- Live pipeline: HostScope -> Safety -> Record ---
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewSafetyStep(httpEngine, nil, nil, logger),
		pipeline.NewRecordStep(store, logger),
	}
	p := pipeline.New(steps...)

	// PII payload — a Visa-format credit card the MCP plane will mask.
	const cardNumber = "4111111111111111"
	originalBody := []byte(`{"holder":"alice","card":"` + cardNumber + `"}`)
	originalRaw := []byte("POST /api/pay HTTP/1.1\r\nHost: example.com\r\nContent-Length: 50\r\n\r\n" + string(originalBody))

	streamID := "stream-wire-fidelity-1"
	flowID := "flow-wire-fidelity-1"

	// Snapshot pre-pipeline so we can prove the underlying byte slices
	// were not mutated either.
	bodySnapshot := append([]byte(nil), originalBody...)
	rawSnapshot := append([]byte(nil), originalRaw...)

	sendEnv := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    flowID,
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       originalRaw,
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/api/pay",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
			},
			Body: originalBody,
		},
	}

	if _, action, _ := p.Run(ctx, sendEnv); action == pipeline.Drop {
		t.Fatal("live pipeline unexpectedly dropped a credit-card payload via destructive-sql preset; " +
			"this would invalidate the wire-fidelity assertion")
	}

	// Receive envelope to close out the stream — emits a flow with body
	// containing the same card number on the response side too.
	respBody := []byte(`{"status":"ok","mirror":"` + cardNumber + `"}`)
	respRaw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 38\r\n\r\n" + string(respBody))
	respBodySnap := append([]byte(nil), respBody...)
	respRawSnap := append([]byte(nil), respRaw...)

	recvEnv := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    flowID + "-resp",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       respRaw,
		Message: &envelope.HTTPMessage{
			Status:  200,
			Headers: []envelope.KeyValue{{Name: "Content-Type", Value: "application/json"}},
			Body:    respBody,
		},
	}
	if _, action, _ := p.Run(ctx, recvEnv); action == pipeline.Drop {
		t.Fatalf("receive pipeline unexpectedly dropped: action=%v", action)
	}

	// --- Assertion (1): the live path did not mutate envelope contents ---
	if string(sendEnv.Message.(*envelope.HTTPMessage).Body) != string(bodySnapshot) {
		t.Errorf("live path mutated request body: got %q, want %q",
			sendEnv.Message.(*envelope.HTTPMessage).Body, bodySnapshot)
	}
	if string(sendEnv.Raw) != string(rawSnapshot) {
		t.Errorf("live path mutated request env.Raw: got %q, want %q", sendEnv.Raw, rawSnapshot)
	}
	if string(recvEnv.Message.(*envelope.HTTPMessage).Body) != string(respBodySnap) {
		t.Errorf("live path mutated response body: got %q, want %q",
			recvEnv.Message.(*envelope.HTTPMessage).Body, respBodySnap)
	}
	if string(recvEnv.Raw) != string(respRawSnap) {
		t.Errorf("live path mutated response env.Raw: got %q, want %q", recvEnv.Raw, respRawSnap)
	}

	// --- Assertion (2): the store contains the original (unmasked) bytes ---
	storedFlows, err := store.GetFlows(ctx, streamID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(storedFlows) != 2 {
		t.Fatalf("expected 2 stored flows, got %d", len(storedFlows))
	}
	var sendFlow, recvFlow *flow.Flow
	for _, f := range storedFlows {
		switch f.Direction {
		case "send":
			sendFlow = f
		case "receive":
			recvFlow = f
		}
	}
	if sendFlow == nil {
		t.Fatal("send flow not stored")
	}
	if recvFlow == nil {
		t.Fatal("receive flow not stored")
	}
	if !strings.Contains(string(sendFlow.Body), cardNumber) {
		t.Errorf("stored send body missing original card number %q: got %q",
			cardNumber, string(sendFlow.Body))
	}
	if !strings.Contains(string(recvFlow.Body), cardNumber) {
		t.Errorf("stored receive body missing original card number %q: got %q",
			cardNumber, string(recvFlow.Body))
	}
	if !strings.Contains(string(sendFlow.RawBytes), cardNumber) {
		t.Errorf("stored send RawBytes missing original card number %q: got %q",
			cardNumber, string(sendFlow.RawBytes))
	}
	if !strings.Contains(string(recvFlow.RawBytes), cardNumber) {
		t.Errorf("stored receive RawBytes missing original card number %q: got %q",
			cardNumber, string(recvFlow.RawBytes))
	}

	// --- Set up the MCP plane with an output-masking safety.Engine ---
	const replacement = "[CARD_REDACTED]"
	mcpEngine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				Preset:      "credit-card",
				Action:      "mask",
				Replacement: replacement,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cs := setupTestSessionWithOutputFilter(t, store, nil, mcpEngine)

	// --- Assertion (3): MCP query masks the response body ---
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := cs.CallTool(queryCtx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: outputMustMarshalArgs(t, queryInput{Resource: "messages", ID: streamID}),
	})
	if err != nil {
		t.Fatalf("CallTool query messages: %v", err)
	}
	if result.IsError {
		t.Fatalf("query messages returned error: %s", outputTextContent(result))
	}
	respText := outputTextContent(result)

	// The MCP transport may base64-encode binary bodies; check both
	// raw + b64-encoded forms of the unmasked card number to be safe.
	cardB64 := base64.StdEncoding.EncodeToString([]byte(cardNumber))
	if strings.Contains(respText, cardNumber) || strings.Contains(respText, cardB64) {
		t.Errorf("MCP query response leaks unmasked card number %q\nfull response: %s",
			cardNumber, respText)
	}
	if !strings.Contains(respText, replacement) &&
		!strings.Contains(respText, base64.StdEncoding.EncodeToString([]byte(replacement))) {
		t.Errorf("MCP query response missing replacement %q\nfull response: %s",
			replacement, respText)
	}

	// --- Assertion (4): the store was NOT modified by the MCP query ---
	postQueryFlows, err := store.GetFlows(ctx, streamID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows after MCP query: %v", err)
	}
	if len(postQueryFlows) != 2 {
		t.Fatalf("post-query flow count changed: got %d, want 2", len(postQueryFlows))
	}
	for _, f := range postQueryFlows {
		if !strings.Contains(string(f.Body), cardNumber) {
			t.Errorf("MCP query mutated stored body for direction %q: got %q",
				f.Direction, string(f.Body))
		}
		if !strings.Contains(string(f.RawBytes), cardNumber) {
			t.Errorf("MCP query mutated stored RawBytes for direction %q: got %q",
				f.Direction, string(f.RawBytes))
		}
	}
}
