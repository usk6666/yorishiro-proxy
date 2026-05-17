//go:build e2e && !e2e_smoke

// Package mcp grpc_schema_e2e_integration_test.go is the USK-923 e2e
// wiring test: a recorded gRPC Data flow is seeded into the Store, the
// grpc_schema MCP tool registers a schema for it, and query messages /
// resend_grpc are exercised through the MCP transport.
//
// This file lives in the exhaustive e2e tier (`//go:build e2e && !e2e_smoke`)
// per CLAUDE.md guidance: it is not a per-PR merge gate, but runs nightly
// to catch wiring regressions.
package mcp

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedGRPCFlowForSchemaTest stores a complete gRPC stream (Start + Data)
// against the test fixture's HelloRequest. The body is the proto-encoded
// payload {f_string: "hello", f_int32: 123}.
func seedGRPCFlowForSchemaTest(t *testing.T, store flow.Store, streamID string) {
	t.Helper()
	ctx := context.Background()

	specs, err := protoschema.LoadFileDescriptorSet(embeddedTestDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	reg := protoschema.NewRegistry()
	reg.Register(specs)
	m := reg.LookupMethod("usk.test.Greeter", "SayHello")
	if m == nil {
		t.Fatal("SayHello not in fixture")
	}
	body, err := protoschema.Encode(`{"f_string":"hello","f_int32":123}`, m.InputDesc)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}

	stream := &flow.Stream{
		ID:        streamID,
		ConnID:    "conn-" + streamID,
		Protocol:  "grpc",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	u, _ := url.Parse("https://example.com/usk.test.Greeter/SayHello")
	startFlow := &flow.Flow{
		ID:        streamID + "-send-start",
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{":path": {"/usk.test.Greeter/SayHello"}},
		Metadata: map[string]string{
			"grpc_event":   "start",
			"grpc_service": "usk.test.Greeter",
			"grpc_method":  "SayHello",
		},
	}
	if err := store.SaveFlow(ctx, startFlow); err != nil {
		t.Fatalf("SaveFlow(start): %v", err)
	}

	dataFlow := &flow.Flow{
		ID:        streamID + "-send-data",
		StreamID:  streamID,
		Sequence:  1,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      body,
		Metadata: map[string]string{
			"grpc_event":   "data",
			"grpc_service": "usk.test.Greeter",
			"grpc_method":  "SayHello",
		},
	}
	if err := store.SaveFlow(ctx, dataFlow); err != nil {
		t.Fatalf("SaveFlow(data): %v", err)
	}
}

// TestE2E_GRPCSchema_RegisterAndQueryDecode verifies the full path:
// register a schema via the grpc_schema MCP tool, then call query messages
// on a recorded gRPC Data flow and assert the body is decoded as protojson
// with real field names.
func TestE2E_GRPCSchema_RegisterAndQueryDecode(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	seedGRPCFlowForSchemaTest(t, store, "e2e-flow-1")

	// 1) Register a schema for the recorded service via the MCP tool.
	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	regResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "grpc_schema",
		Arguments: map[string]any{
			"action": "register",
			"params": map[string]any{
				"source":             "descriptor_set",
				"descriptor_set_b64": b64,
			},
		},
	})
	if err != nil {
		t.Fatalf("grpc_schema register: %v", err)
	}
	if regResult.IsError {
		t.Fatalf("register error: %v", regResult.Content)
	}

	// 2) Query messages and assert the data flow's body is decoded with
	// the schema-aware encoding label.
	queryResult := callQuery(t, cs, queryInput{Resource: "messages", ID: "e2e-flow-1"})
	if queryResult.IsError {
		t.Fatalf("query error: %v", queryResult.Content)
	}
	var msgs queryMessagesResult
	unmarshalQueryResult(t, queryResult, &msgs)

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

	if dataEntry.BodyDecodedEncoding != "proto-json" {
		t.Errorf("BodyDecodedEncoding = %q, want proto-json", dataEntry.BodyDecodedEncoding)
	}
	if !strings.Contains(dataEntry.BodyDecoded, `"f_string"`) {
		t.Errorf("BodyDecoded missing real field name f_string: %q", dataEntry.BodyDecoded)
	}
	if !strings.Contains(dataEntry.BodyDecoded, `"hello"`) {
		t.Errorf("BodyDecoded missing value 'hello': %q", dataEntry.BodyDecoded)
	}
	if !strings.Contains(dataEntry.BodyDecoded, `"f_int32"`) {
		t.Errorf("BodyDecoded missing real field name f_int32: %q", dataEntry.BodyDecoded)
	}
	if dataEntry.BodyDecodeAnomaly != nil {
		t.Errorf("unexpected anomaly: %+v", dataEntry.BodyDecodeAnomaly)
	}
}

// TestE2E_GRPCSchema_ListUnregisterClear verifies the lifecycle round-trip
// through the MCP tool.
func TestE2E_GRPCSchema_ListUnregisterClear(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "grpc_schema",
		Arguments: map[string]any{
			"action": "register",
			"params": map[string]any{
				"source":             "descriptor_set",
				"descriptor_set_b64": b64,
			},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// list: must report both services.
	listResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "grpc_schema",
		Arguments: map[string]any{"action": "list"},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listOut grpcSchemaListResult
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 2 {
		t.Fatalf("list len = %d, want 2", len(listOut.Schemas))
	}

	// unregister one service.
	_, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "grpc_schema",
		Arguments: map[string]any{
			"action": "unregister",
			"params": map[string]any{"service": "usk.test.Greeter"},
		},
	})
	if err != nil {
		t.Fatalf("unregister: %v", err)
	}

	// list: one remaining.
	listResult, _ = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "grpc_schema",
		Arguments: map[string]any{"action": "list"},
	})
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 1 || listOut.Schemas[0].Service != "usk.test.Reflective" {
		t.Errorf("after unregister: %+v", listOut.Schemas)
	}

	// clear: empty.
	_, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "grpc_schema",
		Arguments: map[string]any{"action": "clear"},
	})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	listResult, _ = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "grpc_schema",
		Arguments: map[string]any{"action": "list"},
	})
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 0 {
		t.Errorf("after clear: %+v", listOut.Schemas)
	}
}
