package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1344 — query resource=messages / resource=flow message_preview must not
// surface Flow.RawBytes as the L7 `body`. A message without an L7 body but
// with stored wire bytes exposes them as `raw_bytes` (always base64) instead.
//
// Fixtures: every Flow is produced by the real RecordStep (envelopeToFlow)
// from a hand-built Envelope shaped like the one the producing Layer emits
// (see internal/layer/http1, httpaggregator/channel.go for the nil-Message
// h2-frame overlay, internal/layer/grpc, internal/layer/ws). The Raw bytes
// are INVENTED — plausible wire bytes, not captured from a live connection.
// The real-wire path is covered by
// internal/mcptest/query_messages_raw_bytes_integration_test.go.

// recordEnvelopesForQuery runs envs through a Pipeline holding only the real
// RecordStep so the stored Flows are what the live data path would persist.
func recordEnvelopesForQuery(t *testing.T, store flow.Store, envs ...*envelope.Envelope) {
	t.Helper()
	p := pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger()))
	for _, env := range envs {
		if _, action, _ := p.Run(context.Background(), env); action == pipeline.Drop {
			t.Fatalf("record pipeline dropped envelope %s", env.FlowID)
		}
	}
}

// queryMessagesForTest calls query resource=messages and decodes the result.
func queryMessagesForTest(t *testing.T, cs *gomcp.ClientSession, input queryInput) queryMessagesResult {
	t.Helper()
	input.Resource = "messages"
	result := callQuery(t, cs, input)
	if result.IsError {
		t.Fatalf("query messages error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)
	return out
}

// entryByFlowID returns the message entry whose id is flowID.
func entryByFlowID(t *testing.T, entries []queryMessageEntry, flowID string) queryMessageEntry {
	t.Helper()
	for _, e := range entries {
		if e.ID == flowID {
			return e
		}
	}
	t.Fatalf("no message entry with id %q in %d entries", flowID, len(entries))
	return queryMessageEntry{}
}

// decodeRawBytesField base64-decodes an entry's raw_bytes, failing the test
// when it is absent, not base64, or not labelled base64.
func decodeRawBytesField(t *testing.T, e queryMessageEntry) []byte {
	t.Helper()
	if e.RawBytes == "" {
		t.Fatalf("entry %s: raw_bytes is empty; want the stored wire bytes (body=%q)", e.ID, e.Body)
	}
	if e.RawBytesEncoding != "base64" {
		t.Errorf("entry %s: raw_bytes_encoding = %q, want %q", e.ID, e.RawBytesEncoding, "base64")
	}
	b, err := base64.StdEncoding.DecodeString(e.RawBytes)
	if err != nil {
		t.Fatalf("entry %s: raw_bytes is not base64: %v", e.ID, err)
	}
	return b
}

// Invented wire bytes (see file comment).
var (
	rawH1GetHead = []byte("GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n")
	// HPACK-shaped HEADERS block: :method GET, :scheme https, :path /, a
	// literal :authority.
	rawH2GetHPACK      = []byte{0x82, 0x87, 0x84, 0x41, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
	rawGRPCStartHPACK  = []byte{0x83, 0x87, 0x44, 0x0b, '/', 'p', 'k', 'g', '.', 'S', 'v', 'c', '/', 'M', 0x5f, 0x10, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c'}
	rawGRPCEndTrailers = []byte{0x40, 0x0b, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 0x01, '0'}
	rawWSPingEmpty     = []byte{0x89, 0x80, 0x01, 0x02, 0x03, 0x04}
	rawSSEEmptyData    = []byte("event: ping\n\n")
)

func h1GetEnvelope(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-send", Sequence: 0,
		Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Raw: rawH1GetHead,
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "http", Authority: "example.com", Path: "/x",
			HTTPVersion: "http/1.1",
			Headers:     []envelope.KeyValue{{Name: "Host", Value: "example.com"}, {Name: "User-Agent", Value: "t"}},
		},
	}
}

func grpcStartEnvelope(streamID string, raw []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-start", Sequence: 0,
		Direction: envelope.Send, Protocol: envelope.ProtocolGRPC,
		Raw: raw,
		Message: &envelope.GRPCStartMessage{
			Service: "pkg.Svc", Method: "M", Authority: "example.com", Scheme: "https",
			Path: "/pkg.Svc/M", ContentType: "application/grpc",
		},
	}
}

func grpcDataEnvelope(streamID string, seq int, dir envelope.Direction, payload []byte) *envelope.Envelope {
	lpm := append([]byte{0x00, 0x00, 0x00, 0x00, byte(len(payload))}, payload...)
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-data-" + dir.String(), Sequence: seq,
		Direction: dir, Protocol: envelope.ProtocolGRPC,
		Raw: lpm,
		Message: &envelope.GRPCDataMessage{
			Service: "pkg.Svc", Method: "M", WireLength: uint32(len(payload)), Payload: payload,
		},
	}
}

func grpcEndEnvelope(streamID string, seq int, raw []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-end", Sequence: seq,
		Direction: envelope.Receive, Protocol: envelope.ProtocolGRPC,
		Raw:     raw,
		Message: &envelope.GRPCEndMessage{Status: 0},
	}
}

// TestQueryMessages_BodylessMessage_RawBytesNotInBody covers every bodyless
// message shape: body stays empty and the stored wire bytes come back as
// raw_bytes (base64) with raw_bytes_size = stored length.
func TestQueryMessages_BodylessMessage_RawBytesNotInBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		streamID  string
		envs      func(streamID string) []*envelope.Envelope
		targetID  string // FlowID of the entry under test
		wantRaw   []byte
		wireLevel string
	}{
		{
			name:     "http1 GET",
			streamID: "rb-h1",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{h1GetEnvelope(id)}
			},
			targetID: "rb-h1-send",
			wantRaw:  rawH1GetHead,
		},
		{
			name:     "http2 GET",
			streamID: "rb-h2",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{{
					StreamID: id, FlowID: id + "-send", Sequence: 0,
					Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
					Raw: rawH2GetHPACK,
					Message: &envelope.HTTPMessage{
						Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
						HTTPVersion: "h2",
					},
				}}
			},
			targetID: "rb-h2-send",
			wantRaw:  rawH2GetHPACK,
		},
		{
			name:     "grpc Start",
			streamID: "rb-gs",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{grpcStartEnvelope(id, rawGRPCStartHPACK)}
			},
			targetID: "rb-gs-start",
			wantRaw:  rawGRPCStartHPACK,
		},
		{
			name:     "grpc End",
			streamID: "rb-ge",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{
					grpcStartEnvelope(id, rawGRPCStartHPACK),
					grpcEndEnvelope(id, 1, rawGRPCEndTrailers),
				}
			},
			targetID: "rb-ge-end",
			wantRaw:  rawGRPCEndTrailers,
		},
		{
			name:     "ws ping with empty payload",
			streamID: "rb-ws",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{{
					StreamID: id, FlowID: id + "-ping", Sequence: 0,
					Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
					Raw: rawWSPingEmpty,
					Message: &envelope.WSMessage{
						Opcode: envelope.WSPing, Fin: true, Masked: true, Mask: [4]byte{1, 2, 3, 4},
					},
				}}
			},
			targetID: "rb-ws-ping",
			wantRaw:  rawWSPingEmpty,
		},
		{
			name:     "sse event with empty data",
			streamID: "rb-sse",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{
					h1GetEnvelope(id),
					{
						StreamID: id, FlowID: id + "-event", Sequence: 1,
						Direction: envelope.Receive, Protocol: envelope.ProtocolSSE,
						Raw:     rawSSEEmptyData,
						Message: &envelope.SSEMessage{Event: "ping"},
					},
				}
			},
			targetID: "rb-sse-event",
			wantRaw:  rawSSEEmptyData,
		},
		{
			name:     "h2-frame overlay row",
			streamID: "rb-ov",
			envs: func(id string) []*envelope.Envelope {
				return []*envelope.Envelope{
					// Overlay first (aggregator path, USK-1197); nil Message
					// as in httpaggregator/channel.go.
					{
						StreamID: id, FlowID: id + "-frame", Sequence: 0,
						Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
						Raw:     []byte("a=1"),
						Context: envelope.EnvelopeContext{WireLevel: flow.WireLevelH2Frame},
					},
					{
						StreamID: id, FlowID: id + "-send", Sequence: 0,
						Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
						Raw: rawH2GetHPACK,
						Message: &envelope.HTTPMessage{
							Method: "POST", Scheme: "https", Authority: "example.com", Path: "/",
							HTTPVersion: "h2", Body: []byte("a=1"),
						},
					},
				}
			},
			targetID:  "rb-ov-frame",
			wantRaw:   []byte("a=1"),
			wireLevel: "all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			recordEnvelopesForQuery(t, store, tt.envs(tt.streamID)...)
			cs := setupQueryTestSession(t, store)

			in := queryInput{ID: tt.streamID}
			if tt.wireLevel != "" {
				in.Filter = &queryFilter{WireLevel: tt.wireLevel}
			}
			out := queryMessagesForTest(t, cs, in)
			got := entryByFlowID(t, out.Messages, tt.targetID)

			if got.Body != "" {
				t.Errorf("body = %q, want empty (raw wire bytes must not masquerade as the L7 body)", got.Body)
			}
			if got.BodyOriginalSize != 0 {
				t.Errorf("body_original_size = %d, want 0 (must not describe raw bytes)", got.BodyOriginalSize)
			}
			if got.BodyTruncatedByQuery {
				t.Errorf("body_truncated_by_query = true, want false (no cap requested)")
			}
			raw := decodeRawBytesField(t, got)
			if !bytes.Equal(raw, tt.wantRaw) {
				t.Errorf("raw_bytes = %q, want %q", raw, tt.wantRaw)
			}
			if got.RawBytesSize != len(tt.wantRaw) {
				t.Errorf("raw_bytes_size = %d, want %d", got.RawBytesSize, len(tt.wantRaw))
			}
		})
	}
}

// TestQueryMessages_BodyBearingMessage_NoRawBytes is a characterization guard:
// raw TCP chunks keep their bytes in `body` (envelopeToFlow sets Flow.Body =
// RawMessage.Bytes) and body-bearing messages never duplicate wire bytes into
// raw_bytes.
func TestQueryMessages_BodyBearingMessage_NoRawBytes(t *testing.T) {
	t.Parallel()

	chunk := []byte("EHLO example.com\r\n")
	tests := []struct {
		name     string
		env      *envelope.Envelope
		wantBody string
	}{
		{
			name: "raw tcp chunk",
			env: &envelope.Envelope{
				StreamID: "bb-raw", FlowID: "bb-raw-send", Sequence: 0,
				Direction: envelope.Send, Protocol: envelope.ProtocolRaw,
				Raw: chunk, Message: &envelope.RawMessage{Bytes: chunk},
			},
			wantBody: string(chunk),
		},
		{
			name: "http1 POST with body",
			env: &envelope.Envelope{
				StreamID: "bb-post", FlowID: "bb-post-send", Sequence: 0,
				Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
				Raw: []byte("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\na=1"),
				Message: &envelope.HTTPMessage{
					Method: "POST", Scheme: "http", Authority: "example.com", Path: "/x",
					Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
					Body:    []byte("a=1"),
				},
			},
			wantBody: "a=1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			recordEnvelopesForQuery(t, store, tt.env)
			cs := setupQueryTestSession(t, store)

			out := queryMessagesForTest(t, cs, queryInput{ID: tt.env.StreamID})
			got := entryByFlowID(t, out.Messages, tt.env.FlowID)
			if got.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", got.Body, tt.wantBody)
			}
			if got.RawBytes != "" || got.RawBytesEncoding != "" || got.RawBytesSize != 0 {
				t.Errorf("raw_bytes fields = (%q, %q, %d), want all empty for a body-bearing message",
					got.RawBytes, got.RawBytesEncoding, got.RawBytesSize)
			}
		})
	}
}

// TestQueryMessages_IncludeBodiesFalse_SuppressesRawBytes: include_bodies=false
// drops raw_bytes but still reports the stored raw length in raw_bytes_size.
func TestQueryMessages_IncludeBodiesFalse_SuppressesRawBytes(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	recordEnvelopesForQuery(t, store, h1GetEnvelope("ib-h1"))
	cs := setupQueryTestSession(t, store)

	off := false
	out := queryMessagesForTest(t, cs, queryInput{ID: "ib-h1", IncludeBodies: &off})
	got := entryByFlowID(t, out.Messages, "ib-h1-send")
	if got.Body != "" {
		t.Errorf("body = %q, want empty", got.Body)
	}
	if got.RawBytes != "" || got.RawBytesEncoding != "" {
		t.Errorf("raw_bytes = %q (encoding %q), want suppressed under include_bodies=false", got.RawBytes, got.RawBytesEncoding)
	}
	if !got.BodyTruncatedByQuery {
		t.Errorf("body_truncated_by_query = false, want true")
	}
	if got.BodyOriginalSize != 0 {
		t.Errorf("body_original_size = %d, want 0 (raw length must not be mixed in)", got.BodyOriginalSize)
	}
	if got.RawBytesSize != len(rawH1GetHead) {
		t.Errorf("raw_bytes_size = %d, want %d", got.RawBytesSize, len(rawH1GetHead))
	}
}

// TestQueryMessages_OutputFilter_MasksRawBytes: the SafetyFilter Output Filter
// applies to raw_bytes on both resource=messages and resource=flow
// message_preview, and the stored Flow.RawBytes is left untouched.
func TestQueryMessages_OutputFilter_MasksRawBytes(t *testing.T) {
	t.Parallel()
	const email = "admin@secret.com"
	store := newTestStore(t)

	h1 := h1GetEnvelope("of-h1")
	h1.Raw = []byte("GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nX-Contact: " + email + "\r\n\r\n")

	startRaw := append(append([]byte{0x83, 0x87, 0x40, 0x09}, "x-contact"...), byte(len(email)))
	startRaw = append(startRaw, email...)
	recordEnvelopesForQuery(t, store,
		h1,
		grpcStartEnvelope("of-grpc", startRaw),
		grpcDataEnvelope("of-grpc", 1, envelope.Send, []byte("req")),
		grpcDataEnvelope("of-grpc", 2, envelope.Receive, []byte("resp")),
		grpcEndEnvelope("of-grpc", 3, rawGRPCEndTrailers),
	)
	cs := setupQueryTestSession(t, store, WithSafetyEngine(newOutputMaskingSafetyEngine(t)))

	assertMasked := func(t *testing.T, where string, e queryMessageEntry) {
		t.Helper()
		raw := decodeRawBytesField(t, e)
		if bytes.Contains(raw, []byte(email)) {
			t.Errorf("%s: raw_bytes leaks %q: %q", where, email, raw)
		}
		if !bytes.Contains(raw, []byte("[EMAIL_REDACTED]")) {
			t.Errorf("%s: raw_bytes missing redaction marker: %q", where, raw)
		}
	}

	// resource=messages
	out := queryMessagesForTest(t, cs, queryInput{ID: "of-h1"})
	assertMasked(t, "messages", entryByFlowID(t, out.Messages, "of-h1-send"))

	// resource=flow message_preview
	res := callQuery(t, cs, queryInput{Resource: "flow", ID: "of-grpc"})
	if res.IsError {
		t.Fatalf("query flow error: %v", res.Content)
	}
	var fr queryFlowResult
	unmarshalQueryResult(t, res, &fr)
	assertMasked(t, "message_preview", entryByFlowID(t, fr.MessagePreview, "of-grpc-start"))

	// Stored wire bytes stay original (MITM principle 7).
	for _, id := range []string{"of-h1", "of-grpc"} {
		flows, err := store.GetFlows(context.Background(), id, flow.FlowListOptions{Direction: "send"})
		if err != nil {
			t.Fatalf("GetFlows(%s): %v", id, err)
		}
		if len(flows) == 0 || !bytes.Contains(flows[0].RawBytes, []byte(email)) {
			t.Errorf("stored Flow.RawBytes for %s lost the original email (stored copy must not be masked)", id)
		}
	}
}

// TestQueryMessages_OutputFilter_RawBytesMaskedBeforeCap: masking runs on the
// full stored raw bytes before body_max_bytes truncation, so a cap that falls
// mid-match cannot leak a partial fragment the regex would no longer match.
func TestQueryMessages_OutputFilter_RawBytesMaskedBeforeCap(t *testing.T) {
	t.Parallel()
	const email = "admin@secret.com"
	store := newTestStore(t)
	env := h1GetEnvelope("mc-h1")
	env.Raw = []byte("GET http://example.com/x HTTP/1.1\r\nX-Contact: " + email + "\r\nHost: example.com\r\n\r\n")
	recordEnvelopesForQuery(t, store, env)
	cs := setupQueryTestSession(t, store, WithSafetyEngine(newOutputMaskingSafetyEngine(t)))

	// Cap lands inside the email: "...X-Contact: admin@secr".
	capAt := bytes.Index(env.Raw, []byte(email)) + len("admin@secr")
	out := queryMessagesForTest(t, cs, queryInput{ID: "mc-h1", BodyMaxBytes: capAt})
	got := entryByFlowID(t, out.Messages, "mc-h1-send")
	raw := decodeRawBytesField(t, got)
	if bytes.Contains(raw, []byte("admin@")) {
		t.Errorf("raw_bytes leaks a partial email fragment (masked after cap?): %q", raw)
	}
	if len(raw) != capAt {
		t.Errorf("raw_bytes length = %d, want %d (capped)", len(raw), capAt)
	}
	if !got.BodyTruncatedByQuery {
		t.Errorf("body_truncated_by_query = false, want true")
	}
	if got.RawBytesSize != len(env.Raw) {
		t.Errorf("raw_bytes_size = %d, want stored length %d", got.RawBytesSize, len(env.Raw))
	}
}

// TestQueryFlow_MessagePreview_GRPCRawBytes: in a gRPC stream preview, the
// bodyless Start / End entries carry raw_bytes while Data entries keep their
// payload in body and carry no raw_bytes.
func TestQueryFlow_MessagePreview_GRPCRawBytes(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	recordEnvelopesForQuery(t, store,
		grpcStartEnvelope("mp-grpc", rawGRPCStartHPACK),
		grpcDataEnvelope("mp-grpc", 1, envelope.Send, []byte("hello")),
		grpcDataEnvelope("mp-grpc", 2, envelope.Receive, []byte("world")),
		grpcEndEnvelope("mp-grpc", 3, rawGRPCEndTrailers),
	)
	cs := setupQueryTestSession(t, store)

	res := callQuery(t, cs, queryInput{Resource: "flow", ID: "mp-grpc"})
	if res.IsError {
		t.Fatalf("query flow error: %v", res.Content)
	}
	var fr queryFlowResult
	unmarshalQueryResult(t, res, &fr)

	for id, wantRaw := range map[string][]byte{
		"mp-grpc-start": rawGRPCStartHPACK,
		"mp-grpc-end":   rawGRPCEndTrailers,
	} {
		e := entryByFlowID(t, fr.MessagePreview, id)
		if e.Body != "" {
			t.Errorf("%s: body = %q, want empty", id, e.Body)
		}
		if raw := decodeRawBytesField(t, e); !bytes.Equal(raw, wantRaw) {
			t.Errorf("%s: raw_bytes = %x, want %x", id, raw, wantRaw)
		}
	}
	for id, wantBody := range map[string]string{
		"mp-grpc-data-send":    "hello",
		"mp-grpc-data-receive": "world",
	} {
		e := entryByFlowID(t, fr.MessagePreview, id)
		if e.Body != wantBody {
			t.Errorf("%s: body = %q, want %q", id, e.Body, wantBody)
		}
		if e.RawBytes != "" {
			t.Errorf("%s: raw_bytes = %q, want empty for a body-bearing Data message", id, e.RawBytes)
		}
	}
}

// TestMessagesHaveOversizedBody_MatchesEmittedFields: the oversize advisory
// reflects what the response would actually carry — a large body, or large
// raw bytes on a bodyless message. Large raw bytes behind a small body are
// not emitted and must not trigger the advisory.
func TestMessagesHaveOversizedBody_MatchesEmittedFields(t *testing.T) {
	t.Parallel()
	big := []byte(strings.Repeat("x", oversizeAdvisoryThreshold+1))
	tests := []struct {
		name string
		msg  *flow.Flow
		want bool
	}{
		{"large body", &flow.Flow{Body: big}, true},
		{"bodyless with large raw", &flow.Flow{RawBytes: big}, true},
		{"small body with large raw", &flow.Flow{Body: []byte("a"), RawBytes: big}, false},
		{"small both", &flow.Flow{Body: []byte("a"), RawBytes: []byte("b")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messagesHaveOversizedBody([]*flow.Flow{tt.msg}); got != tt.want {
				t.Errorf("messagesHaveOversizedBody = %v, want %v", got, tt.want)
			}
			if got := flowHasOversizedBody(categorizedMessages{}, []*flow.Flow{tt.msg}); got != tt.want {
				t.Errorf("flowHasOversizedBody = %v, want %v", got, tt.want)
			}
		})
	}
}
