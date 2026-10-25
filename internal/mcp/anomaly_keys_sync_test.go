package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestHTTPAnomalyKeys_InSyncWithRecordStep fails when the producer table
// (pipeline RecordStep's AnomalyType → Metadata key) and the query tool's
// reverse table (flowMetadataAnomalyKeyToType) diverge (USK-1229 review
// F-3). A key the producer writes but the query side does not decode
// surfaces as its raw Metadata key instead of the AnomalyType; a key the
// query side decodes but nothing writes is dead.
func TestHTTPAnomalyKeys_InSyncWithRecordStep(t *testing.T) {
	produced := pipeline.HTTPAnomalyMetadataKeys()
	if len(produced) == 0 {
		t.Fatal("pipeline.HTTPAnomalyMetadataKeys() is empty")
	}
	for typ, key := range produced {
		got, ok := flowMetadataAnomalyKeyToType[key]
		if !ok {
			t.Errorf("RecordStep writes %q for %s, but flowMetadataAnomalyKeyToType has no entry", key, typ)
			continue
		}
		if got != string(typ) {
			t.Errorf("flowMetadataAnomalyKeyToType[%q] = %q, want %q", key, got, typ)
		}
	}
	keyToType := make(map[string]envelope.AnomalyType, len(produced))
	for typ, key := range produced {
		keyToType[key] = typ
	}
	for key, typ := range flowMetadataAnomalyKeyToType {
		if !strings.HasPrefix(key, "http_anomaly_") {
			continue
		}
		pt, ok := keyToType[key]
		if !ok {
			t.Errorf("flowMetadataAnomalyKeyToType decodes %q (%s), but RecordStep never writes it", key, typ)
			continue
		}
		if string(pt) != typ {
			t.Errorf("RecordStep writes %q for %s, query decodes it as %s", key, pt, typ)
		}
	}
}

// TestQuery_TruncatedBodyAnomaly_RoundTrip records a response carrying the
// TruncatedBody anomaly through the real RecordStep and reads it back with
// the query tool (USK-1229 review F-3).
func TestQuery_TruncatedBodyAnomaly_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	p := pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger()))

	const streamID = "stream-usk1229-truncated"
	const detail = "connection closed after 10 of 100 Content-Length body bytes"
	p.Run(ctx, &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "flow-usk1229-req",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/",
			Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	})
	p.Run(ctx, &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "flow-usk1229-resp",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"),
		Message: &envelope.HTTPMessage{
			Status:    200,
			Headers:   []envelope.KeyValue{{Name: "Content-Length", Value: "100"}},
			Body:      []byte("0123456789"),
			Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyTruncatedBody, Detail: detail}},
		},
	})

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: streamID})
	if result.IsError {
		t.Fatalf("query flow: %v", result.Content)
	}
	var got queryFlowResult
	unmarshalQueryResult(t, result, &got)
	for _, a := range got.Anomalies {
		if a.Type == string(envelope.AnomalyTruncatedBody) {
			if a.Detail != detail {
				t.Errorf("TruncatedBody Detail = %q, want %q", a.Detail, detail)
			}
			return
		}
	}
	t.Fatalf("query flow anomalies = %+v, want %s", got.Anomalies, envelope.AnomalyTruncatedBody)
}

// TestQuery_RawHeaderTruncatedAnomaly_RoundTrip records a request whose
// header section exceeded max_raw_capture_size (USK-1320) through the real
// RecordStep and reads the RawHeaderTruncated anomaly back with the query
// tool, so a capped record is discoverable.
func TestQuery_RawHeaderTruncatedAnomaly_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	p := pipeline.New(pipeline.NewRecordStep(store, testutil.DiscardLogger()))

	const streamID = "stream-usk1320-raw-header-truncated"
	const detail = "RawBytes capped at 17 of 40 header bytes"
	p.Run(ctx, &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "flow-usk1320-req",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\nH"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/",
			Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
			Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyRawHeaderTruncated, Detail: detail}},
		},
	})

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: streamID})
	if result.IsError {
		t.Fatalf("query flow: %v", result.Content)
	}
	var got queryFlowResult
	unmarshalQueryResult(t, result, &got)
	for _, a := range got.Anomalies {
		if a.Type == string(envelope.AnomalyRawHeaderTruncated) {
			if a.Detail != detail {
				t.Errorf("RawHeaderTruncated Detail = %q, want %q", a.Detail, detail)
			}
			return
		}
	}
	t.Fatalf("query flow anomalies = %+v, want %s", got.Anomalies, envelope.AnomalyRawHeaderTruncated)
}
