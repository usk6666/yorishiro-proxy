package flow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// makeTestSession creates a test flow with messages in the store.
func makeTestSession(t *testing.T, store *SQLiteStore, id, protocol, urlStr string, ts time.Time, body []byte) {
	t.Helper()
	ctx := context.Background()

	fl := &Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  150 * time.Millisecond,
		Tags:      map[string]string{"env": "test"},
		ConnInfo: &ConnectionInfo{
			ClientAddr:           "127.0.0.1:12345",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Message{
		ID:        "msg-send-" + id,
		FlowID:    id,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "GET",
		URL:       mustParseURL(urlStr),
		Headers:   map[string][]string{"Host": {"example.com"}, "Accept": {"text/html"}},
		Body:      body,
		RawBytes:  []byte("GET " + urlStr + " HTTP/1.1\r\n"),
		Metadata:  map[string]string{"key": "value"},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &Message{
		ID:            "msg-recv-" + id,
		FlowID:        id,
		Sequence:      1,
		Direction:     "receive",
		Timestamp:     ts.Add(100 * time.Millisecond),
		StatusCode:    200,
		Headers:       map[string][]string{"Content-Type": {"text/html"}},
		Body:          []byte("<html>OK</html>"),
		BodyTruncated: false,
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	body := []byte(`{"user":"admin","role":"root"}`)
	makeTestSession(t, store, "fl-1", "HTTPS", "https://example.com/api/users", ts, body)
	makeTestSession(t, store, "fl-2", "HTTP/1.x", "http://example.com/index.html", ts.Add(time.Hour), []byte("hello"))

	// Export all sessions
	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 exported, got %d", n)
	}

	// Import into a fresh store
	store2 := newTestStore(t)
	result, err := ImportFlows(ctx, store2, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}

	// Verify imported data matches
	for _, id := range []string{"fl-1", "fl-2"} {
		origSess, err := store.GetFlow(ctx, id)
		if err != nil {
			t.Fatalf("GetFlow(%s) from original: %v", id, err)
		}
		importedSess, err := store2.GetFlow(ctx, id)
		if err != nil {
			t.Fatalf("GetFlow(%s) from imported: %v", id, err)
		}

		if origSess.Protocol != importedSess.Protocol {
			t.Errorf("session %s protocol: got %s, want %s", id, importedSess.Protocol, origSess.Protocol)
		}
		if origSess.FlowType != importedSess.FlowType {
			t.Errorf("session %s session_type: got %s, want %s", id, importedSess.FlowType, origSess.FlowType)
		}
		if origSess.State != importedSess.State {
			t.Errorf("session %s state: got %s, want %s", id, importedSess.State, origSess.State)
		}
		if !origSess.Timestamp.Equal(importedSess.Timestamp) {
			t.Errorf("session %s timestamp: got %v, want %v", id, importedSess.Timestamp, origSess.Timestamp)
		}
		if origSess.Duration != importedSess.Duration {
			t.Errorf("session %s duration: got %v, want %v", id, importedSess.Duration, origSess.Duration)
		}
		if origSess.ConnInfo != nil && importedSess.ConnInfo != nil {
			if origSess.ConnInfo.TLSVersion != importedSess.ConnInfo.TLSVersion {
				t.Errorf("session %s TLSVersion mismatch", id)
			}
		}

		// Verify messages
		origMsgs, _ := store.GetMessages(ctx, id, MessageListOptions{})
		importedMsgs, _ := store2.GetMessages(ctx, id, MessageListOptions{})
		if len(origMsgs) != len(importedMsgs) {
			t.Errorf("session %s message count: got %d, want %d", id, len(importedMsgs), len(origMsgs))
			continue
		}
		for i := range origMsgs {
			if origMsgs[i].Direction != importedMsgs[i].Direction {
				t.Errorf("message %d direction: got %s, want %s", i, importedMsgs[i].Direction, origMsgs[i].Direction)
			}
			if !bytes.Equal(origMsgs[i].Body, importedMsgs[i].Body) {
				t.Errorf("message %d body mismatch", i)
			}
			if !bytes.Equal(origMsgs[i].RawBytes, importedMsgs[i].RawBytes) {
				t.Errorf("message %d raw_bytes mismatch", i)
			}
			if origMsgs[i].Method != importedMsgs[i].Method {
				t.Errorf("message %d method: got %s, want %s", i, importedMsgs[i].Method, origMsgs[i].Method)
			}
			if origMsgs[i].StatusCode != importedMsgs[i].StatusCode {
				t.Errorf("message %d status_code: got %d, want %d", i, importedMsgs[i].StatusCode, origMsgs[i].StatusCode)
			}
			origURL := ""
			if origMsgs[i].URL != nil {
				origURL = origMsgs[i].URL.String()
			}
			importedURL := ""
			if importedMsgs[i].URL != nil {
				importedURL = importedMsgs[i].URL.String()
			}
			if origURL != importedURL {
				t.Errorf("message %d URL: got %s, want %s", i, importedURL, origURL)
			}
		}
	}
}

func TestExportWithProtocolFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-https", "HTTPS", "https://example.com/api", ts, nil)
	makeTestSession(t, store, "fl-http", "HTTP/1.x", "http://example.com/", ts, nil)

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		Filter:        ExportFilter{Protocol: "HTTPS"},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported with HTTPS filter, got %d", n)
	}

	// Verify it's the HTTPS session
	var record ExportRecord
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.Flow.Protocol != "HTTPS" {
		t.Errorf("expected HTTPS, got %s", record.Flow.Protocol)
	}
}

func TestExportWithURLPatternFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-api", "HTTPS", "https://example.com/api/users", ts, nil)
	makeTestSession(t, store, "fl-home", "HTTPS", "https://example.com/index.html", ts, nil)

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		Filter:        ExportFilter{URLPattern: "/api/"},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported with /api/ URL filter, got %d", n)
	}
}

func TestExportWithTimeFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	t1 := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-jan", "HTTPS", "https://example.com/jan", t1, nil)
	makeTestSession(t, store, "fl-feb", "HTTPS", "https://example.com/feb", t2, nil)
	makeTestSession(t, store, "fl-mar", "HTTPS", "https://example.com/mar", t3, nil)

	after := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		Filter: ExportFilter{
			TimeAfter:  &after,
			TimeBefore: &before,
		},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 flow in February, got %d", n)
	}
}

func TestExportMetadataOnly(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-meta", "HTTPS", "https://example.com/api", ts, []byte("request body"))

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		IncludeBodies: false,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported, got %d", n)
	}

	var record ExportRecord
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, msg := range record.Messages {
		if msg.Body != "" {
			t.Errorf("expected empty body with include_bodies=false, got %q", msg.Body)
		}
		if msg.RawBytes != "" {
			t.Errorf("expected empty raw_bytes with include_bodies=false, got %q", msg.RawBytes)
		}
		// Metadata fields should still be present
		if msg.Direction == "" {
			t.Errorf("expected direction to be present")
		}
	}
}

func TestImportConflictSkip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-existing", "HTTPS", "https://example.com/api", ts, []byte("original"))

	// Export from another store with same ID
	store2 := newTestStore(t)
	makeTestSession(t, store2, "fl-existing", "HTTP/1.x", "http://example.com/different", ts, []byte("different"))

	var buf bytes.Buffer
	_, err := ExportFlows(ctx, store2, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}

	// Import with skip policy
	result, err := ImportFlows(ctx, store, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}

	// Verify original data is preserved
	fl, err := store.GetFlow(ctx, "fl-existing")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.Protocol != "HTTPS" {
		t.Errorf("expected original protocol HTTPS, got %s", fl.Protocol)
	}
}

func TestImportConflictReplace(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-replace", "HTTPS", "https://example.com/api", ts, []byte("original"))

	// Export from another store with same ID but different data
	store2 := newTestStore(t)
	makeTestSession(t, store2, "fl-replace", "HTTP/1.x", "http://example.com/different", ts, []byte("replaced"))

	var buf bytes.Buffer
	_, err := ExportFlows(ctx, store2, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}

	// Import with replace policy
	result, err := ImportFlows(ctx, store, &buf, ImportOptions{OnConflict: ConflictReplace})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}

	// Verify replaced data
	fl, err := store.GetFlow(ctx, "fl-replace")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("expected replaced protocol HTTP/1.x, got %s", fl.Protocol)
	}
}

func TestImportInvalidJSONL(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Mix of valid and invalid lines
	data := `not json at all
{"flow":null,"messages":[],"version":"1"}
{"flow":{"id":"good","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}
{"broken json
`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Errors != 3 {
		t.Errorf("expected 3 errors, got %d", result.Errors)
	}
	// Verify error details are populated.
	if len(result.ErrorDetails) != 3 {
		t.Errorf("expected 3 error details, got %d", len(result.ErrorDetails))
	}
	if len(result.ErrorDetails) >= 1 {
		if result.ErrorDetails[0].Line != 1 {
			t.Errorf("expected error on line 1, got %d", result.ErrorDetails[0].Line)
		}
		if !strings.Contains(result.ErrorDetails[0].Reason, "invalid JSON") {
			t.Errorf("expected 'invalid JSON' reason, got %q", result.ErrorDetails[0].Reason)
		}
	}
	if len(result.ErrorDetails) >= 2 {
		if result.ErrorDetails[1].Line != 2 {
			t.Errorf("expected error on line 2, got %d", result.ErrorDetails[1].Line)
		}
		if !strings.Contains(result.ErrorDetails[1].Reason, "missing flow") {
			t.Errorf("expected 'missing flow' reason, got %q", result.ErrorDetails[1].Reason)
		}
	}
}

func TestImportInvalidVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	data := `{"flow":{"id":"ver2","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"2"}`

	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported for version mismatch, got %d", result.Imported)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error for version mismatch, got %d", result.Errors)
	}
	// Verify error detail includes version info.
	if len(result.ErrorDetails) != 1 {
		t.Fatalf("expected 1 error detail, got %d", len(result.ErrorDetails))
	}
	if !strings.Contains(result.ErrorDetails[0].Reason, "unsupported version") {
		t.Errorf("expected 'unsupported version' reason, got %q", result.ErrorDetails[0].Reason)
	}
	if result.ErrorDetails[0].FlowID != "ver2" {
		t.Errorf("expected flow_id 'ver2', got %q", result.ErrorDetails[0].FlowID)
	}
}

func TestImportEmptyLines(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	data := "\n\n\n"
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported for empty lines, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors for empty lines, got %d", result.Errors)
	}
}

func TestExportJSONLFormat(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-format", "HTTPS", "https://example.com/api", ts, []byte("binary\x00data"))

	var buf bytes.Buffer
	_, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}

	// Each line should be valid JSON
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var record ExportRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}

	if record.Version != "1" {
		t.Errorf("expected version 1, got %s", record.Version)
	}
	if record.Flow.ID != "fl-format" {
		t.Errorf("expected flow ID fl-format, got %s", record.Flow.ID)
	}
	if record.Flow.Protocol != "HTTPS" {
		t.Errorf("expected protocol HTTPS, got %s", record.Flow.Protocol)
	}

	// Body should be Base64 encoded
	for _, msg := range record.Messages {
		if msg.Direction == "send" && msg.Body != "" {
			decoded, err := base64.StdEncoding.DecodeString(msg.Body)
			if err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !bytes.Equal(decoded, []byte("binary\x00data")) {
				t.Errorf("body mismatch after base64 roundtrip")
			}
		}
	}
}

func TestExportNoSessions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 exported from empty store, got %d", n)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", buf.Len())
	}
}

func TestLargeExportImport(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping large export/import test in short mode")
	}

	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	const count = 1000
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("fl-large-%04d", i)
		makeTestSession(t, store, id, "HTTPS", fmt.Sprintf("https://example.com/api/%d", i), ts.Add(time.Duration(i)*time.Second), []byte(fmt.Sprintf("body-%d", i)))
	}

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != count {
		t.Fatalf("expected %d exported, got %d", count, n)
	}

	store2 := newTestStore(t)
	result, err := ImportFlows(ctx, store2, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != count {
		t.Errorf("expected %d imported, got %d", count, result.Imported)
	}
}

func TestExportSessionWithNilConnInfo(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	fl := &Flow{
		ID:        "fl-noconn",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	// Import and verify
	store2 := newTestStore(t)
	result, err := ImportFlows(ctx, store2, &buf, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}

	imported, err := store2.GetFlow(ctx, "fl-noconn")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if imported.Protocol != "HTTP/1.x" {
		t.Errorf("expected HTTP/1.x, got %s", imported.Protocol)
	}
}

func TestExportImportWithURLMessage(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	fl := &Flow{
		ID:        "fl-url",
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	complexURL, _ := url.Parse("https://example.com/path?key=value&foo=bar#fragment")
	msg := &Message{
		ID:        "msg-url-1",
		FlowID:    "fl-url",
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "POST",
		URL:       complexURL,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"test":true}`),
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	var buf bytes.Buffer
	_, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}

	store2 := newTestStore(t)
	result, err := ImportFlows(ctx, store2, &buf, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}

	msgs, err := store2.GetMessages(ctx, "fl-url", MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].URL == nil {
		t.Fatal("expected URL to be present")
	}
	if msgs[0].URL.String() != complexURL.String() {
		t.Errorf("URL mismatch: got %s, want %s", msgs[0].URL.String(), complexURL.String())
	}
}

func TestExportImportDefaultConflictPolicy(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-default", "HTTPS", "https://example.com/", ts, nil)

	var buf bytes.Buffer
	_, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}

	// Import with empty OnConflict (should default to skip)
	result, err := ImportFlows(ctx, store, bytes.NewReader(buf.Bytes()), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped with default policy, got %d", result.Skipped)
	}
}

func TestExportCombinedFilters(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	t1 := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-1", "HTTPS", "https://example.com/api/v1", t1, nil)
	makeTestSession(t, store, "fl-2", "HTTP/1.x", "http://example.com/api/v2", t2, nil)
	makeTestSession(t, store, "fl-3", "HTTPS", "https://example.com/api/v3", t3, nil)
	makeTestSession(t, store, "fl-4", "HTTPS", "https://example.com/other", t2, nil)

	after := time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		Filter: ExportFilter{
			Protocol:   "HTTPS",
			URLPattern: "/api/",
			TimeAfter:  &after,
			TimeBefore: &before,
		},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	// Only fl-1 is HTTPS+/api/ but before time_after (excluded)
	// fl-2 is HTTP/1.x (excluded by protocol)
	// fl-3 is HTTPS+/api/ but after time_before (excluded)
	// fl-4 is HTTPS but no /api/ (excluded by URL)
	// None should match all filters
	if n != 0 {
		t.Errorf("expected 0 with combined filters, got %d", n)
	}
}

func TestExportMaxFlows(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	// Create 10 sessions
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("fl-max-%02d", i)
		makeTestSession(t, store, id, "HTTPS", fmt.Sprintf("https://example.com/%d", i), ts.Add(time.Duration(i)*time.Second), nil)
	}

	// Export with limit of 3
	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		IncludeBodies: true,
		MaxFlows:      3,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 exported with MaxFlows=3, got %d", n)
	}

	// Count JSONL lines
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 JSONL lines, got %d", len(lines))
	}
}

func TestExportMaxFlowsZeroMeansNoLimit(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("fl-nolimit-%02d", i)
		makeTestSession(t, store, id, "HTTPS", fmt.Sprintf("https://example.com/%d", i), ts.Add(time.Duration(i)*time.Second), nil)
	}

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{
		IncludeBodies: true,
		MaxFlows:      0,
	})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 exported with MaxFlows=0 (no limit), got %d", n)
	}
}

func TestImportValidateIDs_ValidUUIDs(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Use valid UUIDs
	data := `{"flow":{"id":"550e8400-e29b-41d4-a716-446655440000","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","flow_id":"550e8400-e29b-41d4-a716-446655440000","sequence":0,"direction":"send","timestamp":"2026-02-15T10:00:00Z"}],"version":"1"}`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{ValidateIDs: true})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported with valid UUIDs, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
}

func TestImportValidateIDs_InvalidSessionID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Flow ID is not a valid UUID
	data := `{"flow":{"id":"not-a-uuid","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{ValidateIDs: true})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported with invalid flow UUID, got %d", result.Imported)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error for invalid flow UUID, got %d", result.Errors)
	}
	// Verify error detail contains UUID info.
	if len(result.ErrorDetails) != 1 {
		t.Fatalf("expected 1 error detail, got %d", len(result.ErrorDetails))
	}
	if !strings.Contains(result.ErrorDetails[0].Reason, "invalid flow UUID") {
		t.Errorf("expected 'invalid flow UUID' reason, got %q", result.ErrorDetails[0].Reason)
	}
}

func TestImportValidateIDs_InvalidMessageID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Flow ID is valid UUID, but message ID is not
	data := `{"flow":{"id":"550e8400-e29b-41d4-a716-446655440000","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[{"id":"bad-msg-id","flow_id":"550e8400-e29b-41d4-a716-446655440000","sequence":0,"direction":"send","timestamp":"2026-02-15T10:00:00Z"}],"version":"1"}`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{ValidateIDs: true})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported with invalid message UUID, got %d", result.Imported)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error for invalid message UUID, got %d", result.Errors)
	}
	// Verify error detail contains message UUID info.
	if len(result.ErrorDetails) != 1 {
		t.Fatalf("expected 1 error detail, got %d", len(result.ErrorDetails))
	}
	if !strings.Contains(result.ErrorDetails[0].Reason, "invalid message UUID") {
		t.Errorf("expected 'invalid message UUID' reason, got %q", result.ErrorDetails[0].Reason)
	}
}

func TestImportValidateIDs_DisabledByDefault(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Non-UUID IDs should be accepted when ValidateIDs is false (default)
	data := `{"flow":{"id":"custom-id","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{ValidateIDs: false})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported with ValidateIDs=false, got %d", result.Imported)
	}
}

func TestImportMaxScannerBuffer(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a JSONL line that definitely exceeds the small buffer limit (256 bytes).
	// The base JSON structure alone is ~200 bytes; adding a long body ensures it exceeds 256.
	longBody := strings.Repeat("A", 512)
	data := fmt.Sprintf(`{"flow":{"id":"fl-buf","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[{"id":"msg-buf","flow_id":"fl-buf","sequence":0,"direction":"send","timestamp":"2026-02-15T10:00:00Z","body":"%s"}],"version":"1"}`, longBody)

	if len(data) <= 256 {
		t.Fatalf("test data should exceed 256 bytes, got %d", len(data))
	}

	// With a very small buffer, the scanner should fail
	_, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{
		MaxScannerBuffer: 256,
	})
	if err == nil {
		t.Fatal("expected error with small scanner buffer, got nil")
	}
	if !strings.Contains(err.Error(), "read import data") {
		t.Errorf("expected scanner error, got: %v", err)
	}
}

func TestImportDefaultScannerBuffer(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Normal data should work with default buffer
	data := `{"flow":{"id":"fl-defbuf","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`
	result, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

func TestImportErrorDetails_SaveSessionFailure(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow that will cause a duplicate key error when imported twice.
	sessID := "550e8400-e29b-41d4-a716-446655440099"
	data := fmt.Sprintf(`{"flow":{"id":"%s","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`, sessID)

	// First import: should succeed.
	r1, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("first ImportFlows: %v", err)
	}
	if r1.Imported != 1 {
		t.Fatalf("first import: expected 1 imported, got %d", r1.Imported)
	}

	// Second import with skip: should skip.
	r2, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("second ImportFlows: %v", err)
	}
	if r2.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", r2.Skipped)
	}

	// Second import with replace: should succeed.
	r3, err := ImportFlows(ctx, store, strings.NewReader(data), ImportOptions{OnConflict: ConflictReplace})
	if err != nil {
		t.Fatalf("third ImportFlows: %v", err)
	}
	if r3.Imported != 1 {
		t.Errorf("expected 1 imported with replace, got %d", r3.Imported)
	}
	if r3.Errors != 0 {
		t.Errorf("expected 0 errors with replace, got %d", r3.Errors)
		for _, e := range r3.ErrorDetails {
			t.Errorf("  line %d: %s", e.Line, e.Reason)
		}
	}
}

func TestImportErrorDetailsCap(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create more invalid lines than maxErrorDetails to test capping.
	var lines strings.Builder
	for i := 0; i < maxErrorDetails+10; i++ {
		lines.WriteString("not valid json\n")
	}
	result, err := ImportFlows(ctx, store, strings.NewReader(lines.String()), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Errors != maxErrorDetails+10 {
		t.Errorf("expected %d errors, got %d", maxErrorDetails+10, result.Errors)
	}
	if len(result.ErrorDetails) != maxErrorDetails {
		t.Errorf("expected error_details capped at %d, got %d", maxErrorDetails, len(result.ErrorDetails))
	}
}

func TestExportImportRoundTrip_WithValidateIDs(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	// Use real UUID IDs like the production system
	sessID := "550e8400-e29b-41d4-a716-446655440001"
	msgSendID := "550e8400-e29b-41d4-a716-446655440002"
	msgRecvID := "550e8400-e29b-41d4-a716-446655440003"

	fl := &Flow{
		ID:        sessID,
		ConnID:    "conn-" + sessID,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  150 * time.Millisecond,
		Tags:      map[string]string{"env": "test"},
		ConnInfo: &ConnectionInfo{
			ClientAddr:           "127.0.0.1:12345",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Message{
		ID:        msgSendID,
		FlowID:    sessID,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "GET",
		URL:       mustParseURL("https://example.com/api/users"),
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      []byte(`{"user":"admin"}`),
		RawBytes:  []byte("GET /api/users HTTP/1.1\r\n"),
		Metadata:  map[string]string{"key": "value"},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &Message{
		ID:         msgRecvID,
		FlowID:     sessID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  ts.Add(100 * time.Millisecond),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"text/html"}},
		Body:       []byte("<html>OK</html>"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}

	// Export
	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported, got %d", n)
	}

	t.Logf("Exported JSONL:\n%s", buf.String())

	// Import into a fresh store with ValidateIDs: true (like MCP handler does)
	store2 := newTestStore(t)
	result, err := ImportFlows(ctx, store2, &buf, ImportOptions{
		OnConflict:  ConflictSkip,
		ValidateIDs: true,
	})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
}

// TestExportDeleteAllImportRoundTrip is a regression test for BUG-001:
// after DeleteAllFlows, orphan messages could remain if foreign_keys was OFF
// on the connection that executed the DELETE, causing UNIQUE constraint errors
// on re-import.
func TestExportDeleteAllImportRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "fl-1", "HTTPS", "https://example.com/api", ts, []byte("body1"))
	makeTestSession(t, store, "fl-2", "HTTP/1.x", "http://example.com/", ts.Add(time.Hour), []byte("body2"))

	var buf bytes.Buffer
	n, err := ExportFlows(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportFlows: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 exported, got %d", n)
	}

	deleted, err := store.DeleteAllFlows(ctx)
	if err != nil {
		t.Fatalf("DeleteAllFlows: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deleted, got %d", deleted)
	}

	result, err := ImportFlows(ctx, store, bytes.NewReader(buf.Bytes()), ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportFlows: %v", err)
	}
	if result.Errors != 0 {
		for _, e := range result.ErrorDetails {
			t.Errorf("import error line %d (flow %s): %s", e.Line, e.FlowID, e.Reason)
		}
		t.Fatalf("expected 0 errors, got %d", result.Errors)
	}
	if result.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", result.Imported)
	}
}
