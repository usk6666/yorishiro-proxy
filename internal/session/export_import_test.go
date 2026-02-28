package session

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

// makeTestSession creates a test session with messages in the store.
func makeTestSession(t *testing.T, store *SQLiteStore, id, protocol, urlStr string, ts time.Time, body []byte) {
	t.Helper()
	ctx := context.Background()

	sess := &Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   ts,
		Duration:    150 * time.Millisecond,
		Tags:        map[string]string{"env": "test"},
		ConnInfo: &ConnectionInfo{
			ClientAddr:           "127.0.0.1:12345",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	sendMsg := &Message{
		ID:        "msg-send-" + id,
		SessionID: id,
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
		SessionID:     id,
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
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	body := []byte(`{"user":"admin","role":"root"}`)
	makeTestSession(t, store, "sess-1", "HTTPS", "https://example.com/api/users", ts, body)
	makeTestSession(t, store, "sess-2", "HTTP/1.x", "http://example.com/index.html", ts.Add(time.Hour), []byte("hello"))

	// Export all sessions
	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 exported, got %d", n)
	}

	// Import into a fresh store
	store2 := newTestStore(t)
	result, err := ImportSessions(ctx, store2, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
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
	for _, id := range []string{"sess-1", "sess-2"} {
		origSess, err := store.GetSession(ctx, id)
		if err != nil {
			t.Fatalf("GetSession(%s) from original: %v", id, err)
		}
		importedSess, err := store2.GetSession(ctx, id)
		if err != nil {
			t.Fatalf("GetSession(%s) from imported: %v", id, err)
		}

		if origSess.Protocol != importedSess.Protocol {
			t.Errorf("session %s protocol: got %s, want %s", id, importedSess.Protocol, origSess.Protocol)
		}
		if origSess.SessionType != importedSess.SessionType {
			t.Errorf("session %s session_type: got %s, want %s", id, importedSess.SessionType, origSess.SessionType)
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
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-https", "HTTPS", "https://example.com/api", ts, nil)
	makeTestSession(t, store, "sess-http", "HTTP/1.x", "http://example.com/", ts, nil)

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{
		Filter:        ExportFilter{Protocol: "HTTPS"},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported with HTTPS filter, got %d", n)
	}

	// Verify it's the HTTPS session
	var record ExportRecord
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.Session.Protocol != "HTTPS" {
		t.Errorf("expected HTTPS, got %s", record.Session.Protocol)
	}
}

func TestExportWithURLPatternFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-api", "HTTPS", "https://example.com/api/users", ts, nil)
	makeTestSession(t, store, "sess-home", "HTTPS", "https://example.com/index.html", ts, nil)

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{
		Filter:        ExportFilter{URLPattern: "/api/"},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 exported with /api/ URL filter, got %d", n)
	}
}

func TestExportWithTimeFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	t1 := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-jan", "HTTPS", "https://example.com/jan", t1, nil)
	makeTestSession(t, store, "sess-feb", "HTTPS", "https://example.com/feb", t2, nil)
	makeTestSession(t, store, "sess-mar", "HTTPS", "https://example.com/mar", t3, nil)

	after := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{
		Filter: ExportFilter{
			TimeAfter:  &after,
			TimeBefore: &before,
		},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 session in February, got %d", n)
	}
}

func TestExportMetadataOnly(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-meta", "HTTPS", "https://example.com/api", ts, []byte("request body"))

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{
		IncludeBodies: false,
	})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
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
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-existing", "HTTPS", "https://example.com/api", ts, []byte("original"))

	// Export from another store with same ID
	store2 := newTestStore(t)
	makeTestSession(t, store2, "sess-existing", "HTTP/1.x", "http://example.com/different", ts, []byte("different"))

	var buf bytes.Buffer
	_, err := ExportSessions(ctx, store2, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}

	// Import with skip policy
	result, err := ImportSessions(ctx, store, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported, got %d", result.Imported)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}

	// Verify original data is preserved
	sess, err := store.GetSession(ctx, "sess-existing")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.Protocol != "HTTPS" {
		t.Errorf("expected original protocol HTTPS, got %s", sess.Protocol)
	}
}

func TestImportConflictReplace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-replace", "HTTPS", "https://example.com/api", ts, []byte("original"))

	// Export from another store with same ID but different data
	store2 := newTestStore(t)
	makeTestSession(t, store2, "sess-replace", "HTTP/1.x", "http://example.com/different", ts, []byte("replaced"))

	var buf bytes.Buffer
	_, err := ExportSessions(ctx, store2, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}

	// Import with replace policy
	result, err := ImportSessions(ctx, store, &buf, ImportOptions{OnConflict: ConflictReplace})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}

	// Verify replaced data
	sess, err := store.GetSession(ctx, "sess-replace")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.Protocol != "HTTP/1.x" {
		t.Errorf("expected replaced protocol HTTP/1.x, got %s", sess.Protocol)
	}
}

func TestImportInvalidJSONL(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Mix of valid and invalid lines
	data := `not json at all
{"session":null,"messages":[],"version":"1"}
{"session":{"id":"good","conn_id":"c","protocol":"HTTPS","session_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}
{"broken json
`
	result, err := ImportSessions(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}
	if result.Errors != 3 {
		t.Errorf("expected 3 errors, got %d", result.Errors)
	}
}

func TestImportInvalidVersion(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	data := `{"session":{"id":"ver2","conn_id":"c","protocol":"HTTPS","session_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"2"}`

	result, err := ImportSessions(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported for version mismatch, got %d", result.Imported)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error for version mismatch, got %d", result.Errors)
	}
}

func TestImportEmptyLines(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	data := "\n\n\n"
	result, err := ImportSessions(ctx, store, strings.NewReader(data), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 0 {
		t.Errorf("expected 0 imported for empty lines, got %d", result.Imported)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors for empty lines, got %d", result.Errors)
	}
}

func TestExportJSONLFormat(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-format", "HTTPS", "https://example.com/api", ts, []byte("binary\x00data"))

	var buf bytes.Buffer
	_, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
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
	if record.Session.ID != "sess-format" {
		t.Errorf("expected session ID sess-format, got %s", record.Session.ID)
	}
	if record.Session.Protocol != "HTTPS" {
		t.Errorf("expected protocol HTTPS, got %s", record.Session.Protocol)
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
	store := newTestStore(t)
	ctx := context.Background()

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 exported from empty store, got %d", n)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", buf.Len())
	}
}

func TestLargeExportImport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large export/import test in short mode")
	}

	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	const count = 1000
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("sess-large-%04d", i)
		makeTestSession(t, store, id, "HTTPS", fmt.Sprintf("https://example.com/api/%d", i), ts.Add(time.Duration(i)*time.Second), []byte(fmt.Sprintf("body-%d", i)))
	}

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != count {
		t.Fatalf("expected %d exported, got %d", count, n)
	}

	store2 := newTestStore(t)
	result, err := ImportSessions(ctx, store2, &buf, ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != count {
		t.Errorf("expected %d imported, got %d", count, result.Imported)
	}
}

func TestExportSessionWithNilConnInfo(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	sess := &Session{
		ID:          "sess-noconn",
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   ts,
		Duration:    50 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	// Import and verify
	store2 := newTestStore(t)
	result, err := ImportSessions(ctx, store2, &buf, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}

	imported, err := store2.GetSession(ctx, "sess-noconn")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if imported.Protocol != "HTTP/1.x" {
		t.Errorf("expected HTTP/1.x, got %s", imported.Protocol)
	}
}

func TestExportImportWithURLMessage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	sess := &Session{
		ID:          "sess-url",
		Protocol:    "HTTPS",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   ts,
		Duration:    100 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	complexURL, _ := url.Parse("https://example.com/path?key=value&foo=bar#fragment")
	msg := &Message{
		ID:        "msg-url-1",
		SessionID: "sess-url",
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
	_, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}

	store2 := newTestStore(t)
	result, err := ImportSessions(ctx, store2, &buf, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected 1 imported, got %d", result.Imported)
	}

	msgs, err := store2.GetMessages(ctx, "sess-url", MessageListOptions{})
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
	store := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-default", "HTTPS", "https://example.com/", ts, nil)

	var buf bytes.Buffer
	_, err := ExportSessions(ctx, store, &buf, ExportOptions{IncludeBodies: true})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}

	// Import with empty OnConflict (should default to skip)
	result, err := ImportSessions(ctx, store, bytes.NewReader(buf.Bytes()), ImportOptions{})
	if err != nil {
		t.Fatalf("ImportSessions: %v", err)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped with default policy, got %d", result.Skipped)
	}
}

func TestExportCombinedFilters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	t1 := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)

	makeTestSession(t, store, "sess-1", "HTTPS", "https://example.com/api/v1", t1, nil)
	makeTestSession(t, store, "sess-2", "HTTP/1.x", "http://example.com/api/v2", t2, nil)
	makeTestSession(t, store, "sess-3", "HTTPS", "https://example.com/api/v3", t3, nil)
	makeTestSession(t, store, "sess-4", "HTTPS", "https://example.com/other", t2, nil)

	after := time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)

	var buf bytes.Buffer
	n, err := ExportSessions(ctx, store, &buf, ExportOptions{
		Filter: ExportFilter{
			Protocol:   "HTTPS",
			URLPattern: "/api/",
			TimeAfter:  &after,
			TimeBefore: &before,
		},
		IncludeBodies: true,
	})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	// Only sess-1 is HTTPS+/api/ but before time_after (excluded)
	// sess-2 is HTTP/1.x (excluded by protocol)
	// sess-3 is HTTPS+/api/ but after time_before (excluded)
	// sess-4 is HTTPS but no /api/ (excluded by URL)
	// None should match all filters
	if n != 0 {
		t.Errorf("expected 0 with combined filters, got %d", n)
	}
}

