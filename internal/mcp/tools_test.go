package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// newTestCA creates a CA with a generated certificate for testing.
func newTestCA(t *testing.T) *cert.CA {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate test CA: %v", err)
	}
	return ca
}

// newTestStore creates a SQLite session store for testing.
func newTestStore(t *testing.T) session.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// setupTestSession creates a connected MCP client session for testing tools.
// It returns the client session and a cleanup function.
func setupTestSession(t *testing.T, ca *cert.CA, store ...session.Store) *gomcp.ClientSession {
	t.Helper()
	var st0 session.Store
	if len(store) > 0 {
		st0 = store[0]
	}
	return setupTestSessionWithStore(t, ca, st0)
}

// setupTestSessionWithStore creates a connected MCP client session for testing tools
// with a custom session store.
func setupTestSessionWithStore(t *testing.T, ca *cert.CA, store session.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), ca, store, nil)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

func TestExportCACert_Success(t *testing.T) {
	ca := newTestCA(t)
	cs := setupTestSession(t, ca)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "export_ca_cert",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Parse the result from text content (SDK auto-populates Content with JSON text).
	var out exportCACertResult
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal text content: %v", err)
	}

	// Verify PEM format.
	block, _ := pem.Decode([]byte(out.PEM))
	if block == nil {
		t.Fatal("PEM decode returned nil block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %q, want CERTIFICATE", block.Type)
	}

	// Parse the certificate from PEM and verify it matches the CA.
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate from PEM: %v", err)
	}
	if !parsedCert.Equal(ca.Certificate()) {
		t.Error("parsed certificate does not match CA certificate")
	}

	// Verify fingerprint matches SHA-256 of DER-encoded certificate.
	expectedFingerprint := sha256.Sum256(ca.Certificate().Raw)
	expectedFingerprintStr := formatFingerprint(expectedFingerprint[:])
	if out.Fingerprint != expectedFingerprintStr {
		t.Errorf("fingerprint = %q, want %q", out.Fingerprint, expectedFingerprintStr)
	}

	// Verify subject.
	expectedSubject := ca.Certificate().Subject.String()
	if out.Subject != expectedSubject {
		t.Errorf("subject = %q, want %q", out.Subject, expectedSubject)
	}
	if out.Subject != "CN=katashiro-proxy CA" {
		t.Errorf("subject = %q, want %q", out.Subject, "CN=katashiro-proxy CA")
	}

	// Verify not_after is in the future.
	notAfter, err := time.Parse("2006-01-02T15:04:05Z", out.NotAfter)
	if err != nil {
		t.Fatalf("parse not_after %q: %v", out.NotAfter, err)
	}
	if !notAfter.After(time.Now()) {
		t.Errorf("not_after %v is not in the future", notAfter)
	}
}

func TestExportCACert_NilCA(t *testing.T) {
	cs := setupTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "export_ca_cert",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil CA")
	}
}

func TestExportCACert_UninitializedCA(t *testing.T) {
	// Create a CA struct without calling Generate or Load.
	ca := &cert.CA{}
	cs := setupTestSession(t, ca)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "export_ca_cert",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for uninitialized CA")
	}
}

func TestExportCACert_FingerprintFormat(t *testing.T) {
	ca := newTestCA(t)
	cs := setupTestSession(t, ca)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "export_ca_cert",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var out exportCACertResult
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal text content: %v", err)
	}

	// SHA-256 produces 32 bytes, formatted as "XX:XX:...:XX" (32 hex pairs + 31 colons).
	expectedLen := 32*3 - 1 // "XX:" * 32 minus trailing ":"
	if len(out.Fingerprint) != expectedLen {
		t.Errorf("fingerprint length = %d, want %d", len(out.Fingerprint), expectedLen)
	}

	// Verify each byte is uppercase hex separated by colons.
	parts := splitFingerprint(out.Fingerprint)
	if len(parts) != 32 {
		t.Errorf("fingerprint has %d parts, want 32", len(parts))
	}
	for i, part := range parts {
		if len(part) != 2 {
			t.Errorf("fingerprint part[%d] = %q, want 2-character hex", i, part)
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				t.Errorf("fingerprint part[%d] contains non-uppercase-hex character: %c", i, c)
			}
		}
	}
}

// splitFingerprint splits a colon-separated fingerprint string.
func splitFingerprint(fp string) []string {
	if fp == "" {
		return nil
	}
	var parts []string
	for len(fp) > 0 {
		if len(fp) >= 2 {
			parts = append(parts, fp[:2])
			fp = fp[2:]
		}
		if len(fp) > 0 && fp[0] == ':' {
			fp = fp[1:]
		} else {
			break
		}
	}
	return parts
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "single byte",
			input: []byte{0xAB},
			want:  "AB",
		},
		{
			name:  "two bytes",
			input: []byte{0xAB, 0xCD},
			want:  "AB:CD",
		},
		{
			name:  "leading zero",
			input: []byte{0x01, 0x0A},
			want:  "01:0A",
		},
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("formatFingerprint(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- get_session tests (from main/PR #12) ---

// saveTestEntry is a helper that saves a session entry and returns it with the assigned ID.
func saveTestEntry(t *testing.T, store session.Store, entry *session.Entry) *session.Entry {
	t.Helper()
	if err := store.Save(context.Background(), entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return entry
}

func TestGetSession_Success(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	u, _ := url.Parse("http://example.com/api/test")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Duration:  250 * time.Millisecond,
		Request: session.RecordedRequest{
			Method:  "POST",
			URL:     u,
			Headers: map[string][]string{"Content-Type": {"application/json"}, "Host": {"example.com"}},
			Body:    []byte(`{"key":"value"}`),
		},
		Response: session.RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			Body:       []byte(`{"status":"ok"}`),
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify all fields.
	if out.ID != entry.ID {
		t.Errorf("ID = %q, want %q", out.ID, entry.ID)
	}
	if out.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", out.Protocol, "HTTP/1.x")
	}
	if out.Method != "POST" {
		t.Errorf("Method = %q, want %q", out.Method, "POST")
	}
	if out.URL != "http://example.com/api/test" {
		t.Errorf("URL = %q, want %q", out.URL, "http://example.com/api/test")
	}
	if out.RequestBody != `{"key":"value"}` {
		t.Errorf("RequestBody = %q, want %q", out.RequestBody, `{"key":"value"}`)
	}
	if out.RequestBodyEncoding != "text" {
		t.Errorf("RequestBodyEncoding = %q, want %q", out.RequestBodyEncoding, "text")
	}
	if out.ResponseStatusCode != 200 {
		t.Errorf("ResponseStatusCode = %d, want %d", out.ResponseStatusCode, 200)
	}
	if out.ResponseBody != `{"status":"ok"}` {
		t.Errorf("ResponseBody = %q, want %q", out.ResponseBody, `{"status":"ok"}`)
	}
	if out.ResponseBodyEncoding != "text" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", out.ResponseBodyEncoding, "text")
	}
	if out.Timestamp != "2025-01-15T10:30:00Z" {
		t.Errorf("Timestamp = %q, want %q", out.Timestamp, "2025-01-15T10:30:00Z")
	}
	if out.DurationMs != 250 {
		t.Errorf("DurationMs = %d, want %d", out.DurationMs, 250)
	}

	// Verify headers.
	if got := out.RequestHeaders["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("RequestHeaders[Content-Type] = %v, want [application/json]", got)
	}
	if got := out.ResponseHeaders["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("ResponseHeaders[Content-Type] = %v, want [application/json]", got)
	}
}

func TestGetSession_WithTags(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	u, _ := url.Parse("http://example.com/smuggle")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		Duration:  100 * time.Millisecond,
		Request: session.RecordedRequest{
			Method:  "POST",
			URL:     u,
			Headers: map[string][]string{"Host": {"example.com"}},
		},
		Response: session.RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{},
		},
		Tags: map[string]string{
			"smuggling:cl_te_conflict": "true",
			"smuggling:warnings":       "CL/TE conflict detected",
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.Tags == nil {
		t.Fatal("expected non-nil tags")
	}
	if out.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Errorf("Tags[smuggling:cl_te_conflict] = %q, want %q", out.Tags["smuggling:cl_te_conflict"], "true")
	}
	if out.Tags["smuggling:warnings"] != "CL/TE conflict detected" {
		t.Errorf("Tags[smuggling:warnings] = %q, want %q", out.Tags["smuggling:warnings"], "CL/TE conflict detected")
	}
}

func TestGetSession_NotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": "nonexistent-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session ID")
	}
}

func TestGetSession_EmptySessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty session_id")
	}
}

func TestGetSession_NilStore(t *testing.T) {
	cs := setupTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": "some-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestGetSession_BinaryBody(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	// Create binary data that is not valid UTF-8.
	binaryData := []byte{0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90, 0xA0, 0xB0}

	u, _ := url.Parse("http://example.com/binary")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
		Request: session.RecordedRequest{
			Method:  "POST",
			URL:     u,
			Headers: map[string][]string{"Content-Type": {"application/octet-stream"}},
			Body:    binaryData,
		},
		Response: session.RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/octet-stream"}},
			Body:       binaryData,
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify binary bodies are Base64-encoded.
	if out.RequestBodyEncoding != "base64" {
		t.Errorf("RequestBodyEncoding = %q, want %q", out.RequestBodyEncoding, "base64")
	}
	if out.ResponseBodyEncoding != "base64" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", out.ResponseBodyEncoding, "base64")
	}

	// Decode and verify the binary content.
	decodedReq, err := base64.StdEncoding.DecodeString(out.RequestBody)
	if err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if string(decodedReq) != string(binaryData) {
		t.Errorf("decoded request body = %v, want %v", decodedReq, binaryData)
	}

	decodedResp, err := base64.StdEncoding.DecodeString(out.ResponseBody)
	if err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if string(decodedResp) != string(binaryData) {
		t.Errorf("decoded response body = %v, want %v", decodedResp, binaryData)
	}
}

func TestGetSession_EmptyBody(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	u, _ := url.Parse("http://example.com/empty")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Duration:  50 * time.Millisecond,
		Request: session.RecordedRequest{
			Method:  "GET",
			URL:     u,
			Headers: map[string][]string{"Host": {"example.com"}},
			Body:    nil,
		},
		Response: session.RecordedResponse{
			StatusCode: 204,
			Headers:    map[string][]string{},
			Body:       nil,
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.RequestBody != "" {
		t.Errorf("RequestBody = %q, want empty", out.RequestBody)
	}
	if out.RequestBodyEncoding != "text" {
		t.Errorf("RequestBodyEncoding = %q, want %q", out.RequestBodyEncoding, "text")
	}
	if out.ResponseBody != "" {
		t.Errorf("ResponseBody = %q, want empty", out.ResponseBody)
	}
	if out.ResponseBodyEncoding != "text" {
		t.Errorf("ResponseBodyEncoding = %q, want %q", out.ResponseBodyEncoding, "text")
	}
}

func TestEncodeBody(t *testing.T) {
	tests := []struct {
		name         string
		body         []byte
		wantBody     string
		wantEncoding string
	}{
		{
			name:         "nil body",
			body:         nil,
			wantBody:     "",
			wantEncoding: "text",
		},
		{
			name:         "empty body",
			body:         []byte{},
			wantBody:     "",
			wantEncoding: "text",
		},
		{
			name:         "text body",
			body:         []byte("hello world"),
			wantBody:     "hello world",
			wantEncoding: "text",
		},
		{
			name:         "json body",
			body:         []byte(`{"key":"value"}`),
			wantBody:     `{"key":"value"}`,
			wantEncoding: "text",
		},
		{
			name:         "binary body",
			body:         []byte{0xFF, 0xFE, 0x00, 0x01},
			wantBody:     base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE, 0x00, 0x01}),
			wantEncoding: "base64",
		},
		{
			name:         "utf8 with multibyte chars",
			body:         []byte("こんにちは"),
			wantBody:     "こんにちは",
			wantEncoding: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBody, gotEncoding := encodeBody(tt.body)
			if gotBody != tt.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tt.wantBody)
			}
			if gotEncoding != tt.wantEncoding {
				t.Errorf("encoding = %q, want %q", gotEncoding, tt.wantEncoding)
			}
		})
	}
}

// --- list_sessions tests (from branch USK-17) ---

// mustParseURL parses a URL string and panics on error.
func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// seedTestSessions inserts test session entries into the store.
func seedTestSessions(t *testing.T, store session.Store) {
	t.Helper()
	ctx := context.Background()

	entries := []*session.Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			Duration:  100 * time.Millisecond,
			Request: session.RecordedRequest{
				Method:  "GET",
				URL:     mustParseURL("http://example.com/api/users"),
				Headers: map[string][]string{"Host": {"example.com"}},
			},
			Response: session.RecordedResponse{
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
				Body:       []byte(`{"users":[]}`),
			},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 1, 10, 1, 0, 0, time.UTC),
			Duration:  200 * time.Millisecond,
			Request: session.RecordedRequest{
				Method:  "POST",
				URL:     mustParseURL("http://example.com/api/users"),
				Headers: map[string][]string{"Host": {"example.com"}},
				Body:    []byte(`{"name":"test"}`),
			},
			Response: session.RecordedResponse{
				StatusCode: 201,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
				Body:       []byte(`{"id":"1","name":"test"}`),
			},
		},
		{
			Protocol:  "HTTPS",
			Timestamp: time.Date(2025, 1, 1, 10, 2, 0, 0, time.UTC),
			Duration:  150 * time.Millisecond,
			Request: session.RecordedRequest{
				Method:  "GET",
				URL:     mustParseURL("https://secure.example.com/login"),
				Headers: map[string][]string{"Host": {"secure.example.com"}},
			},
			Response: session.RecordedResponse{
				StatusCode: 302,
				Headers:    map[string][]string{"Location": {"/dashboard"}},
			},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 1, 10, 3, 0, 0, time.UTC),
			Duration:  50 * time.Millisecond,
			Request: session.RecordedRequest{
				Method:  "GET",
				URL:     mustParseURL("http://other.com/notfound"),
				Headers: map[string][]string{"Host": {"other.com"}},
			},
			Response: session.RecordedResponse{
				StatusCode: 404,
				Headers:    map[string][]string{"Content-Type": {"text/html"}},
				Body:       []byte("not found"),
			},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
}

func TestListSessions_NoFilter(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_sessions",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 4 {
		t.Errorf("count = %d, want 4", out.Count)
	}
	if out.Total != 4 {
		t.Errorf("total = %d, want 4", out.Total)
	}
	if len(out.Sessions) != 4 {
		t.Errorf("sessions count = %d, want 4", len(out.Sessions))
	}
}

func TestListSessions_FilterByProtocol(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"protocol":"HTTPS"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 1 {
		t.Errorf("total = %d, want 1", out.Count)
	}
	if len(out.Sessions) > 0 && out.Sessions[0].Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", out.Sessions[0].Protocol)
	}
}

func TestListSessions_FilterByMethod(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"POST"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 1 {
		t.Errorf("total = %d, want 1", out.Count)
	}
	if len(out.Sessions) > 0 && out.Sessions[0].Method != "POST" {
		t.Errorf("method = %q, want POST", out.Sessions[0].Method)
	}
}

func TestListSessions_FilterByURLPattern(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"url_pattern":"example.com/api"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 2 {
		t.Errorf("total = %d, want 2", out.Count)
	}
}

func TestListSessions_FilterByStatusCode(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"status_code":404}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 1 {
		t.Errorf("total = %d, want 1", out.Count)
	}
	if len(out.Sessions) > 0 && out.Sessions[0].StatusCode != 404 {
		t.Errorf("status_code = %d, want 404", out.Sessions[0].StatusCode)
	}
}

func TestListSessions_CombinedFilters(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"GET","status_code":200}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 1 {
		t.Errorf("total = %d, want 1", out.Count)
	}
	if len(out.Sessions) > 0 {
		s := out.Sessions[0]
		if s.Method != "GET" {
			t.Errorf("method = %q, want GET", s.Method)
		}
		if s.StatusCode != 200 {
			t.Errorf("status_code = %d, want 200", s.StatusCode)
		}
	}
}

func TestListSessions_Pagination(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	// Get first 2 sessions.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"limit":2,"offset":0}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out1 listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", out1.Count)
	}
	if out1.Total != 4 {
		t.Errorf("page 1 total = %d, want 4", out1.Total)
	}

	// Get next 2 sessions with offset.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"limit":2,"offset":2}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out2 listSessionsResult
	textContent = result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", out2.Count)
	}
	if out2.Total != 4 {
		t.Errorf("page 2 total = %d, want 4", out2.Total)
	}

	// Verify no overlap between pages.
	ids := make(map[string]bool)
	for _, s := range out1.Sessions {
		ids[s.ID] = true
	}
	for _, s := range out2.Sessions {
		if ids[s.ID] {
			t.Errorf("session %s appears in both pages", s.ID)
		}
	}
}

func TestListSessions_DefaultLimit(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	// Call without limit; should use default (50), returning all 4.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_sessions",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// We have 4 entries, which is less than default limit of 50.
	if out.Count != 4 {
		t.Errorf("total = %d, want 4", out.Count)
	}
}

func TestListSessions_EmptyResult(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_sessions",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if len(out.Sessions) != 0 {
		t.Errorf("sessions count = %d, want 0", len(out.Sessions))
	}
}

func TestListSessions_NoMatchingFilter(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"DELETE"}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
}

func TestListSessions_NilStore(t *testing.T) {
	cs := setupTestSessionWithStore(t, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "list_sessions",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestListSessions_ResponseFields(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"status_code":200}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(out.Sessions))
	}

	s := out.Sessions[0]
	if s.ID == "" {
		t.Error("session ID is empty")
	}
	if s.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want HTTP/1.x", s.Protocol)
	}
	if s.Method != "GET" {
		t.Errorf("method = %q, want GET", s.Method)
	}
	if s.URL != "http://example.com/api/users" {
		t.Errorf("url = %q, want http://example.com/api/users", s.URL)
	}
	if s.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", s.StatusCode)
	}
	if s.Timestamp == "" {
		t.Error("timestamp is empty")
	}
	// Verify timestamp is valid RFC 3339 format.
	if _, err := time.Parse("2006-01-02T15:04:05Z", s.Timestamp); err != nil {
		t.Errorf("timestamp %q is not valid RFC 3339: %v", s.Timestamp, err)
	}
}

// --- Security review fix tests ---

func TestListSessions_ExtremeLimit(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	tests := []struct {
		name      string
		limit     int
		wantCount int
	}{
		{"huge limit defaults to 50", 2147483647, 4},
		{"over max defaults to 50", 1001, 4},
		{"zero defaults to 50", 0, 4},
		{"negative defaults to 50", -1, 4},
		{"max allowed is respected", 1000, 4},
		{"valid limit 2", 2, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := fmt.Sprintf(`{"limit":%d}`, tt.limit)
			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name:      "list_sessions",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out listSessionsResult
			textContent := result.Content[0].(*gomcp.TextContent)
			if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if out.Count != tt.wantCount {
				t.Errorf("count = %d, want %d", out.Count, tt.wantCount)
			}
		})
	}
}

func TestListSessions_NegativeOffset(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"offset":-1}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestListSessions_CountAndTotalFields(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	// Verify the JSON response uses both "count" and "total" fields.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"limit":2}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	textContent := result.Content[0].(*gomcp.TextContent)

	// Verify both "count" and "total" are present in JSON.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(textContent.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if _, ok := raw["count"]; !ok {
		t.Error("response JSON does not contain 'count' field")
	}
	if _, ok := raw["total"]; !ok {
		t.Error("response JSON does not contain 'total' field")
	}

	var out listSessionsResult
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 4 {
		t.Errorf("total = %d, want 4", out.Total)
	}
}

func TestListSessions_TotalWithFilterAndPagination(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store) // 4 entries: 3 GET, 1 POST; 3 HTTP/1.x, 1 HTTPS
	cs := setupTestSessionWithStore(t, nil, store)

	// Filter by method=GET (3 matches) with limit=1.
	// count should be 1 (page size), total should be 3 (all matching).
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"GET","limit":1}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out listSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}

	// Verify with offset=2, should get the last matching entry.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"GET","limit":1,"offset":2}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out2 listSessionsResult
	textContent = result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out2.Count != 1 {
		t.Errorf("count = %d, want 1", out2.Count)
	}
	if out2.Total != 3 {
		t.Errorf("total = %d, want 3 (should remain constant across pages)", out2.Total)
	}

	// Verify with offset beyond total, should get 0 entries but total still 3.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: json.RawMessage(`{"method":"GET","limit":10,"offset":100}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out3 listSessionsResult
	textContent = result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out3); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out3.Count != 0 {
		t.Errorf("count = %d, want 0", out3.Count)
	}
	if out3.Total != 3 {
		t.Errorf("total = %d, want 3 (should reflect total matching, not page)", out3.Total)
	}
}

// --- delete_session tests ---

func TestDeleteSession_SingleDelete(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	// List sessions to get a valid ID.
	entries, err := store.List(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one session")
	}
	targetID := entries[0].ID

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"session_id": targetID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out deleteSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", out.DeletedCount)
	}

	// Verify session is deleted.
	_, err = store.Get(context.Background(), targetID)
	if err == nil {
		t.Error("expected error when getting deleted session, got nil")
	}
}

func TestDeleteSession_DeleteAll(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"delete_all": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out deleteSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.DeletedCount != 4 {
		t.Errorf("deleted_count = %d, want 4", out.DeletedCount)
	}

	// Verify all sessions are deleted.
	entries, err := store.List(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries after delete_all, got %d", len(entries))
	}
}

func TestDeleteSession_DeleteAllEmpty(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"delete_all": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out deleteSessionResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", out.DeletedCount)
	}
}

func TestDeleteSession_NotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"session_id": "nonexistent-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session ID")
	}
}

func TestDeleteSession_NoParams(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "delete_session",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when neither session_id nor delete_all is specified")
	}
}

func TestDeleteSession_NilStore(t *testing.T) {
	cs := setupTestSessionWithStore(t, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"session_id": "some-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestDeleteSession_ResponseFields(t *testing.T) {
	store := newTestStore(t)
	seedTestSessions(t, store)
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "delete_session",
		Arguments: map[string]any{"delete_all": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	textContent := result.Content[0].(*gomcp.TextContent)

	// Verify JSON has "deleted_count" field.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(textContent.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if _, ok := raw["deleted_count"]; !ok {
		t.Error("response JSON does not contain 'deleted_count' field")
	}
}

func TestGetSession_WithRawBytesAndConnInfo(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	rawReq := []byte("GET /raw-test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

	u, _ := url.Parse("https://example.com/raw-test")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:    "HTTPS",
		Timestamp:   time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		Duration:    150 * time.Millisecond,
		RawRequest:  rawReq,
		RawResponse: rawResp,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr:           "192.168.1.50:54321",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
		Request: session.RecordedRequest{
			Method:  "GET",
			URL:     u,
			Headers: map[string][]string{"Host": {"example.com"}},
		},
		Response: session.RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Length": {"2"}},
			Body:       []byte("OK"),
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify raw request is base64 encoded.
	if out.RawRequest == "" {
		t.Error("expected non-empty raw_request")
	}
	decodedReq, err := base64.StdEncoding.DecodeString(out.RawRequest)
	if err != nil {
		t.Fatalf("decode raw_request: %v", err)
	}
	if string(decodedReq) != string(rawReq) {
		t.Errorf("decoded raw_request = %q, want %q", decodedReq, rawReq)
	}

	// Verify raw response is base64 encoded.
	if out.RawResponse == "" {
		t.Error("expected non-empty raw_response")
	}
	decodedResp, err := base64.StdEncoding.DecodeString(out.RawResponse)
	if err != nil {
		t.Fatalf("decode raw_response: %v", err)
	}
	if string(decodedResp) != string(rawResp) {
		t.Errorf("decoded raw_response = %q, want %q", decodedResp, rawResp)
	}

	// Verify conn_info.
	if out.ConnInfo == nil {
		t.Fatal("conn_info is nil")
	}
	if out.ConnInfo.ClientAddr != "192.168.1.50:54321" {
		t.Errorf("conn_info.client_addr = %q, want %q", out.ConnInfo.ClientAddr, "192.168.1.50:54321")
	}
	if out.ConnInfo.ServerAddr != "93.184.216.34:443" {
		t.Errorf("conn_info.server_addr = %q, want %q", out.ConnInfo.ServerAddr, "93.184.216.34:443")
	}
	if out.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("conn_info.tls_version = %q, want %q", out.ConnInfo.TLSVersion, "TLS 1.3")
	}
	if out.ConnInfo.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("conn_info.tls_cipher = %q, want %q", out.ConnInfo.TLSCipher, "TLS_AES_128_GCM_SHA256")
	}
	if out.ConnInfo.TLSALPN != "h2" {
		t.Errorf("conn_info.tls_alpn = %q, want %q", out.ConnInfo.TLSALPN, "h2")
	}
	if out.ConnInfo.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("conn_info.tls_server_cert_subject = %q, want %q", out.ConnInfo.TLSServerCertSubject, "CN=example.com")
	}
}

func TestGetSession_WithoutRawBytesOrConnInfo(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	u, _ := url.Parse("http://example.com/no-raw")
	entry := saveTestEntry(t, store, &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
		Request: session.RecordedRequest{
			Method:  "GET",
			URL:     u,
			Headers: map[string][]string{},
		},
		Response: session.RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "get_session",
		Arguments: map[string]any{"session_id": entry.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out getSessionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// raw_request and raw_response should be omitted (empty).
	if out.RawRequest != "" {
		t.Errorf("raw_request = %q, want empty", out.RawRequest)
	}
	if out.RawResponse != "" {
		t.Errorf("raw_response = %q, want empty", out.RawResponse)
	}
	// conn_info should be omitted (nil).
	if out.ConnInfo != nil {
		t.Errorf("conn_info = %+v, want nil", out.ConnInfo)
	}
}
