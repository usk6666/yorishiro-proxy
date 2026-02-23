package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	ctx := context.Background()

	var st0 session.Store
	if len(store) > 0 {
		st0 = store[0]
	}
	s := NewServer(ca, st0)
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
