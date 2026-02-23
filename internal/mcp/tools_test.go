package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
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

// setupTestSession creates a connected MCP client session for testing tools.
// It returns the client session and a cleanup function.
func setupTestSession(t *testing.T, ca *cert.CA) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ca)
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
