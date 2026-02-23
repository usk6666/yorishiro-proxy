package mcp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// exportCACertResult is the structured output of the export_ca_cert tool.
type exportCACertResult struct {
	// PEM is the PEM-encoded CA certificate.
	PEM string `json:"pem"`
	// Fingerprint is the SHA-256 fingerprint in colon-separated hex format.
	Fingerprint string `json:"fingerprint"`
	// Subject is the CA certificate's subject distinguished name.
	Subject string `json:"subject"`
	// NotAfter is the certificate expiration date in RFC 3339 format.
	NotAfter string `json:"not_after"`
}

// registerExportCACert registers the export_ca_cert MCP tool.
func (s *Server) registerExportCACert() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "export_ca_cert",
		Description: "Export the CA certificate in PEM format with metadata. Use this to retrieve the proxy's CA certificate for installation into a client trust store, enabling HTTPS interception.",
	}, s.handleExportCACert)
}

// handleExportCACert handles the export_ca_cert tool invocation.
// It returns the CA certificate PEM, SHA-256 fingerprint, subject, and expiration date.
func (s *Server) handleExportCACert(_ context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *exportCACertResult, error) {
	if s.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized: no CA has been configured for this server")
	}

	cert := s.ca.Certificate()
	if cert == nil {
		return nil, nil, fmt.Errorf("CA certificate is not available: CA has not been generated or loaded")
	}

	certPEM := s.ca.CertPEM()
	if certPEM == nil {
		return nil, nil, fmt.Errorf("CA certificate PEM is not available")
	}

	// Compute SHA-256 fingerprint from DER-encoded certificate.
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	result := &exportCACertResult{
		PEM:         string(certPEM),
		Fingerprint: fingerprintHex,
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return nil, result, nil
}

// formatFingerprint formats a byte slice as a colon-separated uppercase hex string.
// For example: "AB:CD:EF:01:23:45:...".
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
