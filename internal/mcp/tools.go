package mcp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
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

// listSessionsInput is the input parameters for the list_sessions tool.
type listSessionsInput struct {
	// Protocol filters sessions by protocol (e.g. "http", "https").
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter (e.g. http, https)"`
	// Method filters sessions by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters sessions by URL using a LIKE search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL LIKE search pattern"`
	// StatusCode filters sessions by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
	// Limit is the maximum number of sessions to return (default 50).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of sessions to return (default 50)"`
	// Offset is the number of sessions to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"number of sessions to skip for pagination"`
}

// listSessionsEntry is a single session entry in the list_sessions response.
type listSessionsEntry struct {
	// ID is the unique session identifier.
	ID string `json:"id"`
	// Protocol is the detected protocol (e.g. "HTTP/1.x").
	Protocol string `json:"protocol"`
	// Method is the HTTP method (e.g. "GET", "POST").
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// Timestamp is the session creation time in RFC 3339 format.
	Timestamp string `json:"timestamp"`
}

// listSessionsResult is the structured output of the list_sessions tool.
type listSessionsResult struct {
	// Sessions is the list of matching session entries.
	Sessions []listSessionsEntry `json:"sessions"`
	// Total is the number of sessions returned.
	Total int `json:"total"`
}

// defaultListLimit is the default number of sessions returned when limit is not specified.
const defaultListLimit = 50

// registerListSessions registers the list_sessions MCP tool.
func (s *Server) registerListSessions() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "list_sessions",
		Description: "List recorded proxy sessions with optional filtering. Supports filtering by protocol, HTTP method, URL pattern, and status code. Results are paginated with limit/offset.",
	}, s.handleListSessions)
}

// handleListSessions handles the list_sessions tool invocation.
// It queries the session store with the provided filters and returns matching entries.
func (s *Server) handleListSessions(ctx context.Context, _ *gomcp.CallToolRequest, input listSessionsInput) (*gomcp.CallToolResult, *listSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	limit := input.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}

	opts := session.ListOptions{
		Protocol:   input.Protocol,
		Method:     input.Method,
		URLPattern: input.URLPattern,
		StatusCode: input.StatusCode,
		Limit:      limit,
		Offset:     input.Offset,
	}

	entries, err := s.store.List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list sessions: %w", err)
	}

	sessions := make([]listSessionsEntry, 0, len(entries))
	for _, e := range entries {
		urlStr := ""
		if e.Request.URL != nil {
			urlStr = e.Request.URL.String()
		}

		sessions = append(sessions, listSessionsEntry{
			ID:         e.ID,
			Protocol:   e.Protocol,
			Method:     e.Request.Method,
			URL:        urlStr,
			StatusCode: e.Response.StatusCode,
			Timestamp:  e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	result := &listSessionsResult{
		Sessions: sessions,
		Total:    len(sessions),
	}

	return nil, result, nil
}
