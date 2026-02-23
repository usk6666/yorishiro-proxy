package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

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

// getSessionInput is the typed input for the get_session tool.
type getSessionInput struct {
	// SessionID is the unique identifier of the session to retrieve.
	SessionID string `json:"session_id"`
}

// getSessionResult is the structured output of the get_session tool.
type getSessionResult struct {
	// ID is the unique identifier of the session.
	ID string `json:"id"`
	// Protocol is the protocol used (e.g., "HTTP/1.x").
	Protocol string `json:"protocol"`
	// Method is the HTTP method (e.g., "GET", "POST").
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// RequestHeaders is the request headers as a JSON object.
	RequestHeaders map[string][]string `json:"request_headers"`
	// RequestBody is the request body as text or Base64-encoded string.
	RequestBody string `json:"request_body"`
	// RequestBodyEncoding indicates the encoding of the request body ("text" or "base64").
	RequestBodyEncoding string `json:"request_body_encoding"`
	// ResponseStatusCode is the HTTP response status code.
	ResponseStatusCode int `json:"response_status_code"`
	// ResponseHeaders is the response headers as a JSON object.
	ResponseHeaders map[string][]string `json:"response_headers"`
	// ResponseBody is the response body as text or Base64-encoded string.
	ResponseBody string `json:"response_body"`
	// ResponseBodyEncoding indicates the encoding of the response body ("text" or "base64").
	ResponseBodyEncoding string `json:"response_body_encoding"`
	// Timestamp is the time the session was recorded in RFC 3339 format.
	Timestamp string `json:"timestamp"`
	// DurationMs is the session duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
}

// registerGetSession registers the get_session MCP tool.
func (s *Server) registerGetSession() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "get_session",
		Description: "Retrieve the full details of a recorded proxy session by its ID. Returns request/response headers, bodies, timing information, and metadata. Binary bodies are returned as Base64-encoded strings.",
	}, s.handleGetSession)
}

// handleGetSession handles the get_session tool invocation.
// It retrieves a session entry by ID and returns its full details.
func (s *Server) handleGetSession(ctx context.Context, _ *gomcp.CallToolRequest, input getSessionInput) (*gomcp.CallToolResult, *getSessionResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required")
	}

	entry, err := s.store.Get(ctx, input.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	urlStr := ""
	if entry.Request.URL != nil {
		urlStr = entry.Request.URL.String()
	}

	reqBody, reqEncoding := encodeBody(entry.Request.Body)
	respBody, respEncoding := encodeBody(entry.Response.Body)

	result := &getSessionResult{
		ID:                   entry.ID,
		Protocol:             entry.Protocol,
		Method:               entry.Request.Method,
		URL:                  urlStr,
		RequestHeaders:       entry.Request.Headers,
		RequestBody:          reqBody,
		RequestBodyEncoding:  reqEncoding,
		ResponseStatusCode:   entry.Response.StatusCode,
		ResponseHeaders:      entry.Response.Headers,
		ResponseBody:         respBody,
		ResponseBodyEncoding: respEncoding,
		Timestamp:            entry.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs:           entry.Duration.Milliseconds(),
	}

	return nil, result, nil
}

// encodeBody returns the body as a string with its encoding type.
// If the body is valid UTF-8 text, it is returned as-is with encoding "text".
// Otherwise, it is Base64-encoded with encoding "base64".
func encodeBody(body []byte) (string, string) {
	if len(body) == 0 {
		return "", "text"
	}
	if utf8.Valid(body) {
		return string(body), "text"
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}
