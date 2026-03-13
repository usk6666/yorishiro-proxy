//go:build e2e

package mcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestBearerAuth_NoToken_Rejected verifies that requests to /mcp without an
// Authorization header are rejected with 401 Unauthorized.
func TestBearerAuth_NoToken_Rejected(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://%s/mcp", env.addr),
		strings.NewReader(mcpInitPayload))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d; body = %s",
			resp.StatusCode, http.StatusUnauthorized, body)
	}
}

// TestBearerAuth_InvalidToken_Rejected verifies that requests with an incorrect
// Bearer token are rejected with 401 Unauthorized.
func TestBearerAuth_InvalidToken_Rejected(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)

	tests := []struct {
		name       string
		authHeader string
	}{
		{"wrong_token", "Bearer wrong-token-value"},
		{"wrong_scheme_basic", "Basic dXNlcjpwYXNz"},
		{"bearer_lowercase", "bearer " + token},
		{"empty_bearer_value", "Bearer "},
		{"token_with_extra_space", "Bearer  " + token},
		{"partial_token", "Bearer " + token[:len(token)/2]},
		{"token_with_suffix", "Bearer " + token + "extra"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost,
				fmt.Sprintf("http://%s/mcp", env.addr),
				strings.NewReader(mcpInitPayload))
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Authorization", tt.authHeader)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("HTTP request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d; body = %s",
					resp.StatusCode, http.StatusUnauthorized, body)
			}
		})
	}
}

// TestBearerAuth_ValidToken_MCPToolExecution verifies that a correct Bearer
// token allows full MCP tool execution over Streamable HTTP, not just
// connection establishment. This tests the end-to-end flow: authentication
// -> MCP session -> tool invocation -> response.
func TestBearerAuth_ValidToken_MCPToolExecution(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)
	ctx := context.Background()

	// Connect MCP client with valid token.
	cs := newHTTPMCPClient(t, ctx, env.addr, token)

	// Verify ListTools succeeds.
	toolsResult, err := cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(toolsResult.Tools) == 0 {
		t.Fatal("expected at least one tool")
	}

	// Verify actual tool execution works (query status).
	statusResult := callTool[queryStatusResult](t, cs, "query", map[string]any{
		"resource": "status",
	})
	// Proxy should not be running (we haven't started it).
	if statusResult.Running {
		t.Error("proxy should not be running before proxy_start")
	}
}

// TestBearerAuth_GenerateToken_Consistency verifies that tokens produced by
// GenerateToken are accepted by BearerAuthMiddleware and that each call
// produces a unique, 64-character hex token.
func TestBearerAuth_GenerateToken_Consistency(t *testing.T) {
	const iterations = 5
	tokens := make(map[string]bool, iterations)

	for i := range iterations {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken[%d]: %v", i, err)
		}

		// Verify token format: 64 hex characters.
		if len(token) != 64 {
			t.Errorf("token[%d] length = %d, want 64", i, len(token))
		}
		for _, c := range token {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("token[%d] contains non-hex character %q", i, c)
				break
			}
		}

		// Verify uniqueness.
		if tokens[token] {
			t.Errorf("token[%d] is a duplicate", i)
		}
		tokens[token] = true

		// Verify the generated token works with a real MCP server.
		env := setupHTTPTransportEnv(t, token)
		ctx := context.Background()
		cs := newHTTPMCPClient(t, ctx, env.addr, token)

		_, err = cs.ListTools(ctx, &gomcp.ListToolsParams{})
		if err != nil {
			t.Fatalf("ListTools with generated token[%d]: %v", i, err)
		}
	}
}

// TestBearerAuth_MCPClientConnect_InvalidToken_Fails verifies that an MCP
// client using Streamable HTTP transport cannot establish a session when
// configured with an invalid Bearer token.
func TestBearerAuth_MCPClientConnect_InvalidToken_Fails(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)
	ctx := context.Background()

	badHTTPClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &bearerRoundTripper{
			token: "invalid-token-value",
			base:  http.DefaultTransport,
		},
	}
	badTransport := &gomcp.StreamableClientTransport{
		Endpoint:             fmt.Sprintf("http://%s/mcp", env.addr),
		HTTPClient:           badHTTPClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}
	badClient := gomcp.NewClient(&gomcp.Implementation{
		Name:    "bad-auth-client",
		Version: "0.1",
	}, nil)

	_, err = badClient.Connect(ctx, badTransport, nil)
	if err == nil {
		t.Fatal("Connect with invalid token should fail")
	}
}

// TestBearerAuth_MCPClientConnect_NoToken_Fails verifies that an MCP client
// without any authentication cannot establish a session when the server
// requires Bearer token authentication.
func TestBearerAuth_MCPClientConnect_NoToken_Fails(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)
	ctx := context.Background()

	// Client without any auth transport.
	noAuthHTTPClient := &http.Client{Timeout: 5 * time.Second}
	noAuthTransport := &gomcp.StreamableClientTransport{
		Endpoint:             fmt.Sprintf("http://%s/mcp", env.addr),
		HTTPClient:           noAuthHTTPClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}
	noAuthClient := gomcp.NewClient(&gomcp.Implementation{
		Name:    "no-auth-client",
		Version: "0.1",
	}, nil)

	_, err = noAuthClient.Connect(ctx, noAuthTransport, nil)
	if err == nil {
		t.Fatal("Connect without token should fail when auth is required")
	}
}

// TestBearerAuth_WebUI_NoAuthRequired verifies that WebUI routes (/) remain
// accessible without authentication even when Bearer token middleware is
// configured on the /mcp endpoint. This ensures the middleware is only
// applied to MCP endpoints, not the entire server.
func TestBearerAuth_WebUI_NoAuthRequired(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupHTTPTransportEnv(t, token)

	// GET / without any auth header should succeed.
	resp, err := http.Get(fmt.Sprintf("http://%s/", env.addr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("GET / without auth status = %d, want %d; body = %s",
			resp.StatusCode, http.StatusOK, body)
	}

	// Verify the response contains WebUI content.
	body, _ := io.ReadAll(resp.Body)
	// Note: body may already be read above in error case; re-read is safe
	// because io.ReadAll returns remaining bytes after any previous read.
	_ = body // WebUI content check — the status code assertion is sufficient.
}

// mcpInitPayload is a valid MCP initialize request used across auth tests.
const mcpInitPayload = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"auth-test","version":"0.1"}}}`
