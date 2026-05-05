package mcptest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Client is a JSON-RPC over HTTP MCP client wired to a running
// yorishiro-proxy server. The wire format matches what
// cmd/yorishiro-proxy/client.go uses against production servers
// (gomcp.NewClient + gomcp.StreamableClientTransport with a Bearer
// auth round-tripper). Tests interact with the server through this
// client — never via raw http.Client — so the harness's coverage
// includes the full Streamable HTTP envelope (initialize ->
// tools/list -> tools/call).
type Client struct {
	endpoint string
	token    string

	// parentCtx is the harness's run context. CallTool derives its
	// per-call timeout context from parentCtx so that when the harness
	// cancels (Cleanup), in-flight tool calls unblock immediately
	// instead of waiting for the per-call deadline.
	parentCtx context.Context

	mu      sync.Mutex
	session *gomcp.ClientSession
	closed  bool
}

// ToolResult is a structured tool-call result returned by the
// JSON-RPC client. Tests inspect either Text (the tool's flattened
// text payload) or Decoded (the structured-content JSON map for tools
// that return structured output) depending on the tool's contract.
type ToolResult struct {
	// Err holds transport-level / JSON-RPC errors (network failure,
	// auth rejection, bad request). Tools that report a logical error
	// inside the response set IsError instead.
	Err error

	// IsError mirrors gomcp.CallToolResult.IsError — set when the
	// tool reported a domain-level error in its response. The error
	// text is collected in ToolResult.Text.
	IsError bool

	// Text is the concatenation of every TextContent block in the
	// tool's response, joined by newlines. Empty when the tool
	// returned only structured content.
	Text string

	// Decoded is the json.Unmarshal'd structured-content payload. Nil
	// when the tool did not return structured content. Tests should
	// check both Text and Decoded depending on which the tool returns.
	Decoded map[string]any
}

// newClient builds a Streamable HTTP MCP client and runs the
// initialize handshake. It mirrors the connection construction at
// cmd/yorishiro-proxy/client.go:runClientTool — same RoundTripper,
// same Bearer-Authorization header, same per-call deadlines.
func newClient(ctx context.Context, endpoint, token string) (*Client, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &bearerRoundTripper{
			token: token,
			base:  http.DefaultTransport,
		},
	}

	mcpClient := gomcp.NewClient(&gomcp.Implementation{
		Name:    "yorishiro-proxy-mcptest",
		Version: "0.1",
	}, nil)

	transport := &gomcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	session, err := mcpClient.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect MCP server at %s: %w", endpoint, err)
	}

	return &Client{
		endpoint:  endpoint,
		token:     token,
		parentCtx: ctx,
		session:   session,
	}, nil
}

// CallTool invokes the named tool with args (typically a map[string]any
// or a JSON-tagged struct) and decodes the result. Errors are caught
// and returned in ToolResult.Err — callers asserting success should
// use Harness.MustOK instead.
func (c *Client) CallTool(t *testing.T, name string, args any) ToolResult {
	t.Helper()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ToolResult{Err: fmt.Errorf("mcptest: client is closed")}
	}
	session := c.session
	parent := c.parentCtx
	c.mu.Unlock()

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return ToolResult{Err: fmt.Errorf("call tool %q: %w", name, err)}
	}

	out := ToolResult{
		IsError: result.IsError,
	}

	// Concatenate text-content blocks. The gomcp result Content slice
	// is a discriminated union of text/image/resource — in tests we
	// only need text, but the loop tolerates the others by skipping.
	out.Text = collectText(result.Content)

	// Decode structured content if the tool returned any. Some tools
	// emit JSON in TextContent; tests can json.Unmarshal Text
	// themselves rather than relying on Decoded.
	if result.StructuredContent != nil {
		// StructuredContent is `any` per the SDK — re-marshal then
		// unmarshal into a generic map so callers can introspect with
		// the standard map[string]any pattern instead of reflecting
		// over the SDK's typed wrapper.
		raw, jerr := json.Marshal(result.StructuredContent)
		if jerr == nil {
			var decoded map[string]any
			if uerr := json.Unmarshal(raw, &decoded); uerr == nil {
				out.Decoded = decoded
			}
		}
	}

	return out
}

// Close terminates the underlying client session. Safe to call more
// than once. Called automatically by Harness.Cleanup; tests should not
// need to invoke directly.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.session != nil {
		_ = c.session.Close()
	}
}

// collectText flattens the TextContent blocks of a tool result into a
// single newline-joined string. Non-text content is skipped (the
// harness does not currently consume image / resource blocks).
func collectText(content []gomcp.Content) string {
	var out string
	for i, c := range content {
		tc, ok := c.(*gomcp.TextContent)
		if !ok {
			continue
		}
		if i > 0 && out != "" {
			out += "\n"
		}
		out += tc.Text
	}
	return out
}

// bearerRoundTripper attaches an "Authorization: Bearer <token>"
// header to every outgoing request. It clones the request to avoid
// mutating the caller's request, matching the production CLI client
// at cmd/yorishiro-proxy/client.go.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		r := req.Clone(req.Context())
		r.Header.Set("Authorization", "Bearer "+t.token)
		req = r
	}
	return t.base.RoundTrip(req)
}
