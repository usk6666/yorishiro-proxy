// Package mcp registers prompts in addition to tools and resources.
//
// # MCP Prompts
//
// Prompts deliver user-facing vulnerability-verification playbooks to the
// model. Each prompt is a self-contained playbook the model can execute
// step-by-step in a fresh chat — no fetching of MCP Resources is required.
// Delivery is inline-expansion (Option 1 from the "AI Agent first /
// MCP-native interface" draft §5.7): prompts/get returns a single
// PromptMessage whose Content is a TextContent with the full playbook body
// embedded via //go:embed.
//
// # Placeholder Syntax
//
// Prompt bodies use {{arg_name}} double-brace placeholders matching the
// snake_case names declared on each prompt's PromptArgument. The handler
// substitutes them with strings.ReplaceAll at GetPrompt time. This syntax
// is deliberately distinct from Go text/template's {{.Field}} so the model
// is not misled into thinking the prompt body is a Go template.
//
//   - Required arguments missing or empty → the handler returns an error
//     before substitution.
//   - Optional arguments missing or empty → substituted with the empty
//     string.
//
// Arguments are flat map[string]string per the MCP go-sdk PromptArgument
// shape — there is no JSON schema, no type, no enum.
package mcp

import (
	"context"
	"embed"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed prompts/*.md
var promptsFS embed.FS

// promptDef declares a single MCP prompt to register.
type promptDef struct {
	name        string
	title       string
	description string
	filename    string // path within the embedded FS (e.g. "prompts/verify-idor.md")
	arguments   []*gomcp.PromptArgument
}

// userPrompts lists every user-facing vulnerability-verification playbook
// exposed via MCP prompts/list. Descriptions stay in the 80–200 character
// band so prompts/list metadata stays cheap to deliver on every host
// connect (see draft §6.3 token estimate).
var userPrompts = []promptDef{
	{
		name:        "verify-idor",
		title:       "Verify IDOR / privilege escalation",
		description: "Verify Insecure Direct Object Reference on a recorded HTTP flow — sweep candidate ids in body or path and compare authenticated vs unauthorised access.",
		filename:    "prompts/verify-idor.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id of the authenticated request to test.", Required: true},
			{Name: "id_field", Description: "Body JSON path or URL path segment that carries the user/object id.", Required: true},
			{Name: "candidate_ids", Description: "Comma-separated list of ids to substitute in place of the authenticated user's id.", Required: true},
		},
	},
	{
		name:        "verify-sqli",
		title:       "Verify SQL injection",
		description: "Verify SQL injection on a recorded HTTP flow with time-based / error-based / UNION techniques; method-aware safety guardrails block destructive payloads.",
		filename:    "prompts/verify-sqli.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id of the request that reaches the suspected SQL sink.", Required: true},
			{Name: "injection_point", Description: "Typed fuzz_http positions[].path for the sink (e.g. body, raw_query, headers[N].value).", Required: true},
			{Name: "technique", Description: "Optional: time-based (default), error-based, union-orderby, or union-select."},
		},
	},
	{
		name:        "verify-xss",
		title:       "Verify reflected XSS",
		description: "Verify reflected Cross-Site Scripting on a recorded HTTP flow using YP_-prefixed marker payloads — no scripts execute; only detects unescaped reflection.",
		filename:    "prompts/verify-xss.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id of the request that reflects user input into the response.", Required: true},
			{Name: "injection_point", Description: "Typed fuzz_http positions[].path — usually raw_query, body, or headers[N].value.", Required: true},
		},
	},
	{
		name:        "verify-csrf",
		title:       "Verify CSRF token validation",
		description: "Verify whether a state-changing HTTP flow validates its CSRF token by emptying, forging, or removing the token header and observing acceptance.",
		filename:    "prompts/verify-csrf.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id of a state-changing request that includes a CSRF token.", Required: true},
			{Name: "token_header_name", Description: "Header that carries the CSRF token (e.g. X-CSRF-Token, X-XSRF-Token).", Required: true},
		},
	},
	{
		name:        "audit-auth",
		title:       "Audit authentication and authorization",
		description: "Audit a recorded HTTP flow for authentication-bypass and role-downgrade / privilege-escalation flaws by replacing the credential header value.",
		filename:    "prompts/audit-auth.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id of a privileged or authenticated request.", Required: true},
			{Name: "auth_header_name", Description: "Header that carries the credential (typically Authorization or Cookie).", Required: true},
			{Name: "low_priv_token", Description: "Optional: lower-privilege token to test for role downgrade."},
		},
	},
	{
		name:        "fuzz-endpoint",
		title:       "Fuzz an endpoint — general workflow",
		description: "General-purpose fuzz workflow for a recorded request; picks fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw based on the captured flow's protocol.",
		filename:    "prompts/fuzz-endpoint.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id to fuzz against.", Required: true},
			{Name: "position_path", Description: "Typed position path matching the protocol (e.g. body, raw_query, headers[N].value, payload, messages[N].payload).", Required: true},
			{Name: "payload_set", Description: "Short name or description of what to test; used as the fuzz tag (e.g. boundary-numbers, path-traversal).", Required: true},
		},
	},
	{
		name:        "replay-with-mods",
		title:       "Replay a recorded request with modifications",
		description: "Single-shot replay of a recorded request using resend_http / resend_ws / resend_grpc / resend_raw with selective header / body modifications.",
		filename:    "prompts/replay-with-mods.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Description: "Recorded flow_id to replay.", Required: true},
			{Name: "mods_description", Description: "Short description of what to change (e.g. swap Authorization to low-priv token; set body $.role to 'admin').", Required: true},
		},
	},
	{
		name:        "capture-traffic",
		title:       "Capture traffic via playwright-cli",
		description: "Capture HTTP / WebSocket / gRPC traffic via playwright-cli through yorishiro-proxy with a scoped capture filter; obtains flow_ids for verification playbooks.",
		filename:    "prompts/capture-traffic.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_host", Description: "Hostname or glob of the application under test (e.g. *.target.example.com).", Required: true},
			{Name: "listen_addr", Description: "Optional: proxy listen address (defaults to 127.0.0.1:8080)."},
		},
	},
	{
		name:        "stateful-fuzz-loop",
		title:       "Stateful-fuzz loop with macros",
		description: "Drive setup → resend_http → teardown around a stateful endpoint that cannot be safely fuzzed in bulk (repeated DELETE, single-use tokens, rotating CSRF).",
		filename:    "prompts/stateful-fuzz-loop.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "setup_macro_name", Description: "Name for the setup macro (e.g. setup-item).", Required: true},
			{Name: "teardown_macro_name", Description: "Name for the teardown macro (e.g. teardown).", Required: true},
			{Name: "target_flow_id", Description: "Recorded flow_id of the stateful endpoint under test.", Required: true},
		},
	},
}

// registerPrompts registers every user-facing playbook as an MCP prompt.
// Capability advertisement (`prompts: {listChanged:true}`) is handled
// automatically by the go-sdk when the first prompt is added.
func (s *Server) registerPrompts() {
	for _, pd := range userPrompts {
		s.server.AddPrompt(
			&gomcp.Prompt{
				Name:        pd.name,
				Title:       pd.title,
				Description: pd.description,
				Arguments:   pd.arguments,
			},
			makePromptHandler(pd),
		)
	}
}

// makePromptHandler returns a PromptHandler that reads the embedded
// playbook body, validates required arguments, expands {{arg_name}}
// placeholders, and returns a single TextContent message.
func makePromptHandler(pd promptDef) gomcp.PromptHandler {
	return func(_ context.Context, req *gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		args := map[string]string{}
		if req != nil && req.Params != nil && req.Params.Arguments != nil {
			args = req.Params.Arguments
		}

		// Validate required arguments. Empty string counts as missing —
		// substituting "" into a required placeholder would produce a
		// malformed playbook that wastes a model turn.
		for _, a := range pd.arguments {
			if !a.Required {
				continue
			}
			if v, ok := args[a.Name]; !ok || v == "" {
				return nil, fmt.Errorf("argument %q is required", a.Name)
			}
		}

		body, err := promptsFS.ReadFile(pd.filename)
		if err != nil {
			return nil, fmt.Errorf("read embedded prompt %s: %w", pd.filename, err)
		}

		// Expand placeholders. Use strings.ReplaceAll (never fmt.Sprintf
		// with user-supplied value as the format string) so attacker-
		// supplied content cannot smuggle format directives.
		expanded := string(body)
		for _, a := range pd.arguments {
			placeholder := "{{" + a.Name + "}}"
			expanded = strings.ReplaceAll(expanded, placeholder, args[a.Name])
		}

		return &gomcp.GetPromptResult{
			Description: pd.description,
			Messages: []*gomcp.PromptMessage{
				{
					Role:    "user",
					Content: &gomcp.TextContent{Text: expanded},
				},
			},
		}, nil
	}
}
