package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// macroToolInput is the typed input for the macro tool.
type macroToolInput struct {
	// Action specifies the macro action to execute.
	// Available actions: define_macro, run_macro, delete_macro.
	Action string `json:"action" jsonschema:"REQUIRED action to execute: define_macro|run_macro|delete_macro"`
	// Params holds action-specific parameters.
	Params macroToolParams `json:"params" jsonschema:"action-specific parameters; only the fields relevant to the chosen action are read"`
}

// macroToolParams holds the union of all macro action-specific parameters.
// Only the fields relevant to the specified action are used.
type macroToolParams struct {
	// Name is the macro name (required for all macro actions).
	Name string `json:"name,omitempty" jsonschema:"macro name; required for every action. define_macro upserts an existing macro with the same name"`
	// Description is a human-readable description (define_macro).
	Description string `json:"description,omitempty" jsonschema:"human-readable macro description for define_macro"`
	// Steps defines the macro steps (define_macro).
	Steps []macroStepInput `json:"steps,omitempty" jsonschema:"ordered list of steps executed in sequence for define_macro; maximum 50"`
	// InitialVars are pre-populated KV Store entries (define_macro).
	InitialVars map[string]string `json:"initial_vars,omitempty" jsonschema:"pre-populated KV Store entries for define_macro; reference each key from a step's override_method / override_url / override_headers value / override_body as §key§ (U+00A7 SECTION SIGN on both sides). Keys are case-sensitive"`
	// MacroTimeout is the overall macro timeout in milliseconds (define_macro).
	MacroTimeout int `json:"macro_timeout_ms,omitempty" jsonschema:"overall macro timeout in milliseconds; default 300000"`
	// Vars are runtime variable overrides for run_macro.
	Vars map[string]string `json:"vars,omitempty" jsonschema:"runtime KV Store overrides for run_macro, merged over the macro's initial_vars; reference each key from a step's override_* field as §key§"`
}

// availableMacroActions lists the valid action names for the macro tool.
var availableMacroActions = []string{"define_macro", "run_macro", "delete_macro"}

// registerMacro registers the macro MCP tool.
func (s *Server) registerMacro() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "macro",
		Description: "Define and execute multi-step macro workflows for chained security testing. " +
			"Actions: 'define_macro' (upsert, with steps, extraction rules, and guards), " +
			"'run_macro' (execute a stored macro), 'delete_macro'. " +
			"Variables: write §name§ (U+00A7 SECTION SIGN on BOTH sides) to interpolate a KV Store value into " +
			"steps[].override_method / override_url / override_headers values / override_body — " +
			"e.g. override_headers {\"Cookie\": \"PHPSESSID=§session_cookie§\"}. " +
			"Optional encoder chain: §name | url_encode | base64§; an unknown encoder fails the step. " +
			"{{name}}, ${name} and %name% are NOT expanded — they are sent literally on the wire, and a " +
			"post-substitution scan of the url / header values / body reports step status \"warning\" with warnings[]. " +
			"An unknown §name§ is also left literal. " +
			"Values come from params.initial_vars, run_macro params.vars, and earlier steps' extract[].name. " +
			"See yorishiro://help/macro.",
	}, s.handleMacroTool)
}

// handleMacroTool routes the macro tool invocation to the appropriate action handler.
func (s *Server) handleMacroTool(ctx context.Context, _ *gomcp.CallToolRequest, input macroToolInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "macro",
		"action", input.Action,
		"name", input.Params.Name,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "macro",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableMacroActions, ", "))
	case "define_macro":
		mp := macroToolParamsToMacroParams(input.Params)
		result, err := s.handleDefineMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "run_macro":
		mp := macroToolParamsToMacroParams(input.Params)
		result, err := s.handleRunMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "delete_macro":
		mp := macroToolParamsToMacroParams(input.Params)
		result, err := s.handleDeleteMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableMacroActions, ", "))
	}
}

// macroToolParamsToMacroParams converts macro tool input params to the internal macroParams.
func macroToolParamsToMacroParams(p macroToolParams) macroParams {
	return macroParams{
		Name:        p.Name,
		Description: p.Description,
		Steps:       p.Steps,
		InitialVars: p.InitialVars,
		TimeoutMs:   p.MacroTimeout,
		Vars:        p.Vars,
	}
}
