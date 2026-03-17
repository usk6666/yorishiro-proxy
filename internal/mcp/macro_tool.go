package mcp

import (
	"context"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// macroToolInput is the typed input for the macro tool.
type macroToolInput struct {
	// Action specifies the macro action to execute.
	// Available actions: define_macro, run_macro, delete_macro.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params macroToolParams `json:"params"`
}

// macroToolParams holds the union of all macro action-specific parameters.
// Only the fields relevant to the specified action are used.
type macroToolParams struct {
	// Name is the macro name (required for all macro actions).
	Name string `json:"name,omitempty" jsonschema:"macro name"`
	// Description is a human-readable description (define_macro).
	Description string `json:"description,omitempty" jsonschema:"macro description"`
	// Steps defines the macro steps (define_macro).
	Steps []macroStepInput `json:"steps,omitempty" jsonschema:"macro steps for define_macro"`
	// InitialVars are pre-populated KV Store entries (define_macro).
	InitialVars map[string]string `json:"initial_vars,omitempty" jsonschema:"initial KV Store entries for define_macro"`
	// MacroTimeout is the overall macro timeout in milliseconds (define_macro).
	MacroTimeout int `json:"macro_timeout_ms,omitempty" jsonschema:"macro timeout in milliseconds"`
	// Vars are runtime variable overrides for run_macro.
	Vars map[string]string `json:"vars,omitempty" jsonschema:"runtime variable overrides for run_macro"`
}

// availableMacroActions lists the valid action names for the macro tool.
var availableMacroActions = []string{"define_macro", "run_macro", "delete_macro"}

// registerMacro registers the macro MCP tool.
func (s *Server) registerMacro() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "macro",
		Description: "Define and execute macro workflows for multi-step security testing. " +
			"Available actions: " +
			"'define_macro' saves a macro definition (upsert) with steps, extraction rules, and guards; " +
			"'run_macro' executes a stored macro for testing; " +
			"'delete_macro' removes a stored macro definition.",
	}, s.handleMacroTool)
}

// handleMacroTool routes the macro tool invocation to the appropriate action handler.
func (s *Server) handleMacroTool(ctx context.Context, _ *gomcp.CallToolRequest, input macroToolInput) (*gomcp.CallToolResult, any, error) {
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
