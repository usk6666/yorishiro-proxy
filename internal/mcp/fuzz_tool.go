package mcp

import (
	"context"
	"fmt"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// fuzzInput is the typed input for the fuzz tool.
type fuzzInput struct {
	// Action specifies the fuzz action to execute.
	// Available actions: fuzz, fuzz_pause, fuzz_resume, fuzz_cancel.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params fuzzParams `json:"params"`
}

// fuzzParams holds the union of all fuzz action-specific parameters.
// Only the fields relevant to the specified action are used.
type fuzzParams struct {
	// SessionID is the template session for fuzz action.
	SessionID string `json:"session_id,omitempty" jsonschema:"template session ID for fuzz"`

	// fuzz parameters
	AttackType  string                       `json:"attack_type,omitempty" jsonschema:"fuzz attack type: sequential or parallel"`
	Positions   []fuzzer.Position            `json:"positions,omitempty" jsonschema:"payload positions for fuzzing"`
	PayloadSets map[string]fuzzer.PayloadSet `json:"payload_sets,omitempty" jsonschema:"named payload sets for fuzzing"`
	Tag         string                       `json:"tag,omitempty" jsonschema:"tag to label the fuzz job"`

	// fuzz execution control parameters
	Concurrency  *int     `json:"concurrency,omitempty" jsonschema:"number of concurrent workers (default: 1)"`
	RateLimitRPS *float64 `json:"rate_limit_rps,omitempty" jsonschema:"requests per second limit (0 = unlimited)"`
	DelayMs      *int     `json:"delay_ms,omitempty" jsonschema:"fixed delay between requests in ms"`
	MaxRetries   *int     `json:"max_retries,omitempty" jsonschema:"retry count per failed request"`
	TimeoutMs    *int     `json:"timeout_ms,omitempty" jsonschema:"request timeout in milliseconds (default: 30000)"`

	// fuzz stop conditions
	StopOn *fuzzer.StopCondition `json:"stop_on,omitempty" jsonschema:"automatic stop conditions for fuzz jobs"`

	// fuzz job control (fuzz_pause, fuzz_resume, fuzz_cancel)
	FuzzID string `json:"fuzz_id,omitempty" jsonschema:"fuzz job ID for pause/resume/cancel"`

	// hooks parameters
	Hooks *hooksInput `json:"hooks,omitempty" jsonschema:"pre_send/post_receive hooks for macro integration"`
}

// availableFuzzActions lists the valid action names for the fuzz tool.
var availableFuzzActions = []string{"fuzz", "fuzz_pause", "fuzz_resume", "fuzz_cancel"}

// registerFuzz registers the fuzz MCP tool.
func (s *Server) registerFuzz() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz",
		Description: "Execute fuzz testing campaigns on recorded proxy data. " +
			"Available actions: " +
			"'fuzz' starts an async fuzz campaign (returns fuzz_id immediately, query fuzz_results for progress); " +
			"'fuzz_pause' pauses a running fuzz job (requires fuzz_id); " +
			"'fuzz_resume' resumes a paused fuzz job (requires fuzz_id); " +
			"'fuzz_cancel' cancels a running or paused fuzz job (requires fuzz_id).",
	}, s.handleFuzzTool)
}

// handleFuzzTool routes the fuzz tool invocation to the appropriate action handler.
func (s *Server) handleFuzzTool(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzInput) (*gomcp.CallToolResult, any, error) {
	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableFuzzActions, ", "))
	case "fuzz":
		return s.handleFuzzStart(ctx, input.Params)
	case "fuzz_pause":
		return s.handleFuzzPauseAction(input.Params)
	case "fuzz_resume":
		return s.handleFuzzResumeAction(input.Params)
	case "fuzz_cancel":
		return s.handleFuzzCancelAction(input.Params)
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableFuzzActions)
	}
}

// executeFuzzControlResult is the structured output of fuzz control actions.
type executeFuzzControlResult struct {
	FuzzID string `json:"fuzz_id"`
	Action string `json:"action"`
	Status string `json:"status"`
}

// handleFuzzStart handles the fuzz action within the fuzz tool.
func (s *Server) handleFuzzStart(ctx context.Context, params fuzzParams) (*gomcp.CallToolResult, *fuzzer.AsyncResult, error) {
	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for fuzz action")
	}
	if params.AttackType == "" {
		return nil, nil, fmt.Errorf("attack_type is required for fuzz action")
	}
	if len(params.Positions) == 0 {
		return nil, nil, fmt.Errorf("at least one position is required for fuzz action")
	}

	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	// Target scope enforcement: check the template session's URL before starting fuzz.
	if s.targetScope != nil && s.targetScope.HasRules() {
		if s.store == nil {
			return nil, nil, fmt.Errorf("session store is not initialized")
		}
		templateSess, err := s.store.GetSession(ctx, params.SessionID)
		if err != nil {
			return nil, nil, fmt.Errorf("get template session for target scope check: %w", err)
		}
		sendMsgs, err := s.store.GetMessages(ctx, templateSess.ID, session.MessageListOptions{Direction: "send"})
		if err != nil {
			return nil, nil, fmt.Errorf("get send messages for target scope check: %w", err)
		}
		if len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
			if err := s.checkTargetScopeURL(sendMsgs[0].URL); err != nil {
				return nil, nil, err
			}
		}
	}

	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}

	cfg := fuzzer.RunConfig{
		Config: fuzzer.Config{
			SessionID:   params.SessionID,
			AttackType:  params.AttackType,
			Positions:   params.Positions,
			PayloadSets: params.PayloadSets,
			Tag:         params.Tag,
		},
		StopOn: params.StopOn,
	}
	if params.TimeoutMs != nil {
		cfg.TimeoutMs = *params.TimeoutMs
	}
	if params.Concurrency != nil {
		cfg.Concurrency = *params.Concurrency
	}
	if params.RateLimitRPS != nil {
		cfg.RateLimitRPS = *params.RateLimitRPS
	}
	if params.DelayMs != nil {
		cfg.DelayMs = *params.DelayMs
	}
	if params.MaxRetries != nil {
		cfg.MaxRetries = *params.MaxRetries
	}

	if params.Hooks != nil {
		hooks := newFuzzHookCallbacks(s, params.Hooks)
		cfg.Hooks = hooks
	}

	result, err := s.fuzzRunner.Start(s.appCtx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz execution: %w", err)
	}

	return nil, result, nil
}

// handleFuzzPauseAction handles the fuzz_pause action within the fuzz tool.
func (s *Server) handleFuzzPauseAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_pause action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Pause(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_pause: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_pause",
		Status: string(ctrl.Status()),
	}, nil
}

// handleFuzzResumeAction handles the fuzz_resume action within the fuzz tool.
func (s *Server) handleFuzzResumeAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_resume action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Resume(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_resume: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_resume",
		Status: string(ctrl.Status()),
	}, nil
}

// handleFuzzCancelAction handles the fuzz_cancel action within the fuzz tool.
func (s *Server) handleFuzzCancelAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_cancel action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Cancel(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_cancel: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_cancel",
		Status: string(ctrl.Status()),
	}, nil
}
