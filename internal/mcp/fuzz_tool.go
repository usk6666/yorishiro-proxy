package mcp

import (
	"context"
	"fmt"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
	// FlowID is the template flow for fuzz action.
	FlowID string `json:"flow_id,omitempty" jsonschema:"template flow ID for fuzz"`

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

// validAttackTypes lists the valid attack_type values for fuzz actions.
var validAttackTypes = []string{"sequential", "parallel"}

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
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz",
		"action", input.Action,
		"flow_id", input.Params.FlowID,
		"fuzz_id", input.Params.FuzzID,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

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
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableFuzzActions, ", "))
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
	if err := validateFuzzParams(params); err != nil {
		return nil, nil, err
	}

	// Load template flow first for protocol check, then load messages.
	templateFlow, err := s.loadFuzzTemplateFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, err
	}

	// gRPC flows use length-prefixed protobuf frames; byte-offset fuzzing would
	// corrupt the frame header and produce invalid messages. Reject early until
	// frame-aware mutation is implemented.
	if templateFlow.Protocol == "gRPC" {
		return nil, nil, fmt.Errorf("fuzzing gRPC flows is not yet supported: gRPC uses length-prefixed protobuf frames that require frame-aware mutation")
	}

	templateSendMsgs, err := s.loadFuzzTemplateSendMessages(ctx, templateFlow.ID)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkFuzzTargetScopeWithData(templateFlow, templateSendMsgs); err != nil {
		return nil, nil, err
	}

	// SafetyFilter input check: validate the template flow's body/URL/headers.
	if err := s.checkFuzzSafetyInputWithData(templateSendMsgs); err != nil {
		return nil, nil, err
	}

	if s.deps.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}

	cfg := buildFuzzConfig(params)

	if params.Hooks != nil {
		hooks := newFuzzHookCallbacks(s.deps, params.Hooks)
		cfg.Hooks = hooks
	}

	// Inject target scope checker to validate URLs after position application
	// and KV Store template expansion, preventing SSRF via payload injection.
	if s.deps.targetScope != nil && s.deps.targetScope.HasRules() {
		ts := s.deps.targetScope
		cfg.TargetScopeChecker = func(u *url.URL) error {
			return checkTargetScopeURLHelper(ts, u)
		}
	}

	// Inject safety input checker to validate each expanded payload
	// before sending, preventing destructive payloads via fuzz injection.
	if s.deps.safetyEngine != nil {
		se := s.deps.safetyEngine
		cfg.SafetyInputChecker = func(body []byte, rawURL string, headers parser.RawHeaders) error {
			if v := se.CheckInput(body, rawURL, headers); v != nil {
				return fmt.Errorf("%s", safetyViolationError(v))
			}
			return nil
		}
	}

	result, err := s.deps.fuzzRunner.Start(s.deps.appCtx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz execution: %w", err)
	}

	return nil, result, nil
}

// validateFuzzParams validates the required parameters for starting a fuzz job.
func validateFuzzParams(params fuzzParams) error {
	if params.FlowID == "" {
		return fmt.Errorf("flow_id is required for fuzz action")
	}
	if params.AttackType == "" {
		return fmt.Errorf("attack_type is required for fuzz action: valid values are %s", strings.Join(validAttackTypes, ", "))
	}
	if params.AttackType != "sequential" && params.AttackType != "parallel" {
		return fmt.Errorf("invalid attack_type %q: valid values are %s", params.AttackType, strings.Join(validAttackTypes, ", "))
	}
	if len(params.Positions) == 0 {
		return fmt.Errorf("at least one position is required for fuzz action")
	}
	if err := validateHooks(params.Hooks); err != nil {
		return fmt.Errorf("invalid hooks: %w", err)
	}
	return nil
}

// loadFuzzTemplateFlow loads the template flow from the store.
// This is called before protocol checks so unsupported protocols can be
// rejected without loading messages.
func (s *Server) loadFuzzTemplateFlow(ctx context.Context, flowID string) (*flow.Flow, error) {
	if s.deps.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	fl, err := s.deps.store.GetFlow(ctx, flowID)
	if err != nil {
		return nil, fmt.Errorf("get template flow: %w", err)
	}
	return fl, nil
}

// loadFuzzTemplateSendMessages loads the send-direction messages for the given flow.
func (s *Server) loadFuzzTemplateSendMessages(ctx context.Context, flowID string) ([]*flow.Message, error) {
	sendMsgs, err := s.deps.store.GetMessages(ctx, flowID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, fmt.Errorf("get send messages: %w", err)
	}
	return sendMsgs, nil
}

// checkFuzzTargetScopeWithData enforces the target scope on pre-loaded template data.
// If no target scope is configured, this is a no-op.
func (s *Server) checkFuzzTargetScopeWithData(_ *flow.Flow, sendMsgs []*flow.Message) error {
	if s.deps.targetScope == nil || !s.deps.targetScope.HasRules() {
		return nil
	}
	if len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
		if err := s.checkTargetScopeURL(sendMsgs[0].URL); err != nil {
			return err
		}
	}
	return nil
}

// checkFuzzSafetyInputWithData validates pre-loaded template send messages against
// the safety filter engine. If no safety engine is configured, this is a no-op.
func (s *Server) checkFuzzSafetyInputWithData(sendMsgs []*flow.Message) error {
	if s.deps.safetyEngine == nil {
		return nil
	}
	if len(sendMsgs) == 0 {
		return nil
	}
	msg := sendMsgs[0]
	var rawURL string
	if msg.URL != nil {
		rawURL = msg.URL.String()
	}
	headers := httpHeaderToRawHeaders(gohttp.Header(msg.Headers))
	if v := s.deps.safetyEngine.CheckInput(msg.Body, rawURL, headers); v != nil {
		return fmt.Errorf("%s", safetyViolationError(v))
	}
	return nil
}

// buildFuzzConfig constructs a fuzzer.RunConfig from the fuzz parameters.
func buildFuzzConfig(params fuzzParams) fuzzer.RunConfig {
	cfg := fuzzer.RunConfig{
		Config: fuzzer.Config{
			FlowID:      params.FlowID,
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
	return cfg
}

// handleFuzzPauseAction handles the fuzz_pause action within the fuzz tool.
func (s *Server) handleFuzzPauseAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.deps.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_pause action")
	}

	ctrl := s.deps.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Pause(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_pause: %w", err)
	}

	// Sync the paused status to DB immediately so query reflects the change
	// without waiting for the next progress update tick.
	s.syncFuzzJobStatus(params.FuzzID, string(ctrl.Status()))

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_pause",
		Status: string(ctrl.Status()),
	}, nil
}

// handleFuzzResumeAction handles the fuzz_resume action within the fuzz tool.
func (s *Server) handleFuzzResumeAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.deps.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_resume action")
	}

	ctrl := s.deps.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Resume(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_resume: %w", err)
	}

	// Sync the resumed status to DB immediately so query reflects the change
	// without waiting for the next progress update tick.
	s.syncFuzzJobStatus(params.FuzzID, string(ctrl.Status()))

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_resume",
		Status: string(ctrl.Status()),
	}, nil
}

// syncFuzzJobStatus updates the fuzz job's status in the DB immediately.
// This is best-effort; failures are logged but do not propagate errors.
func (s *Server) syncFuzzJobStatus(fuzzID, status string) {
	if s.deps.fuzzStore == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.deps.fuzzStore.UpdateFuzzJobStatus(ctx, fuzzID, status); err != nil {
		slog.Warn("failed to sync fuzz job status to DB", "job_id", fuzzID, "status", status, "error", err)
	}
}

// handleFuzzCancelAction handles the fuzz_cancel action within the fuzz tool.
func (s *Server) handleFuzzCancelAction(params fuzzParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.deps.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_cancel action")
	}

	ctrl := s.deps.fuzzRunner.Registry().Get(params.FuzzID)
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
