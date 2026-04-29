package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// macroParams holds parameters for macro-related execute actions.
type macroParams struct {
	// Name is the macro name (required for define_macro, run_macro, delete_macro).
	Name string `json:"name"`
	// Description is a human-readable description (define_macro).
	Description string `json:"description,omitempty"`
	// Steps defines the macro steps (define_macro).
	Steps []macroStepInput `json:"steps,omitempty"`
	// InitialVars are pre-populated KV Store entries (define_macro).
	InitialVars map[string]string `json:"initial_vars,omitempty"`
	// TimeoutMs is the overall macro timeout in milliseconds (define_macro).
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// Vars are runtime variable overrides for run_macro.
	Vars map[string]string `json:"vars,omitempty"`
}

// macroStepInput represents a single macro step in the MCP input.
type macroStepInput struct {
	ID              string            `json:"id"`
	StreamID        string            `json:"flow_id"`
	OverrideMethod  string            `json:"override_method,omitempty"`
	OverrideURL     string            `json:"override_url,omitempty"`
	OverrideHeaders map[string]string `json:"override_headers,omitempty"`
	OverrideBody    *string           `json:"override_body,omitempty"`
	OnError         string            `json:"on_error,omitempty"`
	RetryCount      int               `json:"retry_count,omitempty"`
	RetryDelayMs    int               `json:"retry_delay_ms,omitempty"`
	TimeoutMs       int               `json:"timeout_ms,omitempty"`
	Extract         []extractionInput `json:"extract,omitempty"`
	When            *guardInput       `json:"when,omitempty"`
}

// extractionInput represents a value extraction rule in the MCP input.
type extractionInput struct {
	Name       string `json:"name"`
	From       string `json:"from"`
	Source     string `json:"source"`
	HeaderName string `json:"header_name,omitempty"`
	Regex      string `json:"regex,omitempty"`
	Group      int    `json:"group,omitempty"`
	JSONPath   string `json:"json_path,omitempty"`
	Default    string `json:"default,omitempty"`
	Required   bool   `json:"required,omitempty"`
}

// guardInput represents a step guard condition in the MCP input.
type guardInput struct {
	Step            string            `json:"step,omitempty"`
	StatusCode      *int              `json:"status_code,omitempty"`
	StatusCodeRange [2]int            `json:"status_code_range,omitempty"`
	HeaderMatch     map[string]string `json:"header_match,omitempty"`
	BodyMatch       string            `json:"body_match,omitempty"`
	ExtractedVar    string            `json:"extracted_var,omitempty"`
	Negate          bool              `json:"negate,omitempty"`
}

// macroConfig is the JSON structure stored in the macros table config column.
// It contains all the fields needed to reconstruct a macro.Macro.
type macroConfig struct {
	Steps       []macroStepInput  `json:"steps"`
	InitialVars map[string]string `json:"initial_vars,omitempty"`
	TimeoutMs   int               `json:"timeout_ms,omitempty"`
}

// macroDefineMacroResult is the structured output of the define_macro action.
type macroDefineMacroResult struct {
	Name      string `json:"name"`
	StepCount int    `json:"step_count"`
	Created   bool   `json:"created"`
}

// macroRunMacroResult is the structured output of the run_macro action.
type macroRunMacroResult struct {
	MacroName     string                 `json:"macro_name"`
	Status        string                 `json:"status"`
	StepsExecuted int                    `json:"steps_executed"`
	KVStore       map[string]string      `json:"kv_store"`
	StepResults   []macroStepResultEntry `json:"step_results"`
	Error         string                 `json:"error,omitempty"`
}

// macroStepResultEntry is a single step result in the run_macro response.
type macroStepResultEntry struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

// macroDeleteMacroResult is the structured output of the delete_macro action.
type macroDeleteMacroResult struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

// handleDefineMacro handles the define_macro action.
// It validates the macro definition, serializes the config to JSON, and upserts into DB.
func (s *Server) handleDefineMacro(ctx context.Context, params macroParams) (*macroDefineMacroResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required for define_macro action")
	}
	if len(params.Steps) == 0 {
		return nil, fmt.Errorf("steps is required for define_macro action")
	}

	// Convert to macro.Macro for validation.
	m, err := macroParamsToMacro(params)
	if err != nil {
		return nil, fmt.Errorf("invalid macro definition: %w", err)
	}

	// Validate using macro package's validator.
	if err := validateMacroDefinition(m); err != nil {
		return nil, fmt.Errorf("invalid macro definition: %w", err)
	}

	// Check if macro already exists (to determine created vs updated).
	// Distinguish "not found" (macro is new) from real DB errors.
	_, getErr := s.flowStore.store.GetMacro(ctx, params.Name)
	var isNew bool
	if getErr != nil {
		if strings.Contains(getErr.Error(), "not found") {
			isNew = true
		} else {
			return nil, fmt.Errorf("check existing macro: %w", getErr)
		}
	}

	// Serialize config to JSON.
	cfg := macroConfig{
		Steps:       params.Steps,
		InitialVars: params.InitialVars,
		TimeoutMs:   params.TimeoutMs,
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal macro config: %w", err)
	}

	if err := s.flowStore.store.SaveMacro(ctx, params.Name, params.Description, string(configJSON)); err != nil {
		return nil, fmt.Errorf("save macro: %w", err)
	}

	return &macroDefineMacroResult{
		Name:      params.Name,
		StepCount: len(params.Steps),
		Created:   isNew,
	}, nil
}

// handleRunMacro handles the run_macro action.
// It loads the macro from DB, creates a macro.Engine, and runs it.
// Access control is handled by the target scope enforcement layer.
func (s *Server) handleRunMacro(ctx context.Context, params macroParams) (*macroRunMacroResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required for run_macro action")
	}

	// Load and build macro from DB.
	m, cfg, err := s.loadAndBuildMacro(ctx, params.Name)
	if err != nil {
		return nil, err
	}

	// Allow run_macro to override the macro-level timeout.
	if params.TimeoutMs > 0 {
		m.TimeoutMs = params.TimeoutMs
	}

	// Target scope enforcement: check each step's target URL before running.
	if err := s.checkMacroStepsTargetScope(ctx, cfg.Steps); err != nil {
		return nil, err
	}

	// Create engine with HTTP client and session fetcher.
	sendFunc := s.macroSendFunc(params.Name)
	fetcher := &storeFlowFetcher{store: s.flowStore.store}

	engine, err := macro.NewEngine(sendFunc, fetcher)
	if err != nil {
		return nil, fmt.Errorf("create macro engine: %w", err)
	}

	result, err := engine.Run(ctx, m, params.Vars)
	if err != nil {
		return nil, fmt.Errorf("run macro: %w", err)
	}

	return buildRunMacroResult(result), nil
}

// loadAndBuildMacro loads a macro record from DB, parses its config, and builds a macro.Macro.
func (s *Server) loadAndBuildMacro(ctx context.Context, name string) (*macro.Macro, macroConfig, error) {
	rec, err := s.flowStore.store.GetMacro(ctx, name)
	if err != nil {
		return nil, macroConfig{}, fmt.Errorf("load macro: %w", err)
	}

	var cfg macroConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return nil, macroConfig{}, fmt.Errorf("parse macro config: %w", err)
	}

	m, err := configToMacro(rec.Name, rec.Description, cfg)
	if err != nil {
		return nil, macroConfig{}, fmt.Errorf("build macro from config: %w", err)
	}

	return m, cfg, nil
}

// checkMacroStepsTargetScope checks each macro step's target URL against the target scope rules.
// It checks both override_url and the flow's original URL for each step.
func (s *Server) checkMacroStepsTargetScope(ctx context.Context, steps []macroStepInput) error {
	if s.connector.targetScope == nil || !s.connector.targetScope.HasRules() {
		return nil
	}
	for _, step := range steps {
		if step.OverrideURL != "" {
			u, parseErr := url.Parse(step.OverrideURL)
			if parseErr == nil && u.Host != "" {
				if scopeErr := s.checkTargetScopeURL(u); scopeErr != nil {
					return fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
				}
			}
		}
		sendMsgs, msgErr := s.flowStore.store.GetFlows(ctx, step.StreamID, flow.FlowListOptions{Direction: "send"})
		if msgErr == nil && len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
			if step.OverrideURL == "" {
				if scopeErr := s.checkTargetScopeURL(sendMsgs[0].URL); scopeErr != nil {
					return fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
				}
			}
		}
	}
	return nil
}

// buildRunMacroResult converts a macro.Result to the MCP response format.
func buildRunMacroResult(result *macro.Result) *macroRunMacroResult {
	stepResults := make([]macroStepResultEntry, len(result.StepResults))
	for i, sr := range result.StepResults {
		stepResults[i] = macroStepResultEntry{
			ID:         sr.ID,
			Status:     sr.Status,
			StatusCode: sr.StatusCode,
			DurationMs: sr.DurationMs,
			Error:      sr.Error,
		}
	}

	return &macroRunMacroResult{
		MacroName:     result.MacroName,
		Status:        result.Status,
		StepsExecuted: result.StepsExecuted,
		KVStore:       result.KVStore,
		StepResults:   stepResults,
		Error:         result.Error,
	}
}

// handleDeleteMacro handles the delete_macro action.
func (s *Server) handleDeleteMacro(ctx context.Context, params macroParams) (*macroDeleteMacroResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required for delete_macro action")
	}

	if err := s.flowStore.store.DeleteMacro(ctx, params.Name); err != nil {
		return nil, fmt.Errorf("delete macro: %w", err)
	}

	return &macroDeleteMacroResult{
		Name:    params.Name,
		Deleted: true,
	}, nil
}

// macroParamsToMacro converts MCP input params to a macro.Macro for validation.
func macroParamsToMacro(params macroParams) (*macro.Macro, error) {
	steps := make([]macro.Step, len(params.Steps))
	for i, s := range params.Steps {
		steps[i] = stepInputToStep(s)
	}

	return &macro.Macro{
		Name:        params.Name,
		Description: params.Description,
		Steps:       steps,
		InitialVars: params.InitialVars,
		TimeoutMs:   params.TimeoutMs,
	}, nil
}

// configToMacro converts stored config to a macro.Macro.
func configToMacro(name, description string, cfg macroConfig) (*macro.Macro, error) {
	steps := make([]macro.Step, len(cfg.Steps))
	for i, s := range cfg.Steps {
		steps[i] = stepInputToStep(s)
	}

	return &macro.Macro{
		Name:        name,
		Description: description,
		Steps:       steps,
		InitialVars: cfg.InitialVars,
		TimeoutMs:   cfg.TimeoutMs,
	}, nil
}

// stepInputToStep converts a macroStepInput to a macro.Step.
func stepInputToStep(s macroStepInput) macro.Step {
	step := macro.Step{
		ID:              s.ID,
		StreamID:        s.StreamID,
		OverrideMethod:  s.OverrideMethod,
		OverrideURL:     s.OverrideURL,
		OverrideHeaders: s.OverrideHeaders,
		OverrideBody:    s.OverrideBody,
		OnError:         macro.OnError(s.OnError),
		RetryCount:      s.RetryCount,
		RetryDelayMs:    s.RetryDelayMs,
		TimeoutMs:       s.TimeoutMs,
	}

	for _, e := range s.Extract {
		step.Extract = append(step.Extract, macro.ExtractionRule{
			Name:       e.Name,
			From:       macro.ExtractionFrom(e.From),
			Source:     macro.ExtractionSource(e.Source),
			HeaderName: e.HeaderName,
			Regex:      e.Regex,
			Group:      e.Group,
			JSONPath:   e.JSONPath,
			Default:    e.Default,
			Required:   e.Required,
		})
	}

	if s.When != nil {
		step.When = &macro.Guard{
			Step:            s.When.Step,
			StatusCode:      s.When.StatusCode,
			StatusCodeRange: s.When.StatusCodeRange,
			HeaderMatch:     s.When.HeaderMatch,
			BodyMatch:       s.When.BodyMatch,
			ExtractedVar:    s.When.ExtractedVar,
			Negate:          s.When.Negate,
		}
	}

	return step
}

// validateMacroDefinition validates a macro definition.
func validateMacroDefinition(m *macro.Macro) error {
	if m.Name == "" {
		return fmt.Errorf("macro name is required")
	}
	if len(m.Steps) == 0 {
		return fmt.Errorf("macro must have at least one step")
	}
	if len(m.Steps) > macro.MaxSteps {
		return fmt.Errorf("macro exceeds maximum step count (%d > %d)", len(m.Steps), macro.MaxSteps)
	}

	seenIDs := make(map[string]bool, len(m.Steps))
	for i := range m.Steps {
		step := &m.Steps[i]
		if err := validateMacroStep(step, i, seenIDs); err != nil {
			return err
		}
	}

	return nil
}

// validateMacroStep validates a single macro step and updates the seenIDs map.
func validateMacroStep(step *macro.Step, index int, seenIDs map[string]bool) error {
	if step.ID == "" {
		return fmt.Errorf("step at index %d has no ID", index)
	}
	if seenIDs[step.ID] {
		return fmt.Errorf("duplicate step ID %q", step.ID)
	}
	seenIDs[step.ID] = true

	if step.StreamID == "" {
		return fmt.Errorf("step %q has no flow_id", step.ID)
	}

	if step.OnError != "" && step.OnError != macro.OnErrorAbort && step.OnError != macro.OnErrorSkip && step.OnError != macro.OnErrorRetry {
		return fmt.Errorf("step %q has invalid on_error value %q (valid: %s)", step.ID, step.OnError, macro.ValidOnErrorList())
	}

	if step.When != nil && step.When.Step != "" {
		if !seenIDs[step.When.Step] {
			return fmt.Errorf("step %q guard references unknown or forward step %q", step.ID, step.When.Step)
		}
	}

	if len(step.OverrideHeaders) > 0 {
		if err := validateHeaderValues(step.OverrideHeaders); err != nil {
			return fmt.Errorf("step %q override_headers: %w", step.ID, err)
		}
	}

	return validateStepExtractionRules(step)
}

// validateStepExtractionRules validates all extraction rules in a macro step.
// Validation logic for source/from enum values is delegated to the macro package
// via macro.ValidSource and macro.ValidFrom to avoid duplicating the allow-lists.
func validateStepExtractionRules(step *macro.Step) error {
	for j := range step.Extract {
		rule := &step.Extract[j]
		if rule.Name == "" {
			return fmt.Errorf("step %q extraction rule at index %d has no name", step.ID, j)
		}
		if rule.Source == "" {
			return fmt.Errorf("step %q extraction rule %q has no source", step.ID, rule.Name)
		}
		if !macro.ValidSource(rule.Source) {
			return fmt.Errorf("step %q extraction rule %q has invalid source %q (valid: %s)", step.ID, rule.Name, rule.Source, macro.ValidSourceList())
		}
		if rule.From == "" {
			return fmt.Errorf("step %q extraction rule %q has no from", step.ID, rule.Name)
		}
		if !macro.ValidFrom(rule.From) {
			return fmt.Errorf("step %q extraction rule %q has invalid from %q (valid: %s)", step.ID, rule.Name, rule.From, macro.ValidFromList())
		}
	}
	return nil
}

// macroSendFunc returns a macro.SendFunc for macro step execution.
// The macroName parameter is embedded in the closure so that each step's
// HTTP exchange can be recorded as a flow with macro metadata tags.
// Access control is handled by the target scope enforcement layer.
func (s *Server) macroSendFunc(macroName string) macro.SendFunc {
	return func(ctx context.Context, req *macro.SendRequest) (*macro.SendResponse, error) {
		var client httpDoer
		if s.jobRunner.replayDoer != nil {
			client = s.jobRunner.replayDoer
		} else {
			dialer := &net.Dialer{
				Timeout: defaultReplayTimeout,
			}
			transport := &http.Transport{
				DialContext: dialer.DialContext,
			}
			client = &http.Client{
				Timeout:   defaultReplayTimeout,
				Transport: transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}

		var body io.Reader
		if len(req.Body) > 0 {
			body = bytes.NewReader(req.Body)
		}

		httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		for key, values := range req.Headers {
			for i, v := range values {
				if i == 0 {
					httpReq.Header.Set(key, v)
				} else {
					httpReq.Header.Add(key, v)
				}
			}
		}

		// Target scope enforcement after template expansion: the pre-run check
		// validates static URLs, but templates like §target_url§ produce the
		// final URL only at send time. Check httpReq.URL to close the TOCTOU gap.
		if err := s.checkTargetScopeURL(httpReq.URL); err != nil {
			return nil, fmt.Errorf("macro step target scope check: %w", err)
		}

		// SafetyFilter input check: macro steps go through this SendFunc (not
		// the resend handler), so we must explicitly validate the outbound
		// request against the safety engine here. This mirrors the check in
		// handleResendAction / checkInterceptSafety for other MCP tools.
		if v := s.checkSafetyInput(req.Body, httpReq.URL.String(), httpHeaderToKeyValues(httpReq.Header)); v != nil {
			return nil, fmt.Errorf("%s", safetyViolationError(v))
		}

		start := time.Now()
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("send request: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxReplayResponseSize))
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		duration := time.Since(start)

		// Record the macro step as a flow so it appears in session history.
		if s.flowStore.store != nil {
			s.recordMacroStepSession(ctx, macroName, req, resp, respBody, httpReq, start, duration)
		}

		return &macro.SendResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       respBody,
			URL:        resp.Request.URL.String(),
		}, nil
	}
}

// recordMacroStepSession saves a macro step's HTTP exchange as a flow with
// send and receive messages. Errors are logged but not propagated to avoid
// disrupting macro execution when flow recording fails.
func (s *Server) recordMacroStepSession(
	ctx context.Context,
	macroName string,
	req *macro.SendRequest,
	resp *http.Response,
	respBody []byte,
	httpReq *http.Request,
	start time.Time,
	duration time.Duration,
) {
	tags := map[string]string{
		"macro":      macroName,
		"macro_step": req.StepID,
	}

	scheme := "http"
	if httpReq.URL != nil && httpReq.URL.Scheme == "https" {
		scheme = "https"
	}
	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		Scheme:    scheme,
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      tags,
	}
	if err := s.flowStore.store.SaveStream(ctx, fl); err != nil {
		slog.WarnContext(ctx, "failed to save macro step session",
			"macro", macroName, "step", req.StepID, "error", err)
		return
	}

	// Build recorded request headers from the actual http.Request.
	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	parsedURL := httpReq.URL

	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    req.Method,
		URL:       parsedURL,
		Headers:   recordedHeaders,
		Body:      req.Body,
	}
	if err := s.flowStore.store.SaveFlow(ctx, sendMsg); err != nil {
		slog.WarnContext(ctx, "failed to save macro step send message",
			"macro", macroName, "step", req.StepID, "error", err)
		return
	}

	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	recvMsg := &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start.Add(duration),
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := s.flowStore.store.SaveFlow(ctx, recvMsg); err != nil {
		slog.WarnContext(ctx, "failed to save macro step receive message",
			"macro", macroName, "step", req.StepID, "error", err)
	}
}

// storeFlowFetcher implements macro.FlowFetcher using the flow store.
type storeFlowFetcher struct {
	store flow.Reader
}

// GetFlowRequest retrieves the send message from a recorded flow
// and converts it to a macro.SendRequest.
func (f *storeFlowFetcher) GetFlowRequest(ctx context.Context, flowID string) (*macro.SendRequest, error) {
	msgs, err := f.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "send"})
	if err != nil {
		return nil, fmt.Errorf("get send messages for flow %s: %w", flowID, err)
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("flow %s has no send messages", flowID)
	}

	msg := msgs[0]
	req := &macro.SendRequest{
		Method:  msg.Method,
		Headers: msg.Headers,
		Body:    msg.Body,
	}
	if msg.URL != nil {
		req.URL = msg.URL.String()
	}

	return req, nil
}
