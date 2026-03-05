package macro

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Engine executes macros by running steps sequentially, managing the KV Store,
// applying templates, extracting values, and evaluating step guards.
type Engine struct {
	sendFunc       SendFunc
	flowFetcher FlowFetcher
}

// NewEngine creates a new macro engine with the given dependencies.
func NewEngine(sendFunc SendFunc, fetcher FlowFetcher) (*Engine, error) {
	if sendFunc == nil {
		return nil, fmt.Errorf("sendFunc is required")
	}
	if fetcher == nil {
		return nil, fmt.Errorf("flowFetcher is required")
	}
	return &Engine{
		sendFunc:       sendFunc,
		flowFetcher: fetcher,
	}, nil
}

// Run executes a macro definition with optional variable overrides.
// The vars parameter can override or supplement the macro's InitialVars.
func (e *Engine) Run(ctx context.Context, macro *Macro, vars map[string]string) (*Result, error) {
	if err := validateMacro(macro); err != nil {
		return nil, fmt.Errorf("invalid macro: %w", err)
	}

	// Determine the macro-level timeout.
	macroTimeoutMs := macro.TimeoutMs
	if macroTimeoutMs <= 0 {
		macroTimeoutMs = DefaultMacroTimeoutMs
	}

	// Apply macro-level timeout.
	macroCtx, macroCancel := context.WithTimeout(ctx, time.Duration(macroTimeoutMs)*time.Millisecond)
	defer macroCancel()

	// Initialize the KV Store with initial vars, then apply overrides.
	kvStore := make(map[string]string)
	for k, v := range macro.InitialVars {
		kvStore[k] = v
	}
	for k, v := range vars {
		kvStore[k] = v
	}

	result := &Result{
		MacroName:   macro.Name,
		StepResults: make([]StepResult, 0, len(macro.Steps)),
	}

	stepStates := make(map[string]*stepState)
	stepsExecuted := 0

	for i := range macro.Steps {
		step := &macro.Steps[i]

		// Check macro-level timeout before starting each step.
		if err := macroCtx.Err(); err != nil {
			result.Status = "timeout"
			result.Error = "macro timeout exceeded"
			result.StepsExecuted = stepsExecuted
			result.KVStore = kvStore
			return result, nil
		}

		stepResult, state, err := e.executeStep(macroCtx, step, kvStore, stepStates)
		if err != nil {
			// Check if this is a macro-level timeout.
			if macroCtx.Err() != nil {
				result.Status = "timeout"
				result.Error = "macro timeout exceeded"
				result.StepResults = append(result.StepResults, StepResult{
					ID:     step.ID,
					Status: "error",
					Error:  "macro timeout exceeded",
				})
				result.StepsExecuted = stepsExecuted
				result.KVStore = kvStore
				return result, nil
			}
			// This is a fatal error (abort).
			result.Status = "error"
			result.Error = err.Error()
			result.StepResults = append(result.StepResults, *stepResult)
			result.StepsExecuted = stepsExecuted
			result.KVStore = kvStore
			return result, nil
		}

		result.StepResults = append(result.StepResults, *stepResult)
		if state != nil {
			stepStates[step.ID] = state
		}
		if stepResult.Status != "skipped" {
			stepsExecuted++
		}
	}

	result.Status = "completed"
	result.StepsExecuted = stepsExecuted
	result.KVStore = kvStore
	return result, nil
}

// executeStep runs a single step, handling guards, template expansion, sending,
// extraction, and error policies. Returns a step result, the step state (for guard
// evaluation in subsequent steps), and an error only if the macro should abort.
func (e *Engine) executeStep(ctx context.Context, step *Step, kvStore map[string]string, stepStates map[string]*stepState) (*StepResult, *stepState, error) {
	// Evaluate guard condition.
	shouldExecute, err := EvaluateGuard(step.When, stepStates, kvStore)
	if err != nil {
		return &StepResult{
			ID:     step.ID,
			Status: "error",
			Error:  fmt.Sprintf("guard evaluation failed: %v", err),
		}, nil, fmt.Errorf("step %q guard evaluation: %w", step.ID, err)
	}

	if !shouldExecute {
		state := &stepState{Skipped: true}
		return &StepResult{
			ID:     step.ID,
			Status: "skipped",
		}, state, nil
	}

	// Determine step timeout.
	stepTimeoutMs := step.TimeoutMs
	if stepTimeoutMs <= 0 {
		stepTimeoutMs = DefaultStepTimeoutMs
	}

	onError := step.OnError
	if onError == "" {
		onError = OnErrorAbort
	}

	retryCount := step.RetryCount
	if retryCount <= 0 {
		retryCount = DefaultRetryCount
	}

	retryDelayMs := step.RetryDelayMs
	if retryDelayMs <= 0 {
		retryDelayMs = DefaultRetryDelayMs
	}

	// Execute with error handling policy.
	var lastErr error
	maxAttempts := 1
	if onError == OnErrorRetry {
		maxAttempts = retryCount + 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Wait before retry, but respect context cancellation.
			select {
			case <-ctx.Done():
				return &StepResult{
					ID:     step.ID,
					Status: "error",
					Error:  "macro timeout exceeded during retry wait",
				}, nil, ctx.Err()
			case <-time.After(time.Duration(retryDelayMs) * time.Millisecond):
			}
		}

		stepResult, state, err := e.doStepExecution(ctx, step, kvStore, stepTimeoutMs)
		if err == nil {
			return stepResult, state, nil
		}

		lastErr = err

		// If the parent context is cancelled, abort immediately.
		if ctx.Err() != nil {
			return &StepResult{
				ID:     step.ID,
				Status: "error",
				Error:  "macro timeout exceeded",
			}, nil, ctx.Err()
		}
	}

	// All attempts failed.
	errorMsg := fmt.Sprintf("step %q failed: %v", step.ID, lastErr)

	switch onError {
	case OnErrorSkip:
		return &StepResult{
			ID:     step.ID,
			Status: "skipped",
			Error:  errorMsg,
		}, &stepState{Skipped: true}, nil
	case OnErrorRetry:
		// All retries exhausted — abort.
		return &StepResult{
			ID:     step.ID,
			Status: "error",
			Error:  fmt.Sprintf("%s (after %d retries)", errorMsg, retryCount),
		}, nil, fmt.Errorf("%s (after %d retries)", errorMsg, retryCount)
	default: // abort
		return &StepResult{
			ID:     step.ID,
			Status: "error",
			Error:  errorMsg,
		}, nil, fmt.Errorf("%s", errorMsg)
	}
}

// doStepExecution performs the actual step execution: fetch flow, expand templates,
// send request, extract values.
func (e *Engine) doStepExecution(ctx context.Context, step *Step, kvStore map[string]string, stepTimeoutMs int) (*StepResult, *stepState, error) {
	// Create step-level timeout context.
	stepCtx, stepCancel := context.WithTimeout(ctx, time.Duration(stepTimeoutMs)*time.Millisecond)
	defer stepCancel()

	start := time.Now()

	// Fetch the template request from the recorded flow.
	baseReq, err := e.flowFetcher.GetFlowRequest(stepCtx, step.FlowID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch flow %q: %w", step.FlowID, err)
	}

	// Build the request with overrides and template expansion.
	req, err := buildRequest(step, baseReq, kvStore)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}

	// Set the step ID so the SendFunc can use it for logging/recording.
	req.StepID = step.ID

	// Send the request.
	resp, err := e.sendFunc(stepCtx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("send request: %w", err)
	}

	duration := time.Since(start)

	// Extract values from the request/response.
	if len(step.Extract) > 0 {
		if err := ExtractValues(step.Extract, req, resp, kvStore); err != nil {
			return nil, nil, fmt.Errorf("extract values: %w", err)
		}
	}

	// Cap the body stored in step state to prevent memory exhaustion when
	// attacker-controlled servers return large responses (CWE-770).
	stateBody := resp.Body
	if len(stateBody) > MaxStepBodySize {
		stateBody = stateBody[:MaxStepBodySize]
	}

	state := &stepState{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       stateBody,
	}

	return &StepResult{
		ID:         step.ID,
		Status:     "completed",
		StatusCode: resp.StatusCode,
		DurationMs: duration.Milliseconds(),
	}, state, nil
}

// buildRequest constructs a SendRequest from a base session request, applying
// step overrides and template expansion.
//
// NOTE (CWE-918): SSRF protection is the responsibility of the SendFunc
// implementation, not the Macro engine. The engine is a library that constructs
// requests from templates and KV Store values; it does not enforce network-level
// restrictions. Callers MUST provide a SendFunc that validates target URLs
// (e.g., blocking cloud metadata endpoints and internal services).
func buildRequest(step *Step, base *SendRequest, kvStore map[string]string) (*SendRequest, error) {
	req := &SendRequest{
		Method:  base.Method,
		URL:     base.URL,
		Headers: copyHeaders(base.Headers),
		Body:    base.Body,
	}

	// Apply method override.
	if step.OverrideMethod != "" {
		expanded, err := ExpandTemplate(step.OverrideMethod, kvStore)
		if err != nil {
			return nil, fmt.Errorf("expand override_method: %w", err)
		}
		req.Method = expanded
	}

	// Apply URL override.
	if step.OverrideURL != "" {
		expanded, err := ExpandTemplate(step.OverrideURL, kvStore)
		if err != nil {
			return nil, fmt.Errorf("expand override_url: %w", err)
		}
		req.URL = expanded
	}

	// Apply header overrides.
	if len(step.OverrideHeaders) > 0 {
		expandedHeaders, err := ExpandHeaders(step.OverrideHeaders, kvStore)
		if err != nil {
			return nil, fmt.Errorf("expand override_headers: %w", err)
		}
		// Validate expanded header values for CRLF injection (CWE-113).
		// Template expansion may introduce CR/LF characters from KV Store values.
		for k, v := range expandedHeaders {
			if strings.ContainsAny(k, "\r\n") {
				return nil, fmt.Errorf("expanded header key %q contains CR/LF characters", k)
			}
			if strings.ContainsAny(v, "\r\n") {
				return nil, fmt.Errorf("expanded header value for %q contains CR/LF characters", k)
			}
			req.Headers[k] = []string{v}
		}
	}

	// Apply body override.
	if step.OverrideBody != nil {
		expanded, err := ExpandTemplate(*step.OverrideBody, kvStore)
		if err != nil {
			return nil, fmt.Errorf("expand override_body: %w", err)
		}
		req.Body = []byte(expanded)
	}

	return req, nil
}

// copyHeaders creates a deep copy of a headers map.
func copyHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return make(map[string][]string)
	}
	cp := make(map[string][]string, len(h))
	for k, v := range h {
		vs := make([]string, len(v))
		copy(vs, v)
		cp[k] = vs
	}
	return cp
}

// validateMacro checks that a macro definition is valid.
func validateMacro(m *Macro) error {
	if m == nil {
		return fmt.Errorf("macro is nil")
	}
	if m.Name == "" {
		return fmt.Errorf("macro name is required")
	}
	if len(m.Steps) == 0 {
		return fmt.Errorf("macro must have at least one step")
	}
	if len(m.Steps) > MaxSteps {
		return fmt.Errorf("macro exceeds maximum step count (%d > %d)", len(m.Steps), MaxSteps)
	}

	// Validate step IDs are unique and non-empty.
	seenIDs := make(map[string]bool, len(m.Steps))
	for i := range m.Steps {
		step := &m.Steps[i]
		if step.ID == "" {
			return fmt.Errorf("step at index %d has no ID", i)
		}
		if seenIDs[step.ID] {
			return fmt.Errorf("duplicate step ID %q", step.ID)
		}
		seenIDs[step.ID] = true

		if step.FlowID == "" {
			return fmt.Errorf("step %q has no session_id", step.ID)
		}

		// Validate on_error value.
		if step.OnError != "" && step.OnError != OnErrorAbort && step.OnError != OnErrorSkip && step.OnError != OnErrorRetry {
			return fmt.Errorf("step %q has invalid on_error value %q", step.ID, step.OnError)
		}

		// Validate guard references only previously defined steps.
		if step.When != nil && step.When.Step != "" {
			if !seenIDs[step.When.Step] {
				return fmt.Errorf("step %q guard references unknown or forward step %q", step.ID, step.When.Step)
			}
		}

		// Validate extraction rules.
		for j := range step.Extract {
			rule := &step.Extract[j]
			if rule.Name == "" {
				return fmt.Errorf("step %q extraction rule at index %d has no name", step.ID, j)
			}
			if rule.Source == "" {
				return fmt.Errorf("step %q extraction rule %q has no source", step.ID, rule.Name)
			}
			if rule.From == "" {
				return fmt.Errorf("step %q extraction rule %q has no from", step.ID, rule.Name)
			}
		}
	}

	return nil
}
