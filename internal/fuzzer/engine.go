package fuzzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxResponseSize is the maximum response body size (1 MB) to prevent OOM.
const maxResponseSize = 1 << 20

// Config holds the configuration for a fuzz job.
type Config struct {
	// SessionID is the template session to fuzz.
	SessionID string `json:"session_id"`
	// AttackType is the fuzzing strategy: sequential or parallel.
	AttackType string `json:"attack_type"`
	// Positions defines where to inject payloads.
	Positions []Position `json:"positions"`
	// PayloadSets maps payload set names to their definitions.
	PayloadSets map[string]PayloadSet `json:"payload_sets"`
	// TimeoutMs is the per-request timeout in milliseconds (default: 10000).
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// Tag is an optional label for the fuzz job.
	Tag string `json:"tag,omitempty"`
}

// Validate checks that a Config is well-formed.
func (c *Config) Validate() error {
	if c.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if c.AttackType == "" {
		return fmt.Errorf("attack_type is required")
	}
	if c.AttackType != "sequential" && c.AttackType != "parallel" {
		return fmt.Errorf("invalid attack_type %q: must be sequential or parallel", c.AttackType)
	}
	if len(c.Positions) == 0 {
		return fmt.Errorf("at least one position is required")
	}

	posIDs := make(map[string]bool)
	for i, pos := range c.Positions {
		if err := pos.Validate(); err != nil {
			return fmt.Errorf("positions[%d]: %w", i, err)
		}
		if posIDs[pos.ID] {
			return fmt.Errorf("positions[%d]: duplicate position id %q", i, pos.ID)
		}
		posIDs[pos.ID] = true
	}

	for name, ps := range c.PayloadSets {
		if err := ps.Validate(); err != nil {
			return fmt.Errorf("payload_sets[%q]: %w", name, err)
		}
	}

	// Verify all referenced payload sets exist.
	for _, pos := range c.Positions {
		if pos.effectiveMode() == "remove" {
			continue
		}
		if _, ok := c.PayloadSets[pos.PayloadSet]; !ok {
			return fmt.Errorf("position %q references undefined payload set %q", pos.ID, pos.PayloadSet)
		}
	}

	return nil
}

// SessionFetcher retrieves session data needed by the fuzz engine.
type SessionFetcher interface {
	GetSession(ctx context.Context, id string) (*session.Session, error)
	GetMessages(ctx context.Context, sessionID string, opts session.MessageListOptions) ([]*session.Message, error)
}

// SessionRecorder persists new sessions and messages created during fuzzing.
type SessionRecorder interface {
	SaveSession(ctx context.Context, s *session.Session) error
	AppendMessage(ctx context.Context, msg *session.Message) error
}

// FuzzJobStore persists fuzz job and result data.
type FuzzJobStore interface {
	SaveFuzzJob(ctx context.Context, job *session.FuzzJob) error
	UpdateFuzzJob(ctx context.Context, job *session.FuzzJob) error
	SaveFuzzResult(ctx context.Context, result *session.FuzzResult) error
}

// HTTPDoer abstracts HTTP request execution.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Engine executes fuzz campaigns.
type Engine struct {
	sessionFetcher  SessionFetcher
	sessionRecorder SessionRecorder
	fuzzStore       FuzzJobStore
	httpDoer        HTTPDoer
	wordlistDir     string
}

// NewEngine creates a new fuzz engine.
func NewEngine(fetcher SessionFetcher, recorder SessionRecorder, fuzzStore FuzzJobStore, doer HTTPDoer, wordlistDir string) *Engine {
	return &Engine{
		sessionFetcher:  fetcher,
		sessionRecorder: recorder,
		fuzzStore:       fuzzStore,
		httpDoer:        doer,
		wordlistDir:     wordlistDir,
	}
}

// Result holds the output of a synchronous fuzz execution.
type Result struct {
	// FuzzID is the unique identifier of the fuzz job.
	FuzzID string `json:"fuzz_id"`
	// Status is the final job status.
	Status string `json:"status"`
	// Total is the total number of iterations.
	Total int `json:"total"`
	// Completed is the number of completed iterations.
	Completed int `json:"completed"`
	// Errors is the number of failed iterations.
	Errors int `json:"errors"`
	// Tag is the job tag (if set).
	Tag string `json:"tag,omitempty"`
}

// Run executes a fuzz job synchronously. It creates the job in the DB, iterates
// through all fuzz cases, sends requests, records results, and returns a summary.
func (e *Engine) Run(ctx context.Context, cfg Config) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid fuzz config: %w", err)
	}

	// Fetch the template session.
	sess, err := e.sessionFetcher.GetSession(ctx, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("get template session: %w", err)
	}

	sendMsgs, err := e.sessionFetcher.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, fmt.Errorf("template session %s has no send messages", cfg.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Build the base request data from the template session (deep clone).
	baseData := BuildRequestData(sendMsg)

	// Resolve payload sets.
	resolvedPayloads := make(map[string][]string)
	for name, ps := range cfg.PayloadSets {
		payloads, err := ps.Generate(e.wordlistDir)
		if err != nil {
			return nil, fmt.Errorf("generate payload set %q: %w", name, err)
		}
		resolvedPayloads[name] = payloads
	}

	// Create iterator.
	iter, err := NewIterator(cfg.AttackType, cfg.Positions, resolvedPayloads)
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}

	// Serialize config for DB storage.
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal fuzz config: %w", err)
	}

	// Create fuzz job in DB.
	now := time.Now()
	job := &session.FuzzJob{
		ID:        uuid.New().String(),
		SessionID: cfg.SessionID,
		Config:    string(configJSON),
		Status:    "running",
		Tag:       cfg.Tag,
		CreatedAt: now,
		Total:     iter.Total(),
	}
	if err := e.fuzzStore.SaveFuzzJob(ctx, job); err != nil {
		return nil, fmt.Errorf("save fuzz job: %w", err)
	}

	// Determine per-request timeout.
	timeout := 10 * time.Second
	if cfg.TimeoutMs > 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}

	// Execute fuzz iterations synchronously.
	completedCount := 0
	errorCount := 0

	for {
		fc, ok := iter.Next()
		if !ok {
			break
		}

		select {
		case <-ctx.Done():
			job.Status = "cancelled"
			job.CompletedCount = completedCount
			job.ErrorCount = errorCount
			_ = e.fuzzStore.UpdateFuzzJob(ctx, job)
			return nil, ctx.Err()
		default:
		}

		result := e.executeFuzzCase(ctx, baseData, cfg.Positions, fc, sess.Protocol, timeout, job.ID, nil)
		if err := e.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
			// Log and continue; don't abort the entire job for a DB write failure.
			errorCount++
			continue
		}

		if result.Error != "" {
			errorCount++
		} else {
			completedCount++
		}
	}

	// Update job status.
	completedAt := time.Now()
	job.Status = "completed"
	job.CompletedAt = &completedAt
	job.CompletedCount = completedCount
	job.ErrorCount = errorCount
	if err := e.fuzzStore.UpdateFuzzJob(ctx, job); err != nil {
		return nil, fmt.Errorf("update fuzz job: %w", err)
	}

	return &Result{
		FuzzID:    job.ID,
		Status:    job.Status,
		Total:     job.Total,
		Completed: completedCount,
		Errors:    errorCount,
		Tag:       cfg.Tag,
	}, nil
}

// executeFuzzCase applies positions to the template, sends the request,
// records the session, and returns a FuzzResult.
func (e *Engine) executeFuzzCase(
	ctx context.Context,
	baseData *RequestData,
	positions []Position,
	fc FuzzCase,
	protocol string,
	timeout time.Duration,
	fuzzID string,
	doerOverride HTTPDoer,
) *session.FuzzResult {
	result := &session.FuzzResult{
		FuzzID:   fuzzID,
		IndexNum: fc.Index,
		Payloads: session.PayloadsToJSON(fc.Payloads),
	}

	// Clone and apply positions.
	data := baseData.Clone()
	for _, pos := range positions {
		payload, ok := fc.Payloads[pos.ID]
		if !ok {
			continue
		}
		if err := ApplyPosition(data, pos, payload); err != nil {
			result.Error = fmt.Sprintf("apply position %s: %s", pos.ID, err.Error())
			// SessionID left empty for error results (no FK to sessions table).
			return result
		}
	}

	if data.URL == nil {
		result.Error = "template session has no URL"
		// SessionID left empty for error results (no FK to sessions table).
		return result
	}

	// Build HTTP request.
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body io.Reader
	if len(data.Body) > 0 {
		body = bytes.NewReader(data.Body)
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, data.Method, data.URL.String(), body)
	if err != nil {
		result.Error = fmt.Sprintf("create request: %s", err.Error())
		// SessionID left empty for error results (no FK to sessions table).
		return result
	}

	for key, values := range data.Headers {
		for i, v := range values {
			if i == 0 {
				httpReq.Header.Set(key, v)
			} else {
				httpReq.Header.Add(key, v)
			}
		}
	}

	// Send request and measure duration.
	doer := e.httpDoer
	if doerOverride != nil {
		doer = doerOverride
	}
	start := time.Now()
	resp, err := doer.Do(httpReq)
	if err != nil {
		duration := time.Since(start)
		result.Error = fmt.Sprintf("send request: %s", err.Error())
		result.DurationMs = int(duration.Milliseconds())
		// SessionID left empty for error results (no FK to sessions table).
		return result
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		duration := time.Since(start)
		result.Error = fmt.Sprintf("read response: %s", err.Error())
		result.DurationMs = int(duration.Milliseconds())
		// SessionID left empty for error results (no FK to sessions table).
		return result
	}
	duration := time.Since(start)

	// Build response headers snapshot.
	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	// Build recorded request headers.
	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	// Record the fuzz iteration as a new session.
	newSess := &session.Session{
		Protocol:    protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        map[string]string{"fuzz_id": fuzzID},
	}

	if err := e.sessionRecorder.SaveSession(ctx, newSess); err != nil {
		result.Error = fmt.Sprintf("save session: %s", err.Error())
		// SessionID left empty for error results (no FK to sessions table).
		return result
	}

	// Save send message.
	newSendMsg := &session.Message{
		SessionID: newSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    data.Method,
		URL:       data.URL,
		Headers:   recordedHeaders,
		Body:      data.Body,
	}
	if err := e.sessionRecorder.AppendMessage(ctx, newSendMsg); err != nil {
		result.Error = fmt.Sprintf("save send message: %s", err.Error())
		result.SessionID = newSess.ID
		return result
	}

	// Save receive message.
	newRecvMsg := &session.Message{
		SessionID:  newSess.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start.Add(duration),
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := e.sessionRecorder.AppendMessage(ctx, newRecvMsg); err != nil {
		result.Error = fmt.Sprintf("save receive message: %s", err.Error())
		result.SessionID = newSess.ID
		return result
	}

	result.SessionID = newSess.ID
	result.StatusCode = resp.StatusCode
	result.ResponseLength = len(respBody)
	result.DurationMs = int(duration.Milliseconds())

	return result
}

// executeFuzzCaseWithHooks wraps executeFuzzCase with pre_send and post_receive hook execution.
// If hooks is nil, it delegates directly to executeFuzzCase.
// Pre_send hooks can provide KV Store values that are expanded in the cloned request data.
// Post_receive hooks receive the response status code and body.
// The hookState.Mu is acquired around PreSend and PostSend calls to prevent data races
// when multiple worker goroutines share the same HookState (CWE-362).
func (e *Engine) executeFuzzCaseWithHooks(
	ctx context.Context,
	baseData *RequestData,
	positions []Position,
	fc FuzzCase,
	protocol string,
	timeout time.Duration,
	fuzzID string,
	hooks HookCallbacks,
	hookState *HookState,
	doerOverride HTTPDoer,
) *session.FuzzResult {
	if hooks == nil {
		return e.executeFuzzCase(ctx, baseData, positions, fc, protocol, timeout, fuzzID, doerOverride)
	}

	// Hold the lock for the full PreSend read-execute-writeback cycle (F-2).
	hookState.Mu.Lock()
	kvStore, err := hooks.PreSend(ctx, hookState)
	hookState.Mu.Unlock()
	if err != nil {
		return &session.FuzzResult{
			FuzzID:   fuzzID,
			IndexNum: fc.Index,
			Payloads: session.PayloadsToJSON(fc.Payloads),
			Error:    fmt.Sprintf("pre_send hook: %s", err.Error()),
		}
	}

	// If pre_send hook returned KV Store values, create a modified baseData
	// with template expansion applied.
	effectiveBaseData := baseData
	if len(kvStore) > 0 {
		effectiveBaseData = expandRequestData(baseData, kvStore)
	}

	// Execute the fuzz case with the (potentially modified) base data.
	// The lock is NOT held here to allow concurrent HTTP requests.
	result := e.executeFuzzCase(ctx, effectiveBaseData, positions, fc, protocol, timeout, fuzzID, doerOverride)

	// Execute post_receive hook if the request succeeded (has a response).
	// Pass the kvStore from PreSend so that post_receive hooks can access
	// values produced by pre_send (e.g., auth_session for logout).
	if result.Error == "" && result.StatusCode != 0 {
		// Retrieve the response body from the recorded session for the hook.
		respBody := e.fetchResponseBody(ctx, result.SessionID)
		hookState.Mu.Lock()
		postErr := hooks.PostSend(ctx, hookState, result.StatusCode, respBody, kvStore)
		hookState.Mu.Unlock()
		if postErr != nil {
			// Post-receive hook errors are recorded but don't fail the fuzz result.
			result.Error = fmt.Sprintf("post_receive hook: %s", postErr.Error())
		}
	}

	return result
}

// expandRequestData creates a clone of baseData with template expansion applied
// to the URL, headers, and body using the KV Store values.
// It obtains the raw URL string from the original baseData before cloning,
// because Clone() re-encodes the query string (escaping {{ }}).
func expandRequestData(baseData *RequestData, kvStore map[string]string) *RequestData {
	// Get the raw URL string before cloning (Clone re-encodes query params).
	var rawURL string
	if baseData.URL != nil {
		rawURL = baseData.URL.String()
	}

	data := baseData.Clone()

	// Expand URL using the raw string from the original.
	if rawURL != "" {
		expanded := expandSimpleTemplate(rawURL, kvStore)
		if expanded != rawURL {
			if u, err := url.Parse(expanded); err == nil {
				data.URL = u
			}
		}
	}

	// Expand headers.
	for key, values := range data.Headers {
		for i, v := range values {
			data.Headers[key][i] = expandSimpleTemplate(v, kvStore)
		}
	}

	// Expand body.
	if len(data.Body) > 0 {
		bodyStr := string(data.Body)
		expanded := expandSimpleTemplate(bodyStr, kvStore)
		if expanded != bodyStr {
			data.Body = []byte(expanded)
		}
	}

	return data
}

// expandSimpleTemplate replaces {{var}} placeholders in the input string
// with values from the KV Store. It ignores encoder pipes (those are handled
// by the macro.ExpandTemplate function in the MCP layer).
// This is a lightweight expansion for the fuzzer layer.
func expandSimpleTemplate(input string, kvStore map[string]string) string {
	result := input
	for k, v := range kvStore {
		placeholder := "{{" + k + "}}"
		result = strings.ReplaceAll(result, placeholder, v)
	}
	return result
}

// fetchResponseBody retrieves the response body from a recorded session.
// Returns nil if the session or response body cannot be retrieved.
func (e *Engine) fetchResponseBody(ctx context.Context, sessionID string) []byte {
	if sessionID == "" {
		return nil
	}
	msgs, err := e.sessionFetcher.GetMessages(ctx, sessionID, session.MessageListOptions{Direction: "receive"})
	if err != nil || len(msgs) == 0 {
		return nil
	}
	return msgs[0].Body
}

// BuildRequestData extracts mutable request data from a session's send message.
func BuildRequestData(sendMsg *session.Message) *RequestData {
	data := &RequestData{
		Method: sendMsg.Method,
		Body:   sendMsg.Body,
	}
	if sendMsg.URL != nil {
		u := *sendMsg.URL
		data.URL = &u
	}
	data.Headers = make(map[string][]string)
	for k, v := range sendMsg.Headers {
		data.Headers[k] = append([]string(nil), v...)
	}
	return data
}

// ResolvePayloads generates all payloads from the payload sets.
func ResolvePayloads(payloadSets map[string]PayloadSet, wordlistDir string) (map[string][]string, error) {
	resolved := make(map[string][]string)
	for name, ps := range payloadSets {
		payloads, err := ps.Generate(wordlistDir)
		if err != nil {
			return nil, fmt.Errorf("generate payload set %q: %w", name, err)
		}
		resolved[name] = payloads
	}
	return resolved, nil
}
