// Package macro implements the Macro engine for sequential step execution,
// KV Store parameter passing, value extraction, template expansion, and step guards.
package macro

import (
	"context"
	"net/http"
)

// Default limits and timeouts.
const (
	// DefaultMacroTimeoutMs is the default timeout for an entire macro execution (5 minutes).
	DefaultMacroTimeoutMs = 300_000
	// DefaultStepTimeoutMs is the default timeout for a single step execution (1 minute).
	DefaultStepTimeoutMs = 60_000
	// MaxSteps is the maximum number of steps allowed in a macro.
	MaxSteps = 50
	// DefaultRetryCount is the default number of retries for retry on_error policy.
	DefaultRetryCount = 3
	// DefaultRetryDelayMs is the default delay between retries in milliseconds.
	DefaultRetryDelayMs = 1000
)

// OnError specifies how a step error is handled.
type OnError string

const (
	// OnErrorAbort aborts the entire macro on step error.
	OnErrorAbort OnError = "abort"
	// OnErrorSkip skips the failed step and continues.
	OnErrorSkip OnError = "skip"
	// OnErrorRetry retries the step according to retry_count and retry_delay_ms.
	OnErrorRetry OnError = "retry"
)

// ExtractionSource specifies where to extract values from.
type ExtractionSource string

const (
	// ExtractionSourceHeader extracts from HTTP headers.
	ExtractionSourceHeader ExtractionSource = "header"
	// ExtractionSourceBody extracts from the body using regex.
	ExtractionSourceBody ExtractionSource = "body"
	// ExtractionSourceBodyJSON extracts from JSON body using JSON Path.
	ExtractionSourceBodyJSON ExtractionSource = "body_json"
	// ExtractionSourceStatus extracts the status code.
	ExtractionSourceStatus ExtractionSource = "status"
	// ExtractionSourceURL extracts from the URL.
	ExtractionSourceURL ExtractionSource = "url"
)

// ExtractionFrom specifies whether to extract from request or response.
type ExtractionFrom string

const (
	// ExtractionFromRequest extracts from the request.
	ExtractionFromRequest ExtractionFrom = "request"
	// ExtractionFromResponse extracts from the response.
	ExtractionFromResponse ExtractionFrom = "response"
)

// Macro defines a named request sequence with steps, initial variables, and timeout.
type Macro struct {
	// Name is the macro identifier.
	Name string
	// Description is a human-readable description.
	Description string
	// Steps is the ordered list of steps to execute.
	Steps []Step
	// InitialVars are pre-populated KV Store entries.
	InitialVars map[string]string
	// TimeoutMs is the overall macro timeout in milliseconds.
	// Zero means use DefaultMacroTimeoutMs.
	TimeoutMs int
}

// Step defines a single step in a macro execution sequence.
type Step struct {
	// ID is a unique identifier for this step within the macro.
	ID string
	// SessionID references the recorded session to use as a template.
	SessionID string
	// OverrideMethod overrides the HTTP method. Empty means use the original.
	OverrideMethod string
	// OverrideURL overrides the request URL. Empty means use the original.
	OverrideURL string
	// OverrideHeaders overrides specific headers (key-value pairs).
	OverrideHeaders map[string]string
	// OverrideBody overrides the request body. Nil means use the original.
	OverrideBody *string
	// OnError specifies error handling behavior. Empty defaults to "abort".
	OnError OnError
	// RetryCount is the number of retries when OnError is "retry".
	// Zero means use DefaultRetryCount.
	RetryCount int
	// RetryDelayMs is the delay between retries in milliseconds.
	// Zero means use DefaultRetryDelayMs.
	RetryDelayMs int
	// TimeoutMs is the step-level timeout in milliseconds.
	// Zero means use DefaultStepTimeoutMs.
	TimeoutMs int
	// Extract defines value extraction rules applied after the step executes.
	Extract []ExtractionRule
	// When defines a guard condition. If set, the step only executes when the condition is met.
	When *Guard
}

// ExtractionRule defines how to extract a value from a request or response.
type ExtractionRule struct {
	// Name is the KV Store key to store the extracted value.
	Name string
	// From specifies whether to extract from request or response.
	From ExtractionFrom
	// Source specifies the extraction source type.
	Source ExtractionSource
	// HeaderName is the header name (used when Source is "header").
	HeaderName string
	// Regex is the regular expression pattern (used with header, body, url sources).
	Regex string
	// Group is the capture group number (0 = full match).
	Group int
	// JSONPath is the JSON Path expression (used when Source is "body_json").
	JSONPath string
	// Default is the fallback value if extraction fails.
	Default string
	// Required causes the macro to fail if extraction fails.
	Required bool
}

// Guard defines a condition that must be met for a step to execute.
type Guard struct {
	// Step is the ID of a previously executed step to evaluate against.
	Step string
	// StatusCode matches an exact status code.
	StatusCode *int
	// StatusCodeRange matches a status code range [min, max] inclusive.
	StatusCodeRange [2]int
	// HeaderMatch maps header names to regex patterns (AND evaluation).
	HeaderMatch map[string]string
	// BodyMatch is a regex pattern to match against the response body.
	BodyMatch string
	// ExtractedVar checks if a variable exists in the KV Store.
	ExtractedVar string
	// Negate inverts the entire condition.
	Negate bool
}

// StepResult holds the outcome of a single step execution.
type StepResult struct {
	// ID is the step identifier.
	ID string
	// Status indicates the step outcome: "completed", "skipped", "error".
	Status string
	// StatusCode is the HTTP response status code (zero if not available).
	StatusCode int
	// DurationMs is the step execution time in milliseconds.
	DurationMs int64
	// Error holds the error message if the step failed.
	Error string
}

// Result holds the outcome of a complete macro execution.
type Result struct {
	// MacroName is the name of the executed macro.
	MacroName string
	// Status indicates the overall outcome: "completed", "error", "timeout".
	Status string
	// StepsExecuted is the number of steps that were actually executed (not skipped).
	StepsExecuted int
	// KVStore is the final state of the KV Store.
	KVStore map[string]string
	// StepResults holds per-step execution results.
	StepResults []StepResult
	// Error holds the error message if the macro failed.
	Error string
}

// SendRequest represents an outgoing HTTP request for a macro step.
type SendRequest struct {
	// Method is the HTTP method.
	Method string
	// URL is the full request URL.
	URL string
	// Headers are the HTTP headers.
	Headers map[string][]string
	// Body is the request body.
	Body []byte
}

// SendResponse represents the response from sending a macro step request.
type SendResponse struct {
	// StatusCode is the HTTP response status code.
	StatusCode int
	// Headers are the response HTTP headers.
	Headers http.Header
	// Body is the response body.
	Body []byte
	// URL is the response URL (may differ from request URL after redirects).
	URL string
}

// SendFunc is the function signature for sending HTTP requests in macro steps.
// It receives a context and a request, and returns a response or error.
// This allows dependency injection for testing and integration with different
// HTTP transport mechanisms.
type SendFunc func(ctx context.Context, req *SendRequest) (*SendResponse, error)

// SessionFetcher retrieves session data needed by macro steps to build requests.
type SessionFetcher interface {
	// GetSessionRequest returns the send message data for a recorded session.
	GetSessionRequest(ctx context.Context, sessionID string) (*SendRequest, error)
}
