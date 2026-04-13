package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// EnvelopeSource generates Envelopes for a Job to send.
// Return io.EOF to signal source exhaustion.
type EnvelopeSource interface {
	Next(ctx context.Context) (*envelope.Envelope, error)
}

// RunInterval controls when a macro hook fires.
type RunInterval string

const (
	// Always fires the hook on every request.
	Always RunInterval = "always"
	// Once fires the hook only on the first request.
	Once RunInterval = "once"
	// EveryN fires the hook every N requests.
	EveryN RunInterval = "every_n"
	// OnError fires the hook when the previous request had an error or status >= 400.
	OnError RunInterval = "on_error"
	// OnStatus fires the hook when the response matches specific status codes.
	OnStatus RunInterval = "on_status"
	// OnMatch fires the hook when the response body matches a regex pattern.
	OnMatch RunInterval = "on_match"
)

// HookConfig is the configuration for a pre-send or post-receive macro hook.
type HookConfig struct {
	// Macro is the name of the stored macro to execute.
	Macro string
	// Vars are runtime variable overrides for the macro.
	Vars map[string]string
	// RunInterval controls when the hook fires. Empty defaults to Always.
	RunInterval RunInterval
	// N is the interval count for EveryN.
	N int
	// StatusCodes is the list of target status codes for OnStatus.
	StatusCodes []int
	// MatchPattern is the regex pattern for OnMatch.
	MatchPattern string
	// CompiledPattern is the pre-compiled regexp for MatchPattern.
	// Set during validation to avoid recompilation on every invocation.
	CompiledPattern *regexp.Regexp
	// PassResponse passes the response status/body to the post-receive macro.
	PassResponse bool
}

// HookState tracks the execution state of macro hooks across iterations.
type HookState struct {
	// PreSendExecuted tracks whether the pre-send hook has been executed (for Once).
	PreSendExecuted bool
	// RequestCount tracks the total number of requests processed (for EveryN).
	RequestCount int
	// LastStatusCode is the status code from the previous response (for OnError/OnStatus).
	LastStatusCode int
	// LastError indicates whether the previous request had an error (for OnError).
	LastError bool
	// LastResponseBody holds the response body from the last request (for OnMatch).
	LastResponseBody []byte
}

// shouldRunPreSend evaluates whether the pre-send hook should fire based on
// the RunInterval and current state.
func (s *HookState) shouldRunPreSend(h *HookConfig) bool {
	interval := h.RunInterval
	if interval == "" {
		interval = Always
	}

	switch interval {
	case Always:
		return true
	case Once:
		if s.PreSendExecuted {
			return false
		}
		s.PreSendExecuted = true
		return true
	case EveryN:
		if h.N <= 0 {
			return false
		}
		return s.RequestCount%h.N == 0
	case OnError:
		// Always run on the first request (no previous error to check).
		if s.RequestCount == 0 {
			return true
		}
		return s.LastError || s.LastStatusCode >= 400
	default:
		return false
	}
}

// shouldRunPostReceive evaluates whether the post-receive hook should fire
// based on the RunInterval, response status code, and response body.
func (s *HookState) shouldRunPostReceive(h *HookConfig, statusCode int, responseBody []byte) bool {
	interval := h.RunInterval
	if interval == "" {
		interval = Always
	}

	switch interval {
	case Always:
		return true
	case OnStatus:
		for _, code := range h.StatusCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	case OnMatch:
		if h.CompiledPattern == nil {
			return false
		}
		return h.CompiledPattern.Match(responseBody)
	case OnError:
		return statusCode >= 400
	default:
		return false
	}
}

// RunHookFunc is the function signature for executing a macro hook.
// It receives the hook configuration, the shared KV store, and optional
// response data (status code and body for post-receive hooks).
// It returns the updated KV store or an error.
type RunHookFunc func(ctx context.Context, hookCfg *HookConfig, kvStore map[string]string) (map[string]string, error)

// Job is the execution unit for resend/fuzz operations.
//
// It reads Envelopes from Source, optionally runs pre-send and post-receive
// macro hooks, and forwards each Envelope through the Pipeline via Dial.
type Job struct {
	// Source generates Envelopes to send.
	Source EnvelopeSource

	// PreSend is the pre-send macro hook configuration. nil means no hook.
	PreSend *HookConfig

	// PostReceive is the post-receive macro hook configuration. nil means no hook.
	PostReceive *HookConfig

	// RunPreSendHook executes the pre-send macro. nil means hooks are disabled.
	RunPreSendHook RunHookFunc

	// RunPostReceiveHook executes the post-receive macro. nil means hooks are disabled.
	RunPostReceiveHook RunHookFunc

	// Dial creates an upstream Channel for sending the Envelope.
	// Called once per iteration; the returned Channel is closed after
	// the response is received.
	Dial session.DialFunc

	// Pipeline is the main processing pipeline.
	Pipeline *pipeline.Pipeline

	// KVStore holds macro key-value pairs shared across hooks.
	KVStore map[string]string

	// HookState tracks hook execution state across iterations.
	HookState HookState
}

// Run executes the Job.
//
// It loops over Source.Next(), runs hooks if configured, processes Envelopes
// through the Pipeline, and dials upstream for each request. Returns nil when
// Source returns io.EOF. Returns an error on context cancellation or
// unrecoverable failure.
func (j *Job) Run(ctx context.Context) error {
	if j.KVStore == nil {
		j.KVStore = make(map[string]string)
	}

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("job: context cancelled: %w", err)
		}

		env, err := j.Source.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("job: source.Next: %w", err)
		}

		if err := j.runPreSendHook(ctx); err != nil {
			return err
		}

		// Run the send Envelope through the Pipeline.
		env, action, _ := j.Pipeline.Run(ctx, env)
		if action == pipeline.Drop || action == pipeline.Respond {
			j.updateState(0, false, nil)
			continue
		}

		respEnv, err := j.dialAndExchange(ctx, env)
		if err != nil {
			return err
		}
		if respEnv == nil {
			// Upstream closed without response (EOF) — already updated state.
			continue
		}

		// Run the response through the Pipeline.
		respEnv, _, _ = j.Pipeline.Run(ctx, respEnv)

		statusCode, body := extractResponseInfo(respEnv)
		if err := j.runPostReceiveHook(ctx, statusCode, body); err != nil {
			return err
		}

		j.updateState(statusCode, statusCode >= 400, body)
	}
}

// runPreSendHook executes the pre-send macro hook if configured and the
// RunInterval condition is met.
func (j *Job) runPreSendHook(ctx context.Context) error {
	if j.PreSend == nil || j.RunPreSendHook == nil || !j.HookState.shouldRunPreSend(j.PreSend) {
		return nil
	}
	kvResult, err := j.RunPreSendHook(ctx, j.PreSend, j.KVStore)
	if err != nil {
		return fmt.Errorf("job: pre-send hook: %w", err)
	}
	mergeKVStore(j.KVStore, kvResult)
	return nil
}

// runPostReceiveHook executes the post-receive macro hook if configured and
// the RunInterval condition is met for the given response.
func (j *Job) runPostReceiveHook(ctx context.Context, statusCode int, body []byte) error {
	if j.PostReceive == nil || j.RunPostReceiveHook == nil {
		return nil
	}
	if !j.HookState.shouldRunPostReceive(j.PostReceive, statusCode, body) {
		return nil
	}
	kvResult, err := j.RunPostReceiveHook(ctx, j.PostReceive, j.KVStore)
	if err != nil {
		return fmt.Errorf("job: post-receive hook: %w", err)
	}
	mergeKVStore(j.KVStore, kvResult)
	return nil
}

// dialAndExchange dials upstream, sends the Envelope, and reads the response.
// Returns (nil, nil) when upstream closes without sending a response (EOF).
func (j *Job) dialAndExchange(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
	upstream, err := j.Dial(ctx, env)
	if err != nil {
		j.updateState(0, true, nil)
		return nil, fmt.Errorf("job: dial: %w", err)
	}

	if err := upstream.Send(ctx, env); err != nil {
		upstream.Close()
		j.updateState(0, true, nil)
		return nil, fmt.Errorf("job: upstream.Send: %w", err)
	}

	respEnv, err := upstream.Next(ctx)
	upstream.Close()

	if err != nil {
		if errors.Is(err, io.EOF) {
			j.updateState(0, true, nil)
			return nil, nil
		}
		j.updateState(0, true, nil)
		return nil, fmt.Errorf("job: upstream.Next: %w", err)
	}

	return respEnv, nil
}

// updateState updates the HookState after processing a request-response pair.
func (j *Job) updateState(statusCode int, isError bool, body []byte) {
	j.HookState.LastStatusCode = statusCode
	j.HookState.LastError = isError
	j.HookState.LastResponseBody = body
	j.HookState.RequestCount++
}

// extractResponseInfo extracts the HTTP status code and body from a response
// Envelope. For RawMessage, status code is 0 (no HTTP semantics).
func extractResponseInfo(env *envelope.Envelope) (int, []byte) {
	if env == nil {
		return 0, nil
	}
	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		return m.Status, m.Body
	case *envelope.RawMessage:
		return 0, m.Bytes
	default:
		return 0, nil
	}
}

// mergeKVStore merges src into dst. Keys in src overwrite existing keys in dst.
func mergeKVStore(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}

// channelSource wraps a single layer.Channel as an EnvelopeSource.
// Useful for testing.
type channelSource struct {
	ch layer.Channel
}

// ChannelSource creates an EnvelopeSource that reads from a Channel.
func ChannelSource(ch layer.Channel) EnvelopeSource {
	return &channelSource{ch: ch}
}

// Next reads the next Envelope from the wrapped Channel.
func (s *channelSource) Next(ctx context.Context) (*envelope.Envelope, error) {
	return s.ch.Next(ctx)
}
