// Package job defines the execution unit for resend/fuzz operations.
//
// Job is NOT a Pipeline Step — it is a separate execution layer that wraps
// the Pipeline + Session loop with Macro hook support (pre-send, post-receive).
//
// Normal proxy traffic flows through: Connector → RunSession(client Codec, dial, pipeline)
// Resend/fuzz flows through:          Job(ExchangeSource, dial, pipeline, macro hooks).Run()
//
// Macro hooks are Job-level concerns because:
//   - Macros are specified per Job (not applied to normal proxy traffic)
//   - RunInterval (once, every_n, on_error, on_status) requires Job-level state
//   - Post-receive runs after Pipeline completion
//   - Macros are inherently stateful (KV Store)
//
// Macro internal requests use Pipeline.Without(InterceptStep). All other Steps
// (Scope, Safety, Transform, Record) still apply to Macro traffic.
package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// ExchangeSource generates Exchanges for a Job to send.
// The signature matches Codec.Next(). Return io.EOF to signal source exhaustion.
type ExchangeSource interface {
	Next(ctx context.Context) (*exchange.Exchange, error)
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
	// RunInterval controls when the hook fires.
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
}

// shouldRunPreSend evaluates whether the pre-send hook should fire based on
// the RunInterval and current state. It updates state as a side effect for
// Once (sets PreSendExecuted).
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

// Job is the execution unit for resend/fuzz operations.
//
// It reads Exchanges from Source, optionally runs pre-send and post-receive
// macro hooks, and forwards each Exchange through the Pipeline via dial.
type Job struct {
	// Source generates Exchanges to send.
	Source ExchangeSource
	// PreSend is the pre-send macro hook configuration. nil means no hook.
	PreSend *HookConfig
	// PostReceive is the post-receive macro hook configuration. nil means no hook.
	PostReceive *HookConfig
	// Dial creates an upstream connection for each Exchange.
	Dial session.DialFunc
	// Pipeline is the main processing pipeline.
	Pipeline *pipeline.Pipeline
	// MacroPipeline is Pipeline.Without(InterceptStep) for macro internal requests.
	MacroPipeline *pipeline.Pipeline
	// KVStore holds macro key-value pairs shared across hooks.
	KVStore map[string]string
	// HookState tracks hook execution state across iterations.
	HookState HookState
}

// Run executes the Job.
//
// It loops over Source.Next(), runs pre-send hook (if configured), processes
// the Exchange through the Pipeline, and runs post-receive hook (if configured).
// Returns nil when Source returns io.EOF. Returns an error on context
// cancellation or unrecoverable failure.
//
// Macro invocation and template expansion are not yet implemented (deferred to M42).
func (j *Job) Run(ctx context.Context) error {
	if j.KVStore == nil {
		j.KVStore = make(map[string]string)
	}

	for {
		ex, err := j.Source.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("source.Next: %w", err)
		}

		// TODO(M42): Execute pre-send macro hook if configured.
		// if j.PreSend != nil && j.HookState.shouldRunPreSend(j.PreSend) {
		//     kvStore, err := runMacro(ctx, j.MacroPipeline, j.PreSend, j.KVStore)
		//     if err != nil { ... }
		//     mergeKVStore(j.KVStore, kvStore)
		// }

		// TODO(M42): Apply template expansion (§variable§) to Exchange using KVStore.

		// Run the Exchange through the Pipeline.
		ex, action, resp := j.Pipeline.Run(ctx, ex)
		switch action {
		case pipeline.Drop:
			j.HookState.RequestCount++
			continue
		case pipeline.Respond:
			// In Job context, Respond means use the response directly
			// without dialing upstream. Record the response status.
			if resp != nil {
				j.HookState.LastStatusCode = resp.Status
				j.HookState.LastError = resp.Status >= 400
			}
			j.HookState.RequestCount++
			continue
		}

		// Dial upstream and send the Exchange.
		upstream, err := j.Dial(ctx, ex)
		if err != nil {
			j.HookState.LastError = true
			j.HookState.RequestCount++
			return fmt.Errorf("dial: %w", err)
		}

		if err := upstream.Send(ctx, ex); err != nil {
			upstream.Close()
			j.HookState.LastError = true
			j.HookState.RequestCount++
			return fmt.Errorf("upstream.Send: %w", err)
		}

		// Read the response from upstream.
		respEx, err := upstream.Next(ctx)
		upstream.Close()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Upstream closed without response — record as error.
				j.HookState.LastError = true
				j.HookState.RequestCount++
				continue
			}
			j.HookState.LastError = true
			j.HookState.RequestCount++
			return fmt.Errorf("upstream.Next: %w", err)
		}

		// Run the response through the Pipeline.
		respEx, _, _ = j.Pipeline.Run(ctx, respEx)

		// Update hook state with the response.
		j.HookState.LastStatusCode = respEx.Status
		j.HookState.LastError = respEx.Status >= 400

		// TODO(M42): Execute post-receive macro hook if configured.
		// if j.PostReceive != nil && j.HookState.shouldRunPostReceive(j.PostReceive, respEx.Status, respEx.Body) {
		//     err := runPostReceiveMacro(ctx, j.MacroPipeline, j.PostReceive, j.KVStore, respEx)
		//     if err != nil { ... }
		// }

		j.HookState.RequestCount++
	}
}
