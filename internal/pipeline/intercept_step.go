//go:build legacy

package pipeline

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/url"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// InterceptStep holds intercepted Exchanges in a Queue until an AI agent
// decides the action (release, modify, or drop). It is a blocking Step:
// Pipeline execution pauses until the agent responds or a timeout fires.
//
// When engine or queue is nil, the Step is a no-op (returns Continue).
type InterceptStep struct {
	engine *intercept.Engine
	queue  *intercept.Queue
}

// NewInterceptStep creates an InterceptStep with the given Engine and Queue.
// If either is nil, Process always returns Continue.
func NewInterceptStep(engine *intercept.Engine, queue *intercept.Queue) *InterceptStep {
	return &InterceptStep{engine: engine, queue: queue}
}

// Process evaluates intercept rules against the Exchange and, on a match,
// enqueues it into the Queue and blocks until an action is received or the
// timeout expires. The action is applied in-place on the Exchange.
func (s *InterceptStep) Process(ctx context.Context, ex *exchange.Exchange) Result {
	if s.engine == nil || s.queue == nil {
		return Result{}
	}

	switch ex.Direction {
	case exchange.Send:
		matched := s.engine.MatchRequestRules(ex.Method, ex.URL, ex.Headers)
		if len(matched) == 0 {
			return Result{}
		}
		return s.waitForAction(ctx, ex, matched)
	case exchange.Receive:
		matched := s.engine.MatchResponseRules(ex.Status, ex.Headers)
		if len(matched) == 0 {
			return Result{}
		}
		return s.waitForAction(ctx, ex, matched)
	}
	return Result{}
}

// waitForAction enqueues the Exchange into the intercept queue and blocks
// until the AI agent responds or the configured timeout fires.
func (s *InterceptStep) waitForAction(ctx context.Context, ex *exchange.Exchange, matchedRules []string) Result {
	var id string
	var actionCh <-chan intercept.InterceptAction

	var opts []intercept.EnqueueOpts
	if len(ex.RawBytes) > 0 {
		opts = append(opts, intercept.EnqueueOpts{RawBytes: ex.RawBytes})
	}

	switch ex.Direction {
	case exchange.Send:
		id, actionCh = s.queue.Enqueue(ex.Method, ex.URL, ex.Headers, ex.Body, matchedRules, opts...)
	case exchange.Receive:
		id, actionCh = s.queue.EnqueueResponse(ex.Method, ex.URL, ex.Status, ex.Headers, ex.Body, matchedRules, opts...)
	}
	defer s.queue.Remove(id)

	slog.Debug("exchange held in intercept queue",
		slog.String("intercept_id", id),
		slog.String("direction", ex.Direction.String()),
		slog.Any("matched_rules", matchedRules),
	)

	timeout := s.queue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var action intercept.InterceptAction
	select {
	case action = <-actionCh:
	case <-timeoutCtx.Done():
		behavior := s.queue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			slog.Debug("intercepted exchange cancelled", slog.String("intercept_id", id))
			return Result{Action: Drop}
		}
		slog.Debug("intercepted exchange timed out",
			slog.String("intercept_id", id),
			slog.String("behavior", string(behavior)),
		)
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return Result{Action: Drop}
		default:
			// auto_release: continue pipeline with original Exchange.
			return Result{}
		}
	}

	return s.applyAction(ex, action)
}

// applyAction applies the InterceptAction to the Exchange in-place.
func (s *InterceptStep) applyAction(ex *exchange.Exchange, action intercept.InterceptAction) Result {
	switch action.Type {
	case intercept.ActionDrop:
		return Result{Action: Drop}

	case intercept.ActionRelease:
		if action.IsRawMode() {
			// Raw mode release: use original RawBytes (already on the Exchange).
			return Result{}
		}
		return Result{}

	case intercept.ActionModifyAndForward:
		if action.IsRawMode() {
			// Raw mode: replace RawBytes on the Exchange.
			ex.RawBytes = action.RawOverride
			return Result{}
		}
		s.applyStructuredModifications(ex, action)
		return Result{}
	}

	return Result{}
}

// applyStructuredModifications applies structured (L7) modifications from the
// InterceptAction to the Exchange in-place.
func (s *InterceptStep) applyStructuredModifications(ex *exchange.Exchange, action intercept.InterceptAction) {
	switch ex.Direction {
	case exchange.Send:
		s.applyRequestModifications(ex, action)
	case exchange.Receive:
		s.applyResponseModifications(ex, action)
	}
}

// applyRequestModifications applies request-level structured modifications.
func (s *InterceptStep) applyRequestModifications(ex *exchange.Exchange, action intercept.InterceptAction) {
	if action.OverrideMethod != "" {
		ex.Method = action.OverrideMethod
	}

	if action.OverrideURL != "" {
		// Best-effort URL parse; ignore errors to match existing behavior.
		if u, err := parseURL(action.OverrideURL); err == nil {
			ex.URL = u
		}
	}

	ex.Headers = applyHeaderModifications(ex.Headers, action.OverrideHeaders, action.AddHeaders, action.RemoveHeaders)

	if action.OverrideBody != nil {
		ex.Body = []byte(*action.OverrideBody)
	}
	if action.OverrideBodyBase64 != nil {
		if decoded, err := decodeBase64Body(*action.OverrideBodyBase64); err == nil {
			ex.Body = decoded
		}
	}
}

// applyResponseModifications applies response-level structured modifications.
func (s *InterceptStep) applyResponseModifications(ex *exchange.Exchange, action intercept.InterceptAction) {
	if action.OverrideStatus > 0 {
		ex.Status = action.OverrideStatus
	}

	ex.Headers = applyHeaderModifications(ex.Headers, action.OverrideResponseHeaders, action.AddResponseHeaders, action.RemoveResponseHeaders)

	if action.OverrideResponseBody != nil {
		ex.Body = []byte(*action.OverrideResponseBody)
	}
}

// applyHeaderModifications applies override, add, and remove header modifications
// to a []exchange.KeyValue slice and returns the result.
func applyHeaderModifications(headers []exchange.KeyValue, overrides map[string]string, adds map[string]string, removes []string) []exchange.KeyValue {
	// Apply overrides: replace value of first matching header (case-insensitive).
	for name, value := range overrides {
		found := false
		for i, h := range headers {
			if equalFoldASCII(h.Name, name) {
				headers[i].Value = value
				found = true
				break
			}
		}
		if !found {
			headers = append(headers, exchange.KeyValue{Name: name, Value: value})
		}
	}

	// Apply adds: append new headers.
	for name, value := range adds {
		headers = append(headers, exchange.KeyValue{Name: name, Value: value})
	}

	// Apply removes: delete all matching headers (case-insensitive).
	for _, name := range removes {
		n := 0
		for _, h := range headers {
			if !equalFoldASCII(h.Name, name) {
				headers[n] = h
				n++
			}
		}
		headers = headers[:n]
	}

	return headers
}

// equalFoldASCII performs ASCII case-insensitive string comparison.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// parseURL parses a URL string.
func parseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}

// decodeBase64Body decodes a base64-encoded string.
func decodeBase64Body(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
