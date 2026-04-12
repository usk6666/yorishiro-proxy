//go:build legacy

package pipeline

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// HookPhase determines which plugin hooks a PluginStep dispatches.
type HookPhase int

const (
	// PhaseRecv dispatches on_receive_from_client (Send) or on_receive_from_server (Receive).
	PhaseRecv HookPhase = iota
	// PhaseSend dispatches on_before_send_to_server (Send) or on_before_send_to_client (Receive).
	PhaseSend
)

// String returns the string representation of a HookPhase.
func (p HookPhase) String() string {
	switch p {
	case PhaseRecv:
		return "PhaseRecv"
	case PhaseSend:
		return "PhaseSend"
	default:
		return "Unknown"
	}
}

// PluginStep dispatches Starlark plugin hooks as a Pipeline Step.
// Two instances are placed in the Pipeline: one with PhaseRecv (before Intercept)
// and one with PhaseSend (after Transform). The phase parameter controls which
// hook is dispatched based on the Exchange Direction.
//
// Pipeline.Without() excludes all PluginStep instances because they share the
// same concrete type.
type PluginStep struct {
	engine *plugin.Engine
	phase  HookPhase
	logger *slog.Logger
}

// NewPluginStep creates a PluginStep with the given engine, phase, and logger.
// If engine is nil, Process always returns Continue. If logger is nil, a
// default logger is used.
func NewPluginStep(engine *plugin.Engine, phase HookPhase, logger *slog.Logger) *PluginStep {
	if logger == nil {
		logger = slog.Default()
	}
	return &PluginStep{
		engine: engine,
		phase:  phase,
		logger: logger,
	}
}

// Process dispatches the appropriate plugin hook based on phase and direction,
// then applies the result to the Exchange.
func (s *PluginStep) Process(ctx context.Context, ex *exchange.Exchange) Result {
	if s.engine == nil {
		return Result{}
	}

	hook := s.resolveHook(ex.Direction)
	data := exchangeToMap(ex)

	result, err := s.engine.Dispatch(ctx, hook, data)
	if err != nil {
		s.logger.WarnContext(ctx, "plugin hook dispatch error",
			slog.String("hook", string(hook)),
			slog.String("phase", s.phase.String()),
			slog.String("error", err.Error()),
		)
		return Result{}
	}
	if result == nil {
		return Result{}
	}

	switch result.Action {
	case plugin.ActionDrop:
		return Result{Action: Drop}

	case plugin.ActionRespond:
		resp := buildResponseFromPlugin(result.ResponseData)
		return Result{Action: Respond, Response: resp}

	case plugin.ActionContinue:
		if result.Data != nil {
			applyPluginChanges(ex, result.Data)
		}
	}

	return Result{}
}

// resolveHook maps (phase, direction) to the correct plugin hook.
//
//	PhaseRecv + Send    -> on_receive_from_client
//	PhaseRecv + Receive -> on_receive_from_server
//	PhaseSend + Send    -> on_before_send_to_server
//	PhaseSend + Receive -> on_before_send_to_client
func (s *PluginStep) resolveHook(dir exchange.Direction) plugin.Hook {
	if s.phase == PhaseRecv {
		if dir == exchange.Send {
			return plugin.HookOnReceiveFromClient
		}
		return plugin.HookOnReceiveFromServer
	}
	// PhaseSend
	if dir == exchange.Send {
		return plugin.HookOnBeforeSendToServer
	}
	return plugin.HookOnBeforeSendToClient
}

// exchangeToMap converts an Exchange to the map[string]any format expected by
// the plugin engine. This is protocol-agnostic: it reads only Exchange fields,
// not protocol-specific types.
func exchangeToMap(ex *exchange.Exchange) map[string]any {
	m := map[string]any{
		"method":  ex.Method,
		"url":     urlString(ex.URL),
		"body":    ex.Body,
		"headers": headersToListOfPairs(ex.Headers),
	}

	if ex.Direction == exchange.Receive {
		m["status_code"] = ex.Status
	}

	if len(ex.Trailers) > 0 {
		m["trailers"] = headersToListOfPairs(ex.Trailers)
	}

	// Expose protocol as a string.
	m["protocol"] = string(ex.Protocol)

	// Expose selected Metadata keys.
	if ex.Metadata != nil {
		for _, key := range []string{"service", "method", "grpc_status", "ws_opcode"} {
			if v, ok := ex.Metadata[key]; ok {
				m[key] = v
			}
		}
	}

	return m
}

// urlString returns the string representation of a URL, or empty string if nil.
func urlString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// headersToListOfPairs converts []KeyValue to the ordered [[name, value], ...]
// format used by the plugin engine.
func headersToListOfPairs(kvs []exchange.KeyValue) []any {
	if kvs == nil {
		return []any{}
	}
	list := make([]any, 0, len(kvs))
	for _, kv := range kvs {
		list = append(list, map[string]any{
			"name":  kv.Name,
			"value": kv.Value,
		})
	}
	return list
}

// pairsToHeaders converts the ordered list format back to []KeyValue.
func pairsToHeaders(v any) []exchange.KeyValue {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	kvs := make([]exchange.KeyValue, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		value, _ := m["value"].(string)
		if name == "" {
			continue
		}
		kvs = append(kvs, exchange.KeyValue{Name: name, Value: value})
	}
	return kvs
}

// applyPluginChanges applies in-place modifications from a plugin result's
// data map back to the Exchange.
func applyPluginChanges(ex *exchange.Exchange, data map[string]any) {
	if v, ok := data["method"].(string); ok && v != "" {
		ex.Method = v
	}

	if v, ok := data["url"].(string); ok && v != "" {
		if u, err := url.Parse(v); err == nil {
			ex.URL = u
		}
	}

	if v, ok := data["status_code"]; ok {
		ex.Status = toInt(v, ex.Status)
	}

	if v, ok := data["headers"]; ok {
		if h := pairsToHeaders(v); h != nil {
			ex.Headers = h
		}
	}

	if v, ok := data["trailers"]; ok {
		if t := pairsToHeaders(v); t != nil {
			ex.Trailers = t
		}
	}

	if v, ok := data["body"]; ok {
		ex.Body = toBytes(v)
	}
}

// toInt converts a numeric value (int, int64, float64) to int.
// Returns fallback if the type is not recognized.
func toInt(v any, fallback int) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return fallback
	}
}

// toBytes converts a value to []byte. Supports []byte and string.
// Returns nil for unrecognized types.
func toBytes(v any) []byte {
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	default:
		return nil
	}
}

// buildResponseFromPlugin constructs a response Exchange from a RESPOND
// action's ResponseData map.
func buildResponseFromPlugin(responseData map[string]any) *exchange.Exchange {
	resp := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
	}
	if responseData == nil {
		return resp
	}

	if v, ok := responseData["status_code"]; ok {
		resp.Status = toInt(v, resp.Status)
	}

	if v, ok := responseData["headers"]; ok {
		if h := pairsToHeaders(v); h != nil {
			resp.Headers = h
		}
	}

	if v, ok := responseData["body"]; ok {
		resp.Body = toBytes(v)
	}

	return resp
}
