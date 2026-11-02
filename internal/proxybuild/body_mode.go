package proxybuild

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// HTTPBodyModeEngines are the live engines an HTTP body-mode predicate
// consults (USK-1409). Any field may be nil. The predicate reads them on
// every call, so a rule added or removed at runtime applies from the next
// message on.
type HTTPBodyModeEngines struct {
	Safety    *httprules.SafetyEngine
	Intercept *httprules.InterceptEngine
	Transform *httprules.TransformEngine
	Plugin    *pluginv2.Engine
}

// NewHTTPBodyModeFunc returns the body-mode predicate for HTTP messages
// (RFC-001 §3.2.1 "HTTP body streaming"). A body is streamed — forwarded
// while it is read — unless something in the Pipeline needs it whole:
//
//   - layer.Buffer for a message with no body by HTTP semantics (1xx / 101,
//     204, 304, a response to HEAD or CONNECT) and for gRPC-Web, whose Layer
//     reassembles the whole body;
//   - layer.Buffer when an Intercept rule matches the head (a hold needs the
//     whole message), when a Transform replace_body rule matches it, and —
//     for requests — when the Safety Input Filter has any body-target rule
//     (RFC-001 §3.7: streaming never exempts traffic from the Input Filter);
//   - layer.BufferUpTo(plugin_max_body_size) when a plugin registered an
//     http on_request / on_response hook (pre or post pipeline) for the
//     message's direction: a body within the plugin cap reaches the hook
//     whole as before; a larger one was never handed to the hook, so it is
//     streamed;
//   - layer.Stream otherwise.
//
// The matchers are the engines' own exported methods; nothing is copied.
func NewHTTPBodyModeFunc(e HTTPBodyModeEngines) layer.BodyModeFunc {
	return func(env *envelope.Envelope, msg *envelope.HTTPMessage) layer.BodyMode {
		if env == nil || msg == nil {
			return layer.Buffer()
		}
		dir := env.Direction
		if dir == envelope.Receive && bodylessResponse(msg.Status, env.Context.RequestMethod) {
			return layer.Buffer()
		}
		if isGRPCWebContentType(headerValue(msg.Headers, "Content-Type")) {
			return layer.Buffer()
		}
		if e.needsWholeBody(env, msg, dir) {
			return layer.Buffer()
		}
		if e.Plugin != nil && hasHTTPHook(e.Plugin, dir) {
			return layer.BufferUpTo(e.Plugin.MaxBodySize())
		}
		return layer.Stream()
	}
}

// needsWholeBody reports whether a rule engine needs msg's whole body.
func (e HTTPBodyModeEngines) needsWholeBody(env *envelope.Envelope, msg *envelope.HTTPMessage, dir envelope.Direction) bool {
	switch dir {
	case envelope.Send:
		if e.Safety != nil && e.Safety.HasBodyTarget() {
			return true
		}
		if e.Intercept != nil && len(e.Intercept.MatchRequest(env, msg)) > 0 {
			return true
		}
	case envelope.Receive:
		if e.Intercept != nil && len(e.Intercept.MatchResponse(env, msg)) > 0 {
			return true
		}
	}
	return e.Transform != nil && e.Transform.MatchesReplaceBody(env, msg, dir)
}

// hasHTTPHook reports whether eng has an http hook for dir in either phase.
func hasHTTPHook(eng *pluginv2.Engine, dir envelope.Direction) bool {
	event := pluginv2.EventOnResponse
	if dir == envelope.Send {
		event = pluginv2.EventOnRequest
	}
	reg := eng.Registry()
	if reg == nil {
		return false
	}
	return len(reg.Lookup(pluginv2.ProtoHTTP, event, pluginv2.PhasePrePipeline)) > 0 ||
		len(reg.Lookup(pluginv2.ProtoHTTP, event, pluginv2.PhasePostPipeline)) > 0
}

// bodylessResponse reports whether a response with status to a request
// with method carries no body by HTTP semantics (RFC 9110 §6.4.1).
func bodylessResponse(status int, method string) bool {
	if status < 200 || status == 204 || status == 304 {
		return true
	}
	switch strings.ToUpper(method) {
	case "HEAD":
		return true
	case "CONNECT":
		return status < 300
	}
	return false
}

// isGRPCWebContentType reports whether ct names a gRPC-Web media type
// (application/grpc-web, application/grpc-web+proto, application/grpc-web-text…).
func isGRPCWebContentType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/grpc-web")
}

// headerValue returns the first value of name (case-insensitive).
func headerValue(headers []envelope.KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
