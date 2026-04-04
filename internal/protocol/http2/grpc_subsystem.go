package http2

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// decodeGRPCPayload decodes a gRPC frame payload to JSON for subsystem processing.
// It handles decompression if the frame is compressed. Returns the JSON string and
// the decompressed payload, or an error if decoding fails.
func decodeGRPCPayload(payload []byte, compressed bool, encoding string) (jsonStr string, decompressed []byte, err error) {
	data := payload
	if compressed {
		data, err = protobuf.Decompress(payload, encoding)
		if err != nil {
			return "", nil, fmt.Errorf("decompress grpc payload: %w", err)
		}
	}
	jsonStr, err = protobuf.Decode(data)
	if err != nil {
		return "", nil, fmt.Errorf("protobuf decode: %w", err)
	}
	return jsonStr, data, nil
}

// encodeGRPCPayload encodes a JSON string back to protobuf and optionally
// compresses it. Returns the re-encoded payload bytes.
func encodeGRPCPayload(jsonStr string, compressed bool, encoding string) ([]byte, error) {
	data, err := protobuf.Encode(jsonStr)
	if err != nil {
		return nil, fmt.Errorf("protobuf encode: %w", err)
	}
	if compressed {
		data, err = protobuf.Compress(data, encoding)
		if err != nil {
			return nil, fmt.Errorf("compress grpc payload: %w", err)
		}
	}
	return data, nil
}

// rebuildGRPCFrame constructs a gRPC frame (5-byte header + payload) from
// a compressed flag and payload data.
func rebuildGRPCFrame(compressed bool, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	if compressed {
		buf[0] = 1
	}
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// applyGRPCSafetyFilter checks a decoded gRPC JSON body against the safety
// filter engine. Returns an InputViolation if a rule matched, or nil.
func applyGRPCSafetyFilter(engine *safety.Engine, jsonBody string, rawURL string, headers []hpack.HeaderField) *safety.InputViolation {
	if engine == nil {
		return nil
	}
	return engine.CheckInput([]byte(jsonBody), rawURL, hpackToRawHeaders(headers))
}

// scMethod returns the request method from h2req.
func scMethod(sc *streamContext) string {
	if sc.h2req != nil {
		return sc.h2req.Method
	}
	return ""
}

// scHeaders returns the hpack headers from h2req.
func scHeaders(sc *streamContext) []hpack.HeaderField {
	if sc.h2req != nil {
		return sc.h2req.AllHeaders
	}
	return nil
}

// scHeadersPluginMap returns headers in plugin map format from h2req.
func scHeadersPluginMap(sc *streamContext) map[string]any {
	if sc.h2req != nil {
		return hpackHeadersToPluginMap(sc.h2req.AllHeaders)
	}
	return nil
}

// applyGRPCOutputFilter applies the output filter to a decoded gRPC JSON body.
// Returns the filtered JSON, whether masking was applied, and whether a block
// rule matched.
func applyGRPCOutputFilter(engine *safety.Engine, jsonBody string, logger *slog.Logger) (filtered string, masked bool, blocked bool) {
	if engine == nil || len(engine.OutputRules()) == 0 {
		return jsonBody, false, false
	}

	result := engine.FilterOutput([]byte(jsonBody))

	for _, m := range result.Matches {
		logger.Info("gRPC output filter matched frame body",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String())
		if m.Action == safety.ActionBlock {
			return jsonBody, false, true
		}
	}

	if result.Masked {
		return string(result.Data), true, false
	}
	return jsonBody, false, false
}

// applyGRPCPluginHook dispatches a plugin hook with the gRPC frame's JSON body.
// Returns the (possibly modified) JSON body and whether a terminate action was returned.
func applyGRPCPluginHook(
	sc *streamContext,
	engine *plugin.Engine,
	hookName plugin.Hook,
	jsonBody string,
	connInfo *plugin.ConnInfo,
	txCtx map[string]any,
	logger *slog.Logger,
) (resultJSON string, action string, terminated bool) {
	if engine == nil {
		return jsonBody, "", false
	}

	data := map[string]any{
		"method":   scMethod(sc),
		"url":      sc.reqURL.String(),
		"headers":  scHeadersPluginMap(sc),
		"body":     jsonBody,
		"protocol": "grpc",
	}
	if connInfo != nil {
		data["conn_info"] = connInfo.ToMap()
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := engine.Dispatch(sc.ctx, hookName, data)
	if err != nil {
		logger.Warn("gRPC plugin hook error", "hook", hookName, "error", err)
		return jsonBody, "", false
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil {
		return jsonBody, "", false
	}

	switch result.Action {
	case plugin.ActionDrop:
		return jsonBody, "drop", true
	case plugin.ActionRespond:
		return jsonBody, "respond", true
	case plugin.ActionContinue:
		if result.Data != nil {
			if newBody, ok := result.Data["body"]; ok {
				if s, ok := newBody.(string); ok && s != jsonBody {
					return s, "continue", false
				}
			}
		}
	}

	return jsonBody, "", false
}

// applyGRPCAutoTransform applies auto-transform rules to a gRPC frame's
// JSON body for request direction. Returns the (possibly modified) JSON body.
func applyGRPCAutoTransform(pipeline *rules.Pipeline, sc *streamContext, jsonBody string) (string, bool) {
	if pipeline == nil || pipeline.Len() == 0 {
		return jsonBody, false
	}
	_, body := pipeline.TransformRequest(scMethod(sc), sc.reqURL, hpackToRawHeaders(scHeaders(sc)), []byte(jsonBody))
	newJSON := string(body)
	return newJSON, newJSON != jsonBody
}

// applyGRPCAutoTransformResponseHpack applies auto-transform rules using hpack
// native types for the response direction.
func applyGRPCAutoTransformResponseHpack(pipeline *rules.Pipeline, statusCode int, headers []hpack.HeaderField, jsonBody string) (string, bool) {
	if pipeline == nil || pipeline.Len() == 0 {
		return jsonBody, false
	}
	_, body := pipeline.TransformResponse(statusCode, hpackToRawHeaders(headers), []byte(jsonBody))
	newJSON := string(body)
	return newJSON, newJSON != jsonBody
}

// processGRPCRequestFrame processes a single gRPC request frame through
// all request-side subsystems: safety filter, plugin hooks (on_receive_from_client,
// on_before_send_to_server), and auto-transform. Returns the wire bytes to
// forward upstream (original if unmodified, re-encoded if modified), and
// whether processing should stop (safety filter block or plugin drop).
//
// Design: if protobuf decode fails, subsystems are skipped and the original
// raw bytes are forwarded transparently. If any subsystem modifies the JSON,
// the frame is re-encoded.
func (h *Handler) processGRPCRequestFrame(
	sc *streamContext,
	raw []byte,
	compressed bool,
	payload []byte,
	encoding string,
	connInfo *plugin.ConnInfo,
	txCtx map[string]any,
) (wireBytes []byte, stop bool) {
	// Attempt protobuf decode.
	jsonStr, _, decodeErr := decodeGRPCPayload(payload, compressed, encoding)
	if decodeErr != nil {
		sc.logger.Debug("gRPC request frame decode failed, skipping subsystems",
			"error", decodeErr)
		return raw, false
	}

	currentJSON := jsonStr
	modified := false

	// 1. Safety filter.
	if h.SafetyEngine != nil {
		violation := applyGRPCSafetyFilter(h.SafetyEngine, currentJSON, sc.reqURL.String(), scHeaders(sc))
		if violation != nil {
			action := h.SafetyFilterAction(violation)
			if action == safety.ActionBlock {
				sc.logger.Info("gRPC request frame blocked by safety filter",
					"rule_id", violation.RuleID, "rule_name", violation.RuleName)
				return nil, true
			}
			// log_only: log but continue.
			sc.logger.Warn("gRPC safety filter violation (log_only)",
				"rule_id", violation.RuleID, "rule_name", violation.RuleName)
		}
	}

	// 2. Plugin: on_receive_from_client.
	newJSON, _, terminated := applyGRPCPluginHook(
		sc, h.pluginEngine, plugin.HookOnReceiveFromClient,
		currentJSON, connInfo, txCtx, sc.logger)
	if terminated {
		return nil, true
	}
	if newJSON != currentJSON {
		currentJSON = newJSON
		modified = true
	}

	// 3. Auto-transform (request direction).
	if h.transformPipeline != nil {
		transformedJSON, changed := applyGRPCAutoTransform(h.transformPipeline, sc, currentJSON)
		if changed {
			currentJSON = transformedJSON
			modified = true
		}
	}

	// 4. Plugin: on_before_send_to_server.
	newJSON, _, terminated = applyGRPCPluginHook(
		sc, h.pluginEngine, plugin.HookOnBeforeSendToServer,
		currentJSON, connInfo, txCtx, sc.logger)
	if terminated {
		return nil, true
	}
	if newJSON != currentJSON {
		currentJSON = newJSON
		modified = true
	}

	// If no modification, forward original bytes.
	if !modified {
		return raw, false
	}

	// Re-encode modified JSON back to protobuf frame.
	newPayload, err := encodeGRPCPayload(currentJSON, compressed, encoding)
	if err != nil {
		sc.logger.Warn("gRPC request frame re-encode failed, forwarding original",
			"error", err)
		return raw, false
	}

	return rebuildGRPCFrame(compressed, newPayload), false
}

// processGRPCResponseFrameH2 processes a single gRPC response frame through
// all response-side subsystems using hpack native types. Returns the wire
// bytes to forward to the client, and whether the stream should be terminated
// (output filter block).
func (h *Handler) processGRPCResponseFrameH2(
	sc *streamContext,
	raw []byte,
	compressed bool,
	payload []byte,
	encoding string,
	statusCode int,
	respHeaders []hpack.HeaderField,
	connInfo *plugin.ConnInfo,
	txCtx map[string]any,
) (wireBytes []byte, blocked bool) {
	jsonStr, _, decodeErr := decodeGRPCPayload(payload, compressed, encoding)
	if decodeErr != nil {
		sc.logger.Debug("gRPC response frame decode failed, skipping subsystems",
			"error", decodeErr)
		return raw, false
	}

	currentJSON := jsonStr
	modified := false

	// 1. Plugin: on_receive_from_server.
	newJSON, changed := applyGRPCResponsePluginHookH2(
		sc, h.pluginEngine, plugin.HookOnReceiveFromServer,
		currentJSON, statusCode, respHeaders, connInfo, txCtx, sc.logger)
	if changed {
		currentJSON = newJSON
		modified = true
	}

	// 2. Auto-transform (response direction).
	if h.transformPipeline != nil {
		transformedJSON, tChanged := applyGRPCAutoTransformResponseHpack(
			h.transformPipeline, statusCode, respHeaders, currentJSON)
		if tChanged {
			currentJSON = transformedJSON
			modified = true
		}
	}

	// 3. Output filter.
	if h.SafetyEngine != nil {
		filtered, isMasked, isBlocked := applyGRPCOutputFilter(h.SafetyEngine, currentJSON, sc.logger)
		if isBlocked {
			sc.logger.Warn("gRPC response frame blocked by output filter")
			return nil, true
		}
		if isMasked {
			currentJSON = filtered
			modified = true
		}
	}

	// 4. Plugin: on_before_send_to_client.
	newJSON, changed = applyGRPCResponsePluginHookH2(
		sc, h.pluginEngine, plugin.HookOnBeforeSendToClient,
		currentJSON, statusCode, respHeaders, connInfo, txCtx, sc.logger)
	if changed {
		currentJSON = newJSON
		modified = true
	}

	if !modified {
		return raw, false
	}

	newPayload, err := encodeGRPCPayload(currentJSON, compressed, encoding)
	if err != nil {
		sc.logger.Warn("gRPC response frame re-encode failed, forwarding original",
			"error", err)
		return raw, false
	}

	return rebuildGRPCFrame(compressed, newPayload), false
}

// applyGRPCResponsePluginHookH2 dispatches a response-side plugin hook with
// the gRPC frame's JSON body using hpack native types.
func applyGRPCResponsePluginHookH2(
	sc *streamContext,
	engine *plugin.Engine,
	hookName plugin.Hook,
	jsonBody string,
	statusCode int,
	respHeaders []hpack.HeaderField,
	connInfo *plugin.ConnInfo,
	txCtx map[string]any,
	logger *slog.Logger,
) (resultJSON string, modified bool) {
	if engine == nil {
		return jsonBody, false
	}

	data := map[string]any{
		"method":      scMethod(sc),
		"url":         sc.reqURL.String(),
		"status_code": statusCode,
		"headers":     hpackHeadersToPluginMap(respHeaders),
		"body":        jsonBody,
		"protocol":    "grpc",
	}
	if connInfo != nil {
		data["conn_info"] = connInfo.ToMap()
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := engine.Dispatch(sc.ctx, hookName, data)
	if err != nil {
		logger.Warn("gRPC plugin hook error", "hook", hookName, "error", err)
		return jsonBody, false
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return jsonBody, false
	}

	if newBody, ok := result.Data["body"]; ok {
		if s, ok := newBody.(string); ok && s != jsonBody {
			return s, true
		}
	}

	return jsonBody, false
}
