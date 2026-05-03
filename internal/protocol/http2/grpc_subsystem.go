package http2

import (
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
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
	return engine.CheckInput([]byte(jsonBody), rawURL, hpackToKeyValues(headers))
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

// applyGRPCAutoTransform applies auto-transform rules to a gRPC frame's
// JSON body for request direction. Returns the (possibly modified) JSON body.
func applyGRPCAutoTransform(pipeline *rules.Pipeline, sc *streamContext, jsonBody string) (string, bool) {
	if pipeline == nil || pipeline.Len() == 0 {
		return jsonBody, false
	}
	_, body := pipeline.TransformRequest(scMethod(sc), sc.reqURL, hpackToKeyValues(scHeaders(sc)), []byte(jsonBody))
	newJSON := string(body)
	return newJSON, newJSON != jsonBody
}

// applyGRPCAutoTransformResponseHpack applies auto-transform rules using hpack
// native types for the response direction.
func applyGRPCAutoTransformResponseHpack(pipeline *rules.Pipeline, statusCode int, headers []hpack.HeaderField, jsonBody string) (string, bool) {
	if pipeline == nil || pipeline.Len() == 0 {
		return jsonBody, false
	}
	_, body := pipeline.TransformResponse(statusCode, hpackToKeyValues(headers), []byte(jsonBody))
	newJSON := string(body)
	return newJSON, newJSON != jsonBody
}

// processGRPCRequestFrame processes a single gRPC request frame through
// the request-side subsystems: safety filter and auto-transform. Returns the
// wire bytes to forward upstream (original if unmodified, re-encoded if
// modified), and whether processing should stop (safety filter block).
func (h *Handler) processGRPCRequestFrame(
	sc *streamContext,
	raw []byte,
	compressed bool,
	payload []byte,
	encoding string,
) (wireBytes []byte, stop bool) {
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
			sc.logger.Warn("gRPC safety filter violation (log_only)",
				"rule_id", violation.RuleID, "rule_name", violation.RuleName)
		}
	}

	// 2. Auto-transform (request direction).
	if h.transformPipeline != nil {
		transformedJSON, changed := applyGRPCAutoTransform(h.transformPipeline, sc, currentJSON)
		if changed {
			currentJSON = transformedJSON
			modified = true
		}
	}

	if !modified {
		return raw, false
	}

	newPayload, err := encodeGRPCPayload(currentJSON, compressed, encoding)
	if err != nil {
		sc.logger.Warn("gRPC request frame re-encode failed, forwarding original",
			"error", err)
		return raw, false
	}

	return rebuildGRPCFrame(compressed, newPayload), false
}

// processGRPCResponseFrameH2 processes a single gRPC response frame through
// the response-side subsystems: auto-transform and output filter. Returns the
// wire bytes to forward to the client, and whether the stream should be
// terminated (output filter block).
func (h *Handler) processGRPCResponseFrameH2(
	sc *streamContext,
	raw []byte,
	compressed bool,
	payload []byte,
	encoding string,
	statusCode int,
	respHeaders []hpack.HeaderField,
) (wireBytes []byte, blocked bool) {
	jsonStr, _, decodeErr := decodeGRPCPayload(payload, compressed, encoding)
	if decodeErr != nil {
		sc.logger.Debug("gRPC response frame decode failed, skipping subsystems",
			"error", decodeErr)
		return raw, false
	}

	currentJSON := jsonStr
	modified := false

	// 1. Auto-transform (response direction).
	if h.transformPipeline != nil {
		transformedJSON, tChanged := applyGRPCAutoTransformResponseHpack(
			h.transformPipeline, statusCode, respHeaders, currentJSON)
		if tChanged {
			currentJSON = transformedJSON
			modified = true
		}
	}

	// 2. Output filter.
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
