package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// interceptInput is the typed input for the intercept tool.
//
// HTTP / WS / GRPCStart / GRPCData / Raw are the per-Message-type modify
// payloads that drive common.HoldQueue dispatch. Exactly one of them must
// be non-nil for a modify_and_forward action; the dispatcher infers
// Phase + Protocol from the held envelope's Message type and rejects the
// request when the supplied payload doesn't match. Mode=raw with
// RawOverrideBase64 short-circuits the typed dispatch and builds a
// synthetic RawMessage envelope (Decision R9).
type interceptInput struct {
	// Action specifies the intercept action to execute.
	// Available actions: release, modify_and_forward, drop.
	Action string `json:"action"`
	// Params holds action-specific parameters (intercept_id, mode,
	// raw_override_base64).
	Params interceptParams `json:"params"`

	// HTTP carries the typed modify payload for an HTTPMessage envelope.
	HTTP *httpMessageModify `json:"http,omitempty" jsonschema:"typed modify payload for HTTPMessage envelopes"`
	// WS carries the typed modify payload for a WSMessage envelope.
	WS *wsMessageModify `json:"ws,omitempty" jsonschema:"typed modify payload for WSMessage envelopes"`
	// GRPCStart carries the typed modify payload for a GRPCStartMessage envelope.
	GRPCStart *grpcStartMessageModify `json:"grpc_start,omitempty" jsonschema:"typed modify payload for GRPCStartMessage envelopes"`
	// GRPCData carries the typed modify payload for a GRPCDataMessage envelope.
	GRPCData *grpcDataMessageModify `json:"grpc_data,omitempty" jsonschema:"typed modify payload for GRPCDataMessage envelopes"`
	// Raw carries the typed modify payload for a RawMessage envelope.
	Raw *rawMessageModify `json:"raw,omitempty" jsonschema:"typed modify payload for RawMessage envelopes"`
}

// interceptParams holds the per-call parameters that route the intercept
// tool — the held entry's id and an optional Mode/RawOverrideBase64 pair
// for the raw-override fast path. Per-Message-type modify payloads ride
// on the sibling interceptInput.HTTP / WS / GRPCStart / GRPCData / Raw
// fields and are consumed by dispatchTypedModify.
type interceptParams struct {
	// InterceptID is the held envelope's id (required for all actions).
	InterceptID string `json:"intercept_id,omitempty" jsonschema:"intercepted envelope ID for release/modify_and_forward/drop"`

	// Mode selects the forwarding mode: "structured" (default) routes
	// modify_and_forward through the typed dispatch; "raw" expects
	// RawOverrideBase64 and forwards the supplied bytes verbatim.
	Mode string `json:"mode,omitempty" jsonschema:"forwarding mode: structured (default) or raw"`

	// RawOverrideBase64 is the base64-encoded raw bytes to forward when
	// Mode is "raw". Caps at 10 MiB (CWE-770).
	RawOverrideBase64 *string `json:"raw_override_base64,omitempty" jsonschema:"base64-encoded raw bytes for raw-mode forwarding (max 10 MiB)"`
}

// availableInterceptActions lists the valid action names for the intercept tool.
var availableInterceptActions = []string{"release", "modify_and_forward", "drop"}

// registerIntercept registers the intercept MCP tool.
func (s *Server) registerIntercept() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "intercept",
		Description: "Act on a held envelope in the HoldQueue. " +
			"Supply intercept_id (required), an action, and the per-Message-type modify payload (http / ws / grpc_start / grpc_data / raw) when modifying. " +
			"Available actions: " +
			"'release' forwards the held envelope as-is; " +
			"'modify_and_forward' applies the supplied typed payload (one of http/ws/grpc_start/grpc_data/raw, matching the envelope's Message type), or with mode=\"raw\" + raw_override_base64 forwards a synthetic RawMessage envelope built from the supplied bytes; " +
			"'drop' discards the held envelope and unblocks the pipeline. " +
			"Headers in the typed payloads MUST be order-preserved arrays of {name, value} objects (RFC-001 wire-fidelity).",
	}, s.handleInterceptTool)
}

// handleInterceptTool routes the intercept tool invocation to the
// HoldQueue dispatcher. Validates the action and the optional
// rawMessageModify (stage-1 schema check) before any queue lookup so a
// malformed request never consumes a held entry.
func (s *Server) handleInterceptTool(ctx context.Context, _ *gomcp.CallToolRequest, input interceptInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "intercept",
		"action", input.Action,
		"intercept_id", input.Params.InterceptID,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "intercept",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if input.Action == "" {
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableInterceptActions, ", "))
	}
	switch input.Action {
	case "release", "modify_and_forward", "drop":
		// valid
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableInterceptActions, ", "))
	}

	// Stage-1 schema validation that does not depend on the held entry —
	// run before any queue lookup so a malformed request never consumes a
	// queue slot. Decision R10 / R24.
	if err := validateRawMessageModify(input.Raw); err != nil {
		return nil, nil, err
	}

	if s.pipeline == nil || s.pipeline.holdQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if input.Params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for %s action", input.Action)
	}
	entry, err := s.pipeline.holdQueue.Get(input.Params.InterceptID)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", input.Action, err)
	}
	return s.handleInterceptHoldQueue(ctx, input, entry)
}

// handleInterceptHoldQueue dispatches an action against an entry in the
// common.HoldQueue. Resolves the action via resolveHoldQueueAction (which
// performs stage-2 validation against the held envelope's type), releases
// the entry, and returns a structured summary.
func (s *Server) handleInterceptHoldQueue(_ context.Context, input interceptInput, entry *common.HeldEntry) (*gomcp.CallToolResult, *holdQueueInterceptResult, error) {
	action, err := resolveHoldQueueAction(entry, input, input.Action)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", input.Action, err)
	}

	if err := s.pipeline.holdQueue.Release(entry.ID, action); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", input.Action, err)
	}

	return nil, &holdQueueInterceptResult{
		InterceptID:  entry.ID,
		Action:       input.Action,
		Status:       holdQueueStatusForAction(input.Action),
		Protocol:     holdQueueProtocolKind(entry.Envelope),
		Direction:    entry.Envelope.Direction.String(),
		MatchedRules: entry.MatchedRules,
		FlowID:       entry.Envelope.FlowID,
		StreamID:     entry.Envelope.StreamID,
	}, nil
}

// holdQueueInterceptResult is the structured response for actions on the
// HoldQueue path. The held envelope's full body is intentionally not
// echoed back — the typed modify payload already round-trips through the
// dispatch arms, and the same envelope is observable via the query tool's
// intercept_queue resource.
type holdQueueInterceptResult struct {
	InterceptID  string   `json:"intercept_id"`
	Action       string   `json:"action"`
	Status       string   `json:"status"`
	Protocol     string   `json:"protocol"`
	Direction    string   `json:"direction"`
	MatchedRules []string `json:"matched_rules,omitempty"`
	FlowID       string   `json:"flow_id,omitempty"`
	StreamID     string   `json:"stream_id,omitempty"`
}

// holdQueueStatusForAction maps the action name to the per-action status
// label used in the structured response.
func holdQueueStatusForAction(action string) string {
	switch action {
	case "release":
		return "released"
	case "modify_and_forward":
		return "forwarded"
	case "drop":
		return "dropped"
	default:
		return action
	}
}
