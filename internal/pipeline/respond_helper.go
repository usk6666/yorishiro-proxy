// Policy-drop synthetic 403 response helper (USK-829).
//
// When a Pipeline Step decides to block a Send-direction HTTPMessage envelope
// (intercept drop, target_scope reject, http_scope reject, safety_filter
// block), the historical behaviour returned Result{Action: Drop} and the
// session loop emitted nothing on the wire. The client read end then hung
// until its own timeout (curl exit 28).
//
// This helper constructs a synthetic 403 Forbidden response envelope so the
// affected Step can return Result{Action: Respond, ...} instead. The client
// sees a parseable HTTP response and closes promptly. The session loop
// already routes Respond to client.Send (session.go dispatchClientAction /
// wsRelayDirection).
//
// Wire fidelity:
//   - The synthetic response is a NEW envelope (Sequence = original.Sequence+1,
//     Direction = Receive). RecordStep records it as a distinct variant. The
//     original held Send envelope is still recorded unchanged.
//   - Raw is intentionally left nil. The HTTP/1.x sendResponseSynthetic path
//     and HTTP/2 aggregator both re-serialize HTTPMessage on Send when Opaque
//     is absent — no per-protocol divergence is required at the Pipeline
//     layer.
//   - Opaque is nil (no layer-internal state to thread through; this is a
//     proxy-generated envelope, not one captured from a wire parse).
//
// Mid-stream WS/gRPC paths intentionally do NOT use this helper — those
// protocols need protocol-correct terminators (Close frame / trailers) that
// HTTPMessage cannot express through the per-protocol Send dispatch. Those
// paths remain at Result{Action: Drop} with TODO references to follow-up
// Issues (D2-D5).

package pipeline

import (
	"encoding/json"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// buildPolicyDropResponse synthesizes a 403 Forbidden response envelope for a
// blocked Send-direction HTTPMessage envelope. The body is a small JSON object
// describing the block.
//
// Body shape:
//
//	{"error":"blocked by <reason>","blocked_by":"<reason>"[,"matched_rules":[...]]}
//
// The "matched_rules" key is included only when matchedRules is non-empty —
// for non-intercept blocks (target_scope / http_scope / safety) the field is
// omitted rather than rendered as an empty array.
//
// Headers (in fixed order):
//
//	Content-Type: application/json; charset=utf-8
//	Connection: close
//	Server: yorishiro-proxy
//
// Content-Length is intentionally NOT stamped here — the HTTP/1.x Send path
// computes it from len(Body) at serialize time (sendResponseSynthetic) and
// the HTTP/2 aggregator omits length headers entirely. Stamping it twice
// would risk a CL/TE conflict on the HTTP/1.x path if any downstream Step
// re-rendered the body.
//
// The synthetic envelope mirrors plugin_dispatch.buildRespondEnvelope (USK-665)
// in identity layout: same StreamID/FlowID/Context, Sequence+1, Direction
// flipped to Receive, Protocol carried over from the original (so HTTP/1.x
// stays HTTP/1.x and HTTP/2 stays HTTP/2 — the relevant Send path is selected
// by the client Channel, not by the synthetic envelope's Protocol field).
func buildPolicyDropResponse(env *envelope.Envelope, reason string, matchedRules []string) *envelope.Envelope {
	body := policyDropBody(reason, matchedRules)
	headers := []envelope.KeyValue{
		{Name: "Content-Type", Value: "application/json; charset=utf-8"},
		{Name: "Connection", Value: "close"},
		{Name: "Server", Value: "yorishiro-proxy"},
	}
	resp := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence + 1,
		Direction: envelope.Receive,
		Protocol:  env.Protocol,
		Context:   env.Context,
		Message: &envelope.HTTPMessage{
			Status:       403,
			StatusReason: "Forbidden",
			Headers:      headers,
			Body:         body,
		},
	}
	return resp
}

// policyDropBody renders the JSON body. json.Marshal is used so that any
// future expansion of the body shape (extra metadata fields, structured
// rule descriptors) goes through the encoder rather than fmt.Sprintf
// fragments. Failure to marshal falls back to a minimal hand-rolled
// representation — the only way Marshal fails here is if the input is non-
// JSON-encodable, which the closed shape used below cannot produce.
func policyDropBody(reason string, matchedRules []string) []byte {
	payload := map[string]any{
		"error":      "blocked by " + reason,
		"blocked_by": reason,
	}
	if len(matchedRules) > 0 {
		payload["matched_rules"] = matchedRules
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Defensive: the structured payload above cannot produce a
		// Marshal error in practice, but if a future edit somehow does,
		// emit a hand-rolled minimal body so the wire still closes cleanly.
		return []byte(`{"error":"blocked by ` + reason + `","blocked_by":"` + reason + `"}`)
	}
	return b
}
