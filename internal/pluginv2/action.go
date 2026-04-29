package pluginv2

import "fmt"

// Action is the action a plugin hook returns to control proxy behavior.
// RFC §9.3 Decision item 5: which actions are valid depends on the event.
type Action int

const (
	// ActionContinue lets the proxy continue with the (possibly modified)
	// envelope. Always valid.
	ActionContinue Action = iota

	// ActionDrop tells the proxy to drop the connection / envelope.
	// Valid only on transaction-start events (http.on_request,
	// ws.on_upgrade, grpc.on_start, grpc-web.on_start, connection.on_connect,
	// socks5.on_connect).
	ActionDrop

	// ActionRespond tells the proxy to short-circuit with a synthetic
	// response. Valid only on transaction-start events for the request
	// direction, and on http.on_response (replacement of upstream response).
	ActionRespond
)

// String returns a stable lowercase token for telemetry.
func (a Action) String() string {
	switch a {
	case ActionContinue:
		return "CONTINUE"
	case ActionDrop:
		return "DROP"
	case ActionRespond:
		return "RESPOND"
	default:
		return fmt.Sprintf("Action(%d)", int(a))
	}
}

// ActionMask is a bitfield of permitted actions for a given hook entry.
// Used by the surface table to enforce action validity at load time.
type ActionMask uint8

const (
	// ActionMaskContinue is implicit on every entry — every hook can return CONTINUE.
	ActionMaskContinue ActionMask = 1 << iota
	// ActionMaskDrop allows ActionDrop. Set on transaction-start events.
	ActionMaskDrop
	// ActionMaskRespond allows ActionRespond. Set on response-replacement
	// and transaction-start request events.
	ActionMaskRespond
)

// Has reports whether the mask permits the given action.
func (m ActionMask) Has(a Action) bool {
	switch a {
	case ActionContinue:
		return m&ActionMaskContinue != 0
	case ActionDrop:
		return m&ActionMaskDrop != 0
	case ActionRespond:
		return m&ActionMaskRespond != 0
	default:
		return false
	}
}
