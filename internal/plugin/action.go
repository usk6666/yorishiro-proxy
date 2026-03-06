package plugin

import "fmt"

// ActionType represents the action a plugin hook returns to control
// proxy behavior after hook execution.
type ActionType int

const (
	// ActionContinue instructs the proxy to continue processing with
	// the (potentially modified) data. Valid in all hooks.
	ActionContinue ActionType = iota

	// ActionDrop instructs the proxy to silently drop the connection.
	// Only valid in on_receive_from_client hooks.
	ActionDrop

	// ActionRespond instructs the proxy to send a custom response to
	// the client instead of forwarding to the server.
	// Only valid in on_receive_from_client hooks.
	ActionRespond
)

// String returns the string representation of an ActionType.
func (a ActionType) String() string {
	switch a {
	case ActionContinue:
		return "CONTINUE"
	case ActionDrop:
		return "DROP"
	case ActionRespond:
		return "RESPOND"
	default:
		return fmt.Sprintf("ActionType(%d)", int(a))
	}
}

// ParseActionType converts a string to an ActionType.
// It returns an error for unrecognized values.
func ParseActionType(s string) (ActionType, error) {
	switch s {
	case "CONTINUE":
		return ActionContinue, nil
	case "DROP":
		return ActionDrop, nil
	case "RESPOND":
		return ActionRespond, nil
	default:
		return ActionContinue, fmt.Errorf("unknown action type: %q", s)
	}
}

// HookResult is the result returned by a plugin hook function.
// It contains the action to take and any modified data.
type HookResult struct {
	// Action is the action type to take (CONTINUE, DROP, RESPOND).
	Action ActionType

	// Data holds the (potentially modified) data dict from the hook.
	// The keys and values are protocol-specific.
	Data map[string]any

	// ResponseData holds custom response data when Action is ActionRespond.
	// This is only used for on_receive_from_client hooks.
	ResponseData map[string]any
}
