package plugin

import "fmt"

// Hook represents a named hook point in the proxy pipeline.
type Hook string

// Data hooks are called during request/response processing.
const (
	// HookOnReceiveFromClient is called after TargetScope evaluation,
	// before Intercept. The plugin receives the client's request data.
	HookOnReceiveFromClient Hook = "on_receive_from_client"

	// HookOnBeforeSendToServer is called after Transform, before Recording.
	// The plugin receives the request about to be sent upstream.
	HookOnBeforeSendToServer Hook = "on_before_send_to_server"

	// HookOnReceiveFromServer is called after receiving the server response,
	// before Transform. The plugin receives the raw server response.
	HookOnReceiveFromServer Hook = "on_receive_from_server"

	// HookOnBeforeSendToClient is called after Transform, before Recording.
	// The plugin receives the response about to be sent to the client.
	HookOnBeforeSendToClient Hook = "on_before_send_to_client"
)

// Lifecycle hooks are called during connection lifecycle events.
const (
	// HookOnConnect is called when a new TCP connection is accepted.
	HookOnConnect Hook = "on_connect"

	// HookOnTLSHandshake is called after a TLS handshake completes.
	HookOnTLSHandshake Hook = "on_tls_handshake"

	// HookOnDisconnect is called when a connection is closed.
	HookOnDisconnect Hook = "on_disconnect"

	// HookOnSOCKS5Connect is called when a SOCKS5 CONNECT tunnel is
	// successfully established. Data includes target host, port,
	// authentication user (if any), and client address.
	HookOnSOCKS5Connect Hook = "on_socks5_connect"
)

// allHooks lists all valid hook names for validation.
var allHooks = map[Hook]bool{
	HookOnReceiveFromClient:  true,
	HookOnBeforeSendToServer: true,
	HookOnReceiveFromServer:  true,
	HookOnBeforeSendToClient: true,
	HookOnConnect:            true,
	HookOnTLSHandshake:       true,
	HookOnDisconnect:         true,
	HookOnSOCKS5Connect:      true,
}

// droppableHooks lists hooks that support ActionDrop and ActionRespond.
var droppableHooks = map[Hook]bool{
	HookOnReceiveFromClient: true,
}

// dataHooks lists hooks that participate in transaction context sharing.
// Lifecycle hooks (on_connect, on_disconnect, etc.) do not receive ctx.
var dataHooks = map[Hook]bool{
	HookOnReceiveFromClient:  true,
	HookOnBeforeSendToServer: true,
	HookOnReceiveFromServer:  true,
	HookOnBeforeSendToClient: true,
}

// IsDataHook reports whether the hook is a data hook (request/response
// processing) that participates in transaction context sharing.
// Lifecycle hooks such as on_connect and on_disconnect return false.
func IsDataHook(h Hook) bool {
	return dataHooks[h]
}

// ValidateHook checks whether a hook name is valid.
func ValidateHook(h Hook) error {
	if !allHooks[h] {
		return fmt.Errorf("unknown hook: %q", string(h))
	}
	return nil
}

// ValidateAction checks whether the given action is valid for the given hook.
func ValidateAction(h Hook, a ActionType) error {
	if a == ActionContinue {
		return nil
	}
	if !droppableHooks[h] {
		return fmt.Errorf("action %s is not allowed in hook %q (only CONTINUE is valid)", a, string(h))
	}
	return nil
}
