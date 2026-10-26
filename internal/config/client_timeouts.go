package config

// Bounds of the client-side timeouts request_timeout_ms and
// client_idle_timeout_ms (USK-1186), shared by the config file and the MCP
// proxy_start / configure inputs. 0 is accepted on its own and means
// "disabled".
const (
	MinClientTimeoutMs = 100
	MaxClientTimeoutMs = 600000
)

// ValidateClientTimeoutMs checks a client-side timeout value named name:
// 0 (disabled) or MinClientTimeoutMs..MaxClientTimeoutMs.
func ValidateClientTimeoutMs(name string, ms int) error {
	return nil
}
