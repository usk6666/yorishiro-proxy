package config

import "fmt"

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
	if ms == 0 || (ms >= MinClientTimeoutMs && ms <= MaxClientTimeoutMs) {
		return nil
	}
	return fmt.Errorf("%s must be 0 (disabled) or between %d and %d, got %d", name, MinClientTimeoutMs, MaxClientTimeoutMs, ms)
}

// validateClientTimeouts checks the optional request_timeout_ms /
// client_idle_timeout_ms keys of a config file. Nil (omitted) is valid.
func (c *ProxyConfig) validateClientTimeouts() error {
	if c.RequestTimeoutMs != nil {
		if err := ValidateClientTimeoutMs("request_timeout_ms", *c.RequestTimeoutMs); err != nil {
			return err
		}
	}
	if c.ClientIdleTimeoutMs != nil {
		if err := ValidateClientTimeoutMs("client_idle_timeout_ms", *c.ClientIdleTimeoutMs); err != nil {
			return err
		}
	}
	return nil
}
