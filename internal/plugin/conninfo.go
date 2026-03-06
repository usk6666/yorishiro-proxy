package plugin

// ConnInfo holds network connection metadata for plugin hooks.
// This is a protocol-agnostic type that can be used by HTTP, gRPC,
// WebSocket, and other protocol handlers.
type ConnInfo struct {
	// ClientAddr is the remote address of the client (e.g., "192.168.1.100:54321").
	ClientAddr string
	// ServerAddr is the resolved address of the upstream server (e.g., "93.184.216.34:443").
	ServerAddr string
	// TLSVersion is the negotiated TLS version (e.g., "TLS 1.3").
	// Empty for non-TLS connections.
	TLSVersion string
	// TLSCipher is the negotiated TLS cipher suite name (e.g., "TLS_AES_128_GCM_SHA256").
	// Empty for non-TLS connections.
	TLSCipher string
	// TLSALPN is the negotiated Application-Layer Protocol (e.g., "h2", "http/1.1").
	// Empty if ALPN was not negotiated or for non-TLS connections.
	TLSALPN string
}

// ToMap converts ConnInfo to a map[string]any suitable for plugin hook data.
func (c *ConnInfo) ToMap() map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"client_addr": c.ClientAddr,
		"server_addr": c.ServerAddr,
		"tls_version": c.TLSVersion,
		"tls_cipher":  c.TLSCipher,
		"tls_alpn":    c.TLSALPN,
	}
}

// ConnInfoFromMap converts a map[string]any back to a ConnInfo.
// This is used to extract potentially modified ConnInfo from plugin hook results.
func ConnInfoFromMap(m map[string]any) *ConnInfo {
	if m == nil {
		return &ConnInfo{}
	}
	c := &ConnInfo{}
	if v, ok := m["client_addr"].(string); ok {
		c.ClientAddr = v
	}
	if v, ok := m["server_addr"].(string); ok {
		c.ServerAddr = v
	}
	if v, ok := m["tls_version"].(string); ok {
		c.TLSVersion = v
	}
	if v, ok := m["tls_cipher"].(string); ok {
		c.TLSCipher = v
	}
	if v, ok := m["tls_alpn"].(string); ok {
		c.TLSALPN = v
	}
	return c
}
