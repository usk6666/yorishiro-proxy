package config

// Config holds the application configuration.
type Config struct {
	// ListenAddr is the TCP address the proxy listens on.
	ListenAddr string `json:"listen_addr"`

	// MCPAddr is the address the MCP server listens on.
	MCPAddr string `json:"mcp_addr"`

	// CAKeyPath is the path to the CA private key file.
	CAKeyPath string `json:"ca_key_path"`

	// CACertPath is the path to the CA certificate file.
	CACertPath string `json:"ca_cert_path"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		ListenAddr: ":8080",
		MCPAddr:    ":3000",
	}
}
