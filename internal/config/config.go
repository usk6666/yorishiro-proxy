package config

import "time"

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

	// DBPath is the path to the SQLite database file.
	DBPath string `json:"db_path"`

	// LogLevel is the minimum log level: debug, info, warn, error.
	LogLevel string `json:"log_level"`

	// LogFormat is the log output format: text, json.
	LogFormat string `json:"log_format"`

	// LogFile is the log output file path. Empty means stderr.
	LogFile string `json:"log_file"`

	// PeekTimeout is the timeout for protocol detection on new connections.
	PeekTimeout time.Duration `json:"peek_timeout"`

	// RequestTimeout is the timeout for reading HTTP request headers.
	RequestTimeout time.Duration `json:"request_timeout"`

	// MaxConnections is the maximum number of concurrent proxy connections.
	MaxConnections int `json:"max_connections"`

	// InsecureSkipVerify disables TLS certificate verification for upstream
	// connections. This is useful when the target uses self-signed or expired
	// certificates, such as during vulnerability assessments.
	// WARNING: Enabling this option disables security checks on upstream TLS.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		ListenAddr:     "127.0.0.1:8080",
		MCPAddr:        ":3000",
		DBPath:         "katashiro.db",
		LogLevel:       "info",
		LogFormat:      "text",
		PeekTimeout:    30 * time.Second,
		RequestTimeout: 60 * time.Second,
		MaxConnections: 1024,
	}
}
