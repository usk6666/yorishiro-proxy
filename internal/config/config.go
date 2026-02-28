package config

import "time"

// Config holds the application configuration.
type Config struct {
	// ListenAddr is the TCP address the proxy listens on.
	ListenAddr string `json:"listen_addr"`

	// MCPAddr is the address the MCP server listens on.
	MCPAddr string `json:"mcp_addr"`

	// MCPHTTPAddr is the address the MCP Streamable HTTP server listens on.
	// When set, an HTTP transport is started in addition to stdio.
	// Can also be set via KP_MCP_HTTP_ADDR environment variable.
	MCPHTTPAddr string `json:"mcp_http_addr"`

	// MCPHTTPToken is the Bearer token for authenticating Streamable HTTP requests.
	// When empty, a random token is generated at startup.
	// Can also be set via KP_MCP_HTTP_TOKEN environment variable.
	MCPHTTPToken string `json:"mcp_http_token"`

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

	// RetentionMaxSessions is the maximum number of sessions to retain.
	// 0 means unlimited (default).
	RetentionMaxSessions int `json:"retention_max_sessions"`

	// RetentionMaxAge is the maximum age of sessions to retain.
	// 0 means unlimited (default).
	RetentionMaxAge time.Duration `json:"retention_max_age"`

	// CleanupInterval is the interval between automatic cleanup runs.
	// 0 disables automatic cleanup. Default: 1h.
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// TLSPassthrough is a list of domain patterns that should bypass TLS
	// interception (MITM). Supported formats:
	//   - Exact match: "example.com"
	//   - Wildcard: "*.example.com" (matches any subdomain)
	TLSPassthrough []string `json:"tls_passthrough"`

	// CAEphemeral forces in-memory-only CA generation with no file persistence.
	// When true, a new CA is generated on each startup.
	CAEphemeral bool `json:"ca_ephemeral"`

	// CADataDir overrides the default CA data directory (~/.katashiro-proxy/ca/).
	// Used for testing; excluded from JSON serialization.
	CADataDir string `json:"-"`
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
		MaxConnections:  1024,
		CleanupInterval: time.Hour,
	}
}
