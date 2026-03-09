package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// validLogLevels lists the accepted log level strings.
var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

// Validate checks the Config fields for invalid values and returns an error
// describing the first problem found. It should be called after flag parsing
// and environment variable resolution, before initializing dependent components.
func (c *Config) Validate() error {
	if c.MaxConnections < 1 {
		return fmt.Errorf("max_connections must be >= 1, got %d", c.MaxConnections)
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout must be > 0, got %s", c.RequestTimeout)
	}
	if c.PeekTimeout <= 0 {
		return fmt.Errorf("peek_timeout must be > 0, got %s", c.PeekTimeout)
	}
	if c.LogLevel != "" && !validLogLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("invalid log level: %q (must be debug, info, warn, or error)", c.LogLevel)
	}
	if lf := strings.ToLower(c.LogFormat); lf != "" && lf != "text" && lf != "json" {
		return fmt.Errorf("invalid log format: %q (must be text or json)", c.LogFormat)
	}
	if c.RetentionMaxFlows < 0 {
		return fmt.Errorf("retention_max_flows must be >= 0, got %d", c.RetentionMaxFlows)
	}
	if c.RetentionMaxAge < 0 {
		return fmt.Errorf("retention_max_age must be >= 0, got %s", c.RetentionMaxAge)
	}
	if c.CleanupInterval < 0 {
		return fmt.Errorf("cleanup_interval must be >= 0, got %s", c.CleanupInterval)
	}
	return nil
}

// Config holds the application configuration.
type Config struct {
	// ListenAddr is the TCP address the proxy listens on.
	ListenAddr string `json:"listen_addr"`

	// MCPAddr is the address the MCP server listens on.
	MCPAddr string `json:"mcp_addr"`

	// MCPHTTPAddr is the address the MCP Streamable HTTP server listens on.
	// When set, an HTTP transport is started in addition to stdio.
	// Can also be set via YP_MCP_HTTP_ADDR environment variable.
	MCPHTTPAddr string `json:"mcp_http_addr"`

	// MCPHTTPToken is the Bearer token for authenticating MCP Streamable HTTP
	// requests. When empty, a random token is generated at startup and logged
	// to stderr. Can also be set via YP_MCP_HTTP_TOKEN environment variable.
	// CLI flag: -mcp-http-token
	MCPHTTPToken string `json:"-"`

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

	// RetentionMaxFlows is the maximum number of flows to retain.
	// 0 means unlimited (default).
	RetentionMaxFlows int `json:"retention_max_flows"`

	// RetentionMaxAge is the maximum age of flows to retain.
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

	// CADataDir overrides the default CA data directory (~/.yorishiro-proxy/ca/).
	// Used for testing; excluded from JSON serialization.
	CADataDir string `json:"-"`

	// UIDir is an optional filesystem path for WebUI static files.
	// When set, static files are served from this directory instead of
	// the embedded defaults. Excluded from JSON serialization.
	// CLI flag: -ui-dir, env: YP_UI_DIR.
	UIDir string `json:"-"`

	// NoOpenBrowser disables automatic browser opening when -mcp-http-addr is set.
	// When true, the WebUI URL is only logged to stderr without opening a browser.
	// CLI flag: -no-open-browser, env: YP_NO_OPEN_BROWSER.
	NoOpenBrowser bool `json:"-"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		ListenAddr:      "127.0.0.1:8080",
		MCPAddr:         ":3000",
		DBPath:          DefaultDBPath(),
		LogLevel:        "info",
		LogFormat:       "text",
		PeekTimeout:     30 * time.Second,
		RequestTimeout:  60 * time.Second,
		MaxConnections:  128,
		CleanupInterval: time.Hour,
	}
}

// DefaultDBPath returns the default SQLite database path: ~/.yorishiro-proxy/yorishiro.db.
// If the user's home directory cannot be resolved, it falls back to ./yorishiro.db.
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "yorishiro.db"
	}
	return filepath.Join(home, ".yorishiro-proxy", "yorishiro.db")
}

// EnsureDBDir creates the parent directory of the given database path if it does
// not already exist, using permission mode 0700. This is a no-op when the
// directory already exists.
func EnsureDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	return os.MkdirAll(dir, 0700)
}

// ResolveDBPath applies smart resolution to the given -db flag value:
//
//   - Absolute path (/path/to/db.db): used as-is.
//   - Project name (my-project): resolved to ~/.yorishiro-proxy/my-project.db.
//     A project name has no extension and no path separator.
//   - Relative path with extension (./data.db, subdir/data.db): used as CWD-relative
//     for backward compatibility.
//
// An empty value returns DefaultDBPath(). An error is returned if the value
// looks like a project name but contains invalid characters.
func ResolveDBPath(value string) (string, error) {
	if value == "" {
		return DefaultDBPath(), nil
	}

	// Absolute path: use as-is.
	if filepath.IsAbs(value) {
		return value, nil
	}

	// Check whether the value looks like a bare project name:
	// no file extension AND no path separator.
	ext := filepath.Ext(value)
	hasPathSep := strings.ContainsAny(value, `/\`)

	if ext == "" && !hasPathSep {
		// Validate project name characters.
		if err := validateProjectName(value); err != nil {
			return "", err
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve project DB path: %w", err)
		}
		return filepath.Join(home, ".yorishiro-proxy", value+".db"), nil
	}

	// Otherwise treat as a CWD-relative path (backward compatible).
	return value, nil
}

// validateProjectName checks that a project name contains only safe characters.
// Allowed characters: alphanumeric, hyphen, underscore, and dot (but not leading dot
// or "." / ".." which are path traversals).
func validateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("project name must not be empty")
	}

	// Reject path traversal patterns.
	if name == "." || name == ".." {
		return fmt.Errorf("invalid project name %q: path traversal not allowed", name)
	}

	// Reject names starting with a dot (hidden files).
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid project name %q: must not start with a dot", name)
	}

	// Reject names containing ".." anywhere (traversal sequences like "foo..bar").
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid project name %q: must not contain \"..\"", name)
	}

	for _, r := range name {
		if !isValidProjectNameRune(r) {
			return fmt.Errorf("invalid project name %q: character %q is not allowed", name, string(r))
		}
	}

	return nil
}

// isValidProjectNameRune returns true if the rune is allowed in a project name.
// Allowed: ASCII letters, digits, hyphen, underscore, dot.
func isValidProjectNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.'
}

// TargetRuleConfig defines a single target scope rule in configuration files.
// All non-empty/non-nil fields must match for the rule to apply (AND logic).
type TargetRuleConfig struct {
	// Hostname matches the target hostname (case-insensitive).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	Hostname string `json:"hostname"`

	// Ports restricts the rule to specific port numbers.
	// When nil or empty, all ports are matched.
	Ports []int `json:"ports,omitempty"`

	// PathPrefix matches the beginning of the request URL path (case-sensitive).
	// When empty, all paths are matched.
	PathPrefix string `json:"path_prefix,omitempty"`

	// Schemes restricts the rule to specific URL schemes (e.g., "http", "https").
	// When nil or empty, all schemes are matched.
	Schemes []string `json:"schemes,omitempty"`
}

// TargetScopePolicyConfig defines the target scope policy rules loaded from
// a config file or a dedicated policy file. These rules are immutable at runtime
// and cannot be changed via MCP tools.
type TargetScopePolicyConfig struct {
	// Allows lists the rules that permit network access.
	// When non-empty, only targets matching at least one allow rule are permitted.
	Allows []TargetRuleConfig `json:"allows,omitempty"`

	// Denies lists the rules that block network access.
	// Deny rules take precedence over allow rules.
	Denies []TargetRuleConfig `json:"denies,omitempty"`
}

// ProxyConfig holds the proxy configuration loaded from a JSON config file.
// The JSON format is identical to the proxy_start tool's input format,
// so users can reuse the same JSON structure for both file-based configuration
// and runtime proxy_start invocations.
//
// Complex nested fields (capture_scope, intercept_rules, auto_transform) are
// stored as json.RawMessage to defer parsing to the MCP layer, avoiding
// circular dependencies between the config and mcp packages.
type ProxyConfig struct {
	// ListenAddr is the TCP address the proxy listens on (e.g. "127.0.0.1:8080").
	ListenAddr string `json:"listen_addr,omitempty"`

	// CaptureScope configures which requests are recorded to the flow store.
	CaptureScope json.RawMessage `json:"capture_scope,omitempty"`

	// TLSPassthrough is a list of domain patterns that bypass TLS interception.
	TLSPassthrough []string `json:"tls_passthrough,omitempty"`

	// InterceptRules configures request/response intercept rules.
	InterceptRules json.RawMessage `json:"intercept_rules,omitempty"`

	// AutoTransform configures auto-transform rules for automatic modification.
	AutoTransform json.RawMessage `json:"auto_transform,omitempty"`

	// TCPForwards maps local listen ports to upstream TCP addresses.
	TCPForwards map[string]string `json:"tcp_forwards,omitempty"`

	// UpstreamProxy is the upstream proxy URL for proxy chaining.
	UpstreamProxy string `json:"upstream_proxy,omitempty"`

	// TLSFingerprint selects the TLS ClientHello fingerprint profile for upstream connections.
	// Valid values: "chrome" (default), "firefox", "safari", "edge", "random", "none" (standard crypto/tls).
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`

	// Plugins configures Starlark-based plugins for the proxy pipeline.
	// Each entry specifies a script path, target protocol, subscribed hooks,
	// and error handling behavior. Plugins are executed in order.
	//
	// json.RawMessage is used intentionally to avoid a dependency from the
	// config package to the plugin package. The raw JSON is decoded into
	// []plugin.PluginConfig by the caller (e.g. cmd/yorishiro-proxy/main.go).
	Plugins json.RawMessage `json:"plugins,omitempty"`

	// SOCKS5Auth specifies the SOCKS5 authentication method.
	// Valid values: "none" (default), "password".
	SOCKS5Auth string `json:"socks5_auth,omitempty"`

	// SOCKS5Username is the username for SOCKS5 password authentication.
	SOCKS5Username string `json:"socks5_username,omitempty"`

	// SOCKS5Password is the password for SOCKS5 password authentication.
	SOCKS5Password string `json:"socks5_password,omitempty"`

	// TargetScopePolicy defines the immutable target scope policy rules.
	// These rules control which network targets the proxy is allowed to access.
	// When loaded from a config file, this section is ignored if a dedicated
	// policy file is specified via -target-policy-file / YP_TARGET_POLICY_FILE.
	TargetScopePolicy *TargetScopePolicyConfig `json:"target_scope_policy,omitempty"`
}

// LoadFile reads and parses a JSON config file from the given path.
// It returns an error if the file does not exist or contains invalid JSON.
func LoadFile(path string) (*ProxyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	// Validate that the file contains valid JSON before unmarshalling.
	if !json.Valid(data) {
		return nil, fmt.Errorf("parse config file %s: invalid JSON", path)
	}

	var cfg ProxyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// LoadPolicyFile reads and parses a dedicated target scope policy JSON file.
// The file format is the same as the target_scope_policy section in a config file:
//
//	{
//	  "allows": [{"hostname": "*.target.com"}],
//	  "denies": [{"hostname": "*.internal.corp"}]
//	}
//
// It returns an error if the file does not exist or contains invalid JSON.
func LoadPolicyFile(path string) (*TargetScopePolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}

	if !json.Valid(data) {
		return nil, fmt.Errorf("parse policy file %s: invalid JSON", path)
	}

	var policy TargetScopePolicyConfig
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy file %s: %w", path, err)
	}

	return &policy, nil
}
