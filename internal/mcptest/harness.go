// Package mcptest provides a JSON-RPC over HTTP end-to-end harness for
// the yorishiro-proxy MCP server. It drives the production server
// assembly via mcpserver.Run so e2e tests catch the same class of
// integration bugs that USK-717/718/719 hit (transport-level wiring,
// CLI-flag parsing, boot-order ordering).
//
// Design contract: this package MUST NOT re-implement server assembly.
// All server bring-up flows through mcpserver.Run with a fresh
// flag.FlagSet and a RunOptions.OnHTTPListening hook that captures the
// resolved listen address. The wire format is the same MCP Streamable
// HTTP transport the production CLI client (cmd/yorishiro-proxy/client.go)
// uses — gomcp.NewClient + gomcp.StreamableClientTransport — so request
// shapes match what real clients send.
//
// Coexistence with internal/mcp/*_integration_test.go (in-memory, Class
// B) is intentional: the in-memory harness stays the fast path for
// per-tool detail tests; this harness is the wiring path.
//
// The harness passes -insecure to mcpserver.Run by default. The reason:
// httptest.Server.StartTLS (used by buildUpstream) issues a self-signed
// leaf certificate, and any test driving traffic through the proxy
// would otherwise be rejected at upstream-TLS verification. Tests that
// want verification on (e.g. to assert verification failure surfaces a
// specific error) will need a future HarnessOptions knob to suppress
// -insecure — left as future work; not implemented today.
package mcptest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

// HarnessOptions configures StartHarness. The zero value is valid and
// starts a self-contained MCP server with HTTP MCP enabled, an
// ephemeral CA, an isolated SQLite database, and no upstream test
// server. Tests populate only the fields they need.
type HarnessOptions struct {
	// TLSFingerprint, when non-empty, is passed as the -tls-fingerprint
	// flag to mcpserver.Run. Valid values: "chrome", "firefox",
	// "safari", "edge", "random", "none". Empty leaves the default.
	TLSFingerprint string

	// UpstreamProto selects the test upstream server's wire protocol.
	// Empty disables upstream construction entirely (h.UpstreamTLS is
	// nil). "http/1.1" starts an httptest.NewTLSServer with a fixed
	// echo handler. Other values are reserved for downstream Issues
	// (USK-725 mTLS, USK-726 h2/grpc/ws, USK-727 raw) — passing them
	// today panics with a TODO referencing the consuming Issue rather
	// than silently no-op'ing.
	UpstreamProto string

	// EnableMTLS, when true, configures the upstream test server to
	// require client certificates and provisions a fresh test CA +
	// client cert + key for the test. The CA cert is loaded into the
	// upstream server's ClientCAs pool; the client cert/key paths land
	// on Harness.MTLS so the test can pass them as proxy_start's
	// client_cert / client_key arguments.
	//
	// Requires UpstreamProto != "" (currently only "http/1.1") so the
	// upstream test server actually exists. Passing EnableMTLS=true
	// without an upstream is rejected by validateOptions.
	EnableMTLS bool

	// PreStartTools is a sequence of tool calls invoked AFTER the MCP
	// server is listening but BEFORE StartHarness returns. Used by
	// USK-727 (USK-719 regression) to call resend before proxy_start
	// has run, which historically segfaulted.
	PreStartTools []ToolCall

	// LogLevel overrides the server's log level. Empty defaults to
	// "error" so test output stays quiet; set "debug" while iterating
	// on a flaky test.
	LogLevel string

	// ConfigJSON, when non-empty, is written to a temp file and passed
	// as the `-config <path>` flag to mcpserver.Run. Use this to load
	// proxy configuration that has no dedicated CLI flag (Plugins,
	// SafetyFilter rules, body-spill limits, etc.). The string MUST
	// parse as a yorishiro-proxy config JSON document; mcpserver.Run
	// rejects malformed input at boot, so misconfigured tests fail loudly
	// in waitForListening rather than at first tool call.
	ConfigJSON string
}

// ToolCall is a (name, args) pair used for HarnessOptions.PreStartTools.
type ToolCall struct {
	Name string
	Args any
}

// Harness is the value returned by StartHarness. It owns a running MCP
// server, an MCP client connected to it, and (optionally) an upstream
// HTTPS test server. Cleanup tears all three down.
type Harness struct {
	// BaseURL is the resolved http://host:port/ root of the running MCP
	// server. The MCP endpoint sits at BaseURL+"mcp"; the WebUI sits at
	// BaseURL+"".
	BaseURL string

	// Token is the Bearer token the harness generated for this server
	// instance. Tests may use it to construct alternative HTTP clients
	// (e.g. to assert auth-rejection behavior).
	Token string

	// Client is the JSON-RPC-over-HTTP client connected to the running
	// server. Its CallTool / MustOK / ExpectError methods are the
	// preferred interface for tests.
	Client *Client

	// UpstreamTLS is the optional upstream test server constructed when
	// HarnessOptions.UpstreamProto != "". Nil otherwise. Tests that
	// drive traffic through the proxy point proxy_start at the proxy
	// listener and then issue requests targeting UpstreamTLS.URL.
	UpstreamTLS *httptest.Server

	// MTLS is the per-harness mutual-TLS material, populated only when
	// HarnessOptions.EnableMTLS is true. Tests pass MTLS.ClientCertPath
	// / MTLS.ClientKeyPath to proxy_start so the proxy presents the
	// client certificate when dialling UpstreamTLS. Nil otherwise.
	MTLS *MTLSMaterial

	// UpstreamFingerprint records the TLS ClientHello observed by the
	// upstream test server, used by tests that assert the proxy's
	// configured TLS fingerprint profile actually shaped the wire (e.g.
	// USK-727 boot-order regression: -tls-fingerprint=chrome must take
	// effect even before proxy_start). Populated whenever UpstreamTLS is
	// non-nil; nil otherwise. See FingerprintObserver for the detection
	// contract.
	UpstreamFingerprint *FingerprintObserver

	// Cleanup tears down the harness in this order: client session ->
	// upstream test server -> MCP server (via context cancel + wait).
	// Idempotent: calling more than once is a no-op. t.Cleanup is also
	// registered automatically, so explicit defer is optional.
	Cleanup func()
}

// StartHarness boots a production-wired MCP server on a loopback
// ephemeral port, connects an MCP client, and returns a Harness ready
// for tool calls. It t.Fatal's on any setup error.
//
// Lifecycle: a goroutine running mcpserver.Run is spawned with a
// cancellable context. The OnHTTPListening hook delivers the resolved
// address through a channel so the harness has a real BaseURL by the
// time it returns. Cleanup cancels the run context, waits for the goroutine
// to exit, and reports any non-context-cancelled error via t.Errorf.
func StartHarness(t *testing.T, opts HarnessOptions) *Harness {
	t.Helper()

	validateOptions(t, opts)

	token, err := generateToken()
	if err != nil {
		t.Fatalf("mcptest: generate Bearer token: %v", err)
	}

	// Redirect server.json into the test's TempDir so harness runs do
	// not pollute the developer's ~/.yorishiro-proxy/server.json and
	// concurrent harness instances in the same test process do not
	// clobber each other's PID-scoped removeServerJSON cleanup.
	serverJSONPath := filepath.Join(t.TempDir(), "server.json")
	restoreServerJSON := mcpserver.SetServerJSONPathForTest(func() (string, error) {
		return serverJSONPath, nil
	})
	t.Cleanup(restoreServerJSON)

	args := buildRunArgs(t, opts, token)
	mtlsDir := t.TempDir()
	upstream, mtls, fpObserver, err := buildUpstream(opts, mtlsDir)
	if err != nil {
		t.Fatalf("mcptest: build upstream: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	runErrCh := make(chan error, 1)
	go runMCPServer(runCtx, args, addrCh, runErrCh)

	addr := waitForListening(t, addrCh, runErrCh, runCancel, upstream)
	baseURL := fmt.Sprintf("http://%s/", addr)
	endpoint := baseURL + "mcp"

	// Connect the JSON-RPC-over-HTTP client. The wire format is the
	// MCP Streamable HTTP transport — identical to what
	// cmd/yorishiro-proxy/client.go uses against the production
	// server.
	client, err := newClient(runCtx, endpoint, token)
	if err != nil {
		runCancel()
		if upstream != nil {
			upstream.Close()
		}
		<-runErrCh
		t.Fatalf("mcptest: connect MCP client: %v", err)
	}

	cleanup := makeCleanup(t, client, upstream, runCancel, runCtx, runErrCh)
	t.Cleanup(cleanup)

	h := &Harness{
		BaseURL:             baseURL,
		Token:               token,
		Client:              client,
		UpstreamTLS:         upstream,
		MTLS:                mtls,
		UpstreamFingerprint: fpObserver,
		Cleanup:             cleanup,
	}

	for _, tc := range opts.PreStartTools {
		_ = h.CallTool(t, tc.Name, tc.Args)
	}

	return h
}

// CallTool invokes the named MCP tool with the given arguments and
// returns the structured result. Transport-level errors and JSON-RPC
// errors both flow into ToolResult.Err — callers that want a hard
// failure on error should use MustOK.
func (h *Harness) CallTool(t *testing.T, name string, args any) ToolResult {
	t.Helper()
	return h.Client.CallTool(t, name, args)
}

// MustOK invokes the named MCP tool and t.Fatal's if the call fails or
// the tool itself reports an error. The fatal message includes the
// underlying error / IsError content for debuggability.
func (h *Harness) MustOK(t *testing.T, name string, args any) ToolResult {
	t.Helper()
	res := h.Client.CallTool(t, name, args)
	if res.Err != nil {
		t.Fatalf("mcptest: tool %q failed: %v", name, res.Err)
	}
	if res.IsError {
		t.Fatalf("mcptest: tool %q returned IsError=true: %s", name, res.Text)
	}
	return res
}

// ExpectError invokes the named MCP tool and asserts the call surfaces
// an error whose message contains errSubstring. Substring matching is
// case-sensitive — tests with messages crossing case boundaries should
// pass an explicit lower/upper variant. Used by negative-path scenarios
// (auth failures, malformed args, etc.).
func (h *Harness) ExpectError(t *testing.T, name string, args any, errSubstring string) {
	t.Helper()
	res := h.Client.CallTool(t, name, args)
	combined := combineErrorText(res)
	if combined == "" {
		t.Fatalf("mcptest: tool %q expected error containing %q, got success: %s",
			name, errSubstring, res.Text)
	}
	if !contains(combined, errSubstring) {
		t.Fatalf("mcptest: tool %q error = %q, want substring %q", name, combined, errSubstring)
	}
}

// validateOptions rejects HarnessOptions configurations that are not
// supported by the current implementation. It t.Fatal's so the caller
// gets a clear pointer to the consuming Issue. Silent no-op would hide
// test bugs (a downstream test silently exercising the wrong path).
func validateOptions(t *testing.T, opts HarnessOptions) {
	t.Helper()
	switch opts.UpstreamProto {
	case "", "http/1.1":
		// supported
	case "h2", "h2c", "grpc", "ws":
		t.Fatalf("mcptest: UpstreamProto=%q not yet implemented (deferred to USK-726)", opts.UpstreamProto)
	case "raw":
		t.Fatalf("mcptest: UpstreamProto=%q not yet implemented (deferred to USK-727)", opts.UpstreamProto)
	default:
		t.Fatalf("mcptest: UpstreamProto=%q is not a recognised value", opts.UpstreamProto)
	}
	if opts.EnableMTLS && opts.UpstreamProto == "" {
		// EnableMTLS requires an upstream server to anchor the client-cert
		// requirement against. Silently allowing it would let tests believe
		// they're verifying mTLS while no upstream is even running.
		t.Fatalf("mcptest: EnableMTLS=true requires UpstreamProto to be set (e.g. \"http/1.1\")")
	}
}

// buildRunArgs constructs the args slice fed to mcpserver.Run. Defaults
// are tuned for headless test mode: an OS-assigned loopback port, an
// ephemeral CA, an isolated SQLite path under t.TempDir().
func buildRunArgs(t *testing.T, opts HarnessOptions, token string) []string {
	t.Helper()
	logLevel := opts.LogLevel
	if logLevel == "" {
		logLevel = "error"
	}
	dbPath := filepath.Join(t.TempDir(), "harness.db")
	args := []string{
		"-mcp-http-addr", "127.0.0.1:0",
		"-mcp-http-token", token,
		"-db", dbPath,
		"-ca-ephemeral",
		"-log-level", logLevel,
		// httptest.NewTLSServer uses a self-signed leaf certificate that
		// the proxy's upstream-TLS verification would otherwise reject.
		// The harness is a test fixture targeting only loopback test
		// upstreams, so skipping verification is safe and necessary for
		// any scenario that drives traffic through the proxy.
		"-insecure",
	}
	if opts.TLSFingerprint != "" {
		args = append(args, "-tls-fingerprint", opts.TLSFingerprint)
	}
	if opts.ConfigJSON != "" {
		cfgPath := filepath.Join(t.TempDir(), "harness-config.json")
		if err := writeConfigFile(cfgPath, opts.ConfigJSON); err != nil {
			t.Fatalf("mcptest: write config file: %v", err)
		}
		args = append(args, "-config", cfgPath)
	}
	return args
}

// writeConfigFile materialises HarnessOptions.ConfigJSON to disk so that
// mcpserver.Run's `-config` flag can pick it up. Split out so tests that
// fake the filesystem can swap it without touching buildRunArgs.
func writeConfigFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// buildUpstream constructs the optional upstream test server.
// Returns (nil, nil, nil, nil) when no upstream is requested. When
// EnableMTLS is set, the returned server is configured with
// tls.RequireAndVerifyClientCert plus a ClientCAs pool seeded from a
// freshly-generated test CA, and the corresponding client material is
// returned so the harness can hand the on-disk paths to the test.
//
// Every upstream is wired with a FingerprintObserver via
// installFingerprintObserver so tests can assert the TLS fingerprint
// profile (e.g. uTLS Chrome) configured on the proxy actually shaped
// the ClientHello on the wire (USK-727).
//
// Currently only "http/1.1" is supported; validateOptions has already
// rejected other variants. The handler echoes a constant body for the
// non-mTLS case and reports the verified client CommonName for the
// mTLS case so tests can assert the client cert was actually
// presented.
func buildUpstream(opts HarnessOptions, mtlsDir string) (*httptest.Server, *MTLSMaterial, *FingerprintObserver, error) {
	if opts.UpstreamProto != "http/1.1" {
		return nil, nil, nil, nil
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// In mTLS mode echo the verified client CN so tests can assert
		// the cert really reached the server. In plain mode emit the
		// historical fixed body so existing smoke tests keep matching.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			_, _ = fmt.Fprintf(w, "mcptest upstream echo (client_cn=%s)\n",
				r.TLS.PeerCertificates[0].Subject.CommonName)
			return
		}
		_, _ = io.WriteString(w, "mcptest upstream echo\n")
	})

	if !opts.EnableMTLS {
		// httptest.NewTLSServer auto-configures a self-signed leaf cert
		// during StartTLS; we use NewUnstartedServer + a templated
		// tls.Config so we can layer GetConfigForClient on top for the
		// fingerprint observation hook.
		srv := httptest.NewUnstartedServer(handler)
		tlsCfg, fpObs := installFingerprintObserver(nil)
		srv.TLS = tlsCfg
		srv.StartTLS()
		return srv, nil, fpObs, nil
	}

	mtls, err := generateMTLSMaterial(mtlsDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate mTLS material: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mtls.CACertPEM) {
		return nil, nil, nil, fmt.Errorf("append test CA to pool")
	}

	srv := httptest.NewUnstartedServer(handler)
	tlsCfg, fpObs := installFingerprintObserver(&tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	})
	srv.TLS = tlsCfg
	srv.StartTLS()
	return srv, mtls, fpObs, nil
}

// runMCPServer is the goroutine entry point for the boot path. It
// builds a fresh flag.FlagSet (per the mcpserver.Run contract) and
// publishes the resolved listen address through addrCh; the final
// return value of Run lands in runErrCh.
func runMCPServer(ctx context.Context, args []string, addrCh chan<- string, runErrCh chan<- error) {
	fs := flag.NewFlagSet("mcptest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	runErrCh <- mcpserver.Run(ctx, fs, args, mcpserver.RunOptions{
		Version: "mcptest",
		OnHTTPListening: func(addr string) {
			// Non-blocking send: addrCh is buffered to size 1.
			// Guard with select so a misbehaving caller cannot
			// deadlock the boot goroutine if it reads addrCh
			// twice.
			select {
			case addrCh <- addr:
			default:
			}
		},
	})
}

// waitForListening blocks until the MCP server publishes its listen
// address, mcpserver.Run exits early, or the boot timeout elapses. On
// the failure paths it cancels the run context and tears down the
// upstream test server before t.Fatal'ing.
func waitForListening(t *testing.T, addrCh <-chan string, runErrCh <-chan error, runCancel context.CancelFunc, upstream *httptest.Server) string {
	t.Helper()
	select {
	case addr := <-addrCh:
		return addr
	case err := <-runErrCh:
		runCancel()
		if upstream != nil {
			upstream.Close()
		}
		t.Fatalf("mcptest: mcpserver.Run exited before listening: %v", err)
	case <-time.After(15 * time.Second):
		runCancel()
		if upstream != nil {
			upstream.Close()
		}
		<-runErrCh
		t.Fatalf("mcptest: timed out waiting for MCP server to start listening")
	}
	return "" // unreachable; t.Fatalf above
}

// makeCleanup returns the Harness.Cleanup callback. Wrapped in a
// sync.Once so callers can safely invoke it multiple times (the
// example in the Issue uses defer h.Cleanup() in addition to
// t.Cleanup, which would otherwise fire the teardown twice).
func makeCleanup(t *testing.T, client *Client, upstream *httptest.Server, runCancel context.CancelFunc, runCtx context.Context, runErrCh <-chan error) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			client.Close()
			if upstream != nil {
				upstream.Close()
			}
			runCancel()
			select {
			case err := <-runErrCh:
				if err != nil && runCtx.Err() == nil {
					t.Errorf("mcptest: mcpserver.Run returned unexpected error: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("mcptest: mcpserver.Run did not exit within 10s of context cancel")
			}
		})
	}
}

// combineErrorText returns a unified error string from a ToolResult.
// Both transport errors (Err) and tool-reported errors (IsError +
// Text) qualify. Empty result means the call succeeded.
func combineErrorText(res ToolResult) string {
	if res.Err != nil {
		return res.Err.Error()
	}
	if res.IsError {
		return res.Text
	}
	return ""
}

// contains is a thin wrapper that lets tests inject a different match
// strategy in the future without changing the call sites.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return indexOf(haystack, needle) >= 0
}

// indexOf is a minimal substring search; we avoid pulling in strings
// here so the harness package's import surface stays small. Equivalent
// to strings.Index — kept inline for readability of the substring
// search choice.
func indexOf(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// generateToken returns a 64-character hex string suitable for the MCP
// HTTP Bearer token. Mirrors mcp.GenerateToken's format so the token
// is indistinguishable from one generated by the production server.
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
