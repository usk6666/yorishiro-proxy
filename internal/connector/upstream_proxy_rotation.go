// upstream_proxy_rotation.go implements upstream-proxy URL template
// expansion and per-listener rotation policy resolution.
//
// Two consumers share this file:
//
//  1. The control-plane resend / fuzz MCP tools (USK-954) call
//     UpstreamProxyConfig.ResolveForIteration once per iteration to expand
//     a §-template into a per-flow override that is attached to ctx via
//     ContextWithUpstreamProxyOverride. The package internal/mcp keeps a
//     thin type alias so the existing MCP wire schema is unchanged.
//
//  2. The live MITM data path (USK-959) consults a per-listener
//     RotationResolver via BuildConfig.EffectiveUpstreamProxyForCtx ahead
//     of the per-listener static URL and the process-global slot. Each
//     listener owns its own resolver instance; multi-listener setups
//     therefore cannot leak rotation state across listeners.
//
// Reserved variables (prefix "__") cannot be set or shadowed by
// user-supplied macros — see internal/macro/reserved.go.
package connector

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// UpstreamProxyConfig is the per-iteration upstream proxy configuration
// for control-plane fuzz / resend MCP tools. Optional — when nil or
// URLTemplate is empty, the iteration uses the default (direct) dial
// path without attaching any upstream-proxy override to ctx.
//
// URLTemplate supports the §var§ macro template syntax with the
// following runtime-reserved variables (always present per iteration):
//
//	§__iteration§ — zero-based iteration index for the current MCP call
//	§__nonce§     — fresh UUID minted per iteration
//
// Reserved variables cannot be overridden by user input. The parsed
// upstream proxy URL must use scheme http:// or socks5:// (validated by
// ParseUpstreamProxy). CRLF guards (CWE-93) apply to the expanded URL
// so a §__nonce§-substituted credential cannot smuggle a
// Proxy-Authorization header injection into the downstream CONNECT
// request.
//
// The struct is intentionally a single-field carrier so future
// extensions (rotation policy, session-id sticky window, error-driven
// rotation) can land as additional optional fields without breaking the
// MCP wire schema.
type UpstreamProxyConfig struct {
	URLTemplate string `json:"url_template,omitempty" jsonschema:"upstream proxy URL template (http:// or socks5://). Supports §var§ macro syntax with reserved variables §__iteration§ (zero-based index) and §__nonce§ (per-iteration UUID) for residential-proxy IP rotation. Example: http://user-session-§__nonce§:password@residential.example:8080"`
}

// ResolveForIteration expands the URL template for iteration N, parses
// the result as an upstream proxy URL, and returns a ctx carrying the
// per-flow override (ContextWithUpstreamProxyOverride). Returns the
// input ctx unchanged when the configuration is nil or URLTemplate is
// empty — the caller falls through to the default dial path.
//
// Errors are returned with the user-facing prefix
// "upstream_proxy.url_template" so MCP tool handlers can surface them
// verbatim.
//
// Each call mints a throwaway kvStore seeded with §__iteration§ /
// §__nonce§. Callers that need to share the per-iteration kvStore with
// other consumers (e.g. fuzz_http's pre/post macro hooks per USK-960)
// should use ResolveForIterationWithKV instead.
func (c *UpstreamProxyConfig) ResolveForIteration(ctx context.Context, iteration int) (context.Context, error) {
	if c == nil || c.URLTemplate == "" {
		return ctx, nil
	}

	kvStore := map[string]string{
		macro.ReservedKeyPrefix + "iteration": strconv.Itoa(iteration),
		macro.ReservedKeyPrefix + "nonce":     uuid.NewString(),
	}

	parsed, err := expandAndParseTemplate(c.URLTemplate, kvStore)
	if err != nil {
		return nil, err
	}

	return ContextWithUpstreamProxyOverride(ctx, parsed), nil
}

// ResolveForIterationWithKV expands the URL template against kvStore
// (which the caller owns), parses the result, and returns a ctx carrying
// the per-flow override. The reserved keys §__iteration§ / §__nonce§
// are written into kvStore by this method before expansion. Both keys
// overwrite any pre-existing values for the same iteration so the
// per-iteration semantics match the throwaway-kvStore behaviour of
// ResolveForIteration. Returns the input ctx unchanged (and leaves
// kvStore untouched) when c is nil or URLTemplate is empty.
//
// Use this entry point when a single kvStore must thread through both
// the upstream proxy expansion and other per-iteration consumers (macro
// hooks, template-substituted fuzz body fields, etc.). The kvStore
// becomes the canonical per-iteration state — extracts from pre macros
// land here, fuzz body §var§ expansion reads from here, and reserved
// keys populated here flow into the upstream proxy URL.
func (c *UpstreamProxyConfig) ResolveForIterationWithKV(ctx context.Context, iteration int, kvStore map[string]string) (context.Context, error) {
	if c == nil || c.URLTemplate == "" {
		return ctx, nil
	}
	if kvStore == nil {
		// Defensive: callers should pass a non-nil store, but a nil here
		// can be recovered transparently by falling back to the legacy
		// throwaway path. Without this the next line would panic.
		return c.ResolveForIteration(ctx, iteration)
	}

	kvStore[macro.ReservedKeyPrefix+"iteration"] = strconv.Itoa(iteration)
	kvStore[macro.ReservedKeyPrefix+"nonce"] = uuid.NewString()

	parsed, err := expandAndParseTemplate(c.URLTemplate, kvStore)
	if err != nil {
		return nil, err
	}

	return ContextWithUpstreamProxyOverride(ctx, parsed), nil
}

// SeedIterationKV writes the per-iteration reserved keys §__iteration§
// and §__nonce§ into kvStore in place. Called by fuzz_http's variant
// loop head to populate the canonical per-iteration kvStore even when no
// upstream-proxy override is configured — pre/post macro hooks and fuzz
// body §var§ expansion need the reserved keys regardless of whether
// upstream rotation is active.
func SeedIterationKV(kvStore map[string]string, iteration int) {
	if kvStore == nil {
		return
	}
	kvStore[macro.ReservedKeyPrefix+"iteration"] = strconv.Itoa(iteration)
	kvStore[macro.ReservedKeyPrefix+"nonce"] = uuid.NewString()
}

// expandAndParseTemplate performs macro expansion, CRLF guard, and
// ParseUpstreamProxy on the supplied template against kvStore. Returns
// errors with the "upstream_proxy.url_template" prefix so callers can
// surface them verbatim. Shared by ResolveForIteration (MCP control
// plane) and RotationResolver.Resolve (live data path) so both surfaces
// fail with the same diagnostic shape.
func expandAndParseTemplate(template string, kvStore map[string]string) (*url.URL, error) {
	expanded, err := macro.ExpandTemplate(template, kvStore)
	if err != nil {
		return nil, fmt.Errorf("upstream_proxy.url_template: expand: %w", err)
	}

	if strings.ContainsAny(expanded, "\r\n") {
		return nil, fmt.Errorf("upstream_proxy.url_template: expanded URL contains CR/LF (CWE-93 guard)")
	}

	parsed, err := ParseUpstreamProxy(expanded)
	if err != nil {
		return nil, fmt.Errorf("upstream_proxy.url_template: %w", err)
	}
	return parsed, nil
}

// RotationPolicy controls how often a RotationResolver mints a fresh
// upstream-proxy URL from its template.
type RotationPolicy string

const (
	// RotationPerRequest expands the template at every outbound TCP dial
	// for the listener. For HTTP/2 this means once per dialled upstream
	// connection — the dial is the rotation event, not the individual
	// h2 stream (multiple streams multiplex onto a single TCP dial).
	// Operators wanting per-stream rotation must either disable HTTP/2
	// connection pooling or use per_connection scoping on a listener
	// that only ever speaks HTTP/1.
	RotationPerRequest RotationPolicy = "per_request"

	// RotationPerConnection caches the expanded URL per inbound proxy
	// connection (keyed by ConnID). All outbound dials triggered by the
	// same client connection share the URL; a new client connection
	// (and therefore a new ConnID) mints a fresh URL. State is dropped
	// when the connector closes the ConnectionStack — i.e. when the
	// client disconnects.
	RotationPerConnection RotationPolicy = "per_connection"

	// RotationPerTargetHost caches the expanded URL per (listener,
	// target host) pair. All connections to the same upstream host
	// observe the same URL until the LRU TTL expires; distinct upstream
	// hosts get distinct URLs. Useful for sticky-by-target rotation
	// (e.g. one residential IP per session per upstream).
	RotationPerTargetHost RotationPolicy = "per_target_host"

	// RotationSticky mints the URL once for the listener's lifetime and
	// then reuses it for every subsequent dial. Reload via configure_tool
	// (or proxy_start) clears the sticky value so the next dial mints
	// fresh. Useful for "one residential IP per listener until I say
	// rotate".
	RotationSticky RotationPolicy = "sticky"
)

// String returns the policy as its wire-format string.
func (p RotationPolicy) String() string { return string(p) }

// IsValid reports whether p matches one of the four supported policies.
func (p RotationPolicy) IsValid() bool {
	switch p {
	case RotationPerRequest, RotationPerConnection, RotationPerTargetHost, RotationSticky:
		return true
	}
	return false
}

// DefaultRotationPerHostCacheSize / DefaultRotationPerHostCacheTTL bound the
// per-target-host cache. Defaults mirror the ALPNCache shape so an operator
// pattern is familiar: 10000 hosts × 1h TTL covers a long browsing session
// before a stale cached URL forces a re-mint.
const (
	DefaultRotationPerHostCacheSize = 10_000
	DefaultRotationPerHostCacheTTL  = time.Hour
)

// RotationConfig describes a single rotation resolver: the template plus
// the policy. ListenerName is informational and used in slog warnings on
// fail-closed events.
type RotationConfig struct {
	// Template is the §-template URL. Must expand to a valid upstream
	// proxy URL after substitution.
	Template string

	// Policy selects how often the template is expanded.
	Policy RotationPolicy

	// ListenerName is included in log records on fail-closed events so
	// operators can correlate the warning to a specific listener. Empty
	// is permitted.
	ListenerName string
}

// RotationResolver evaluates a RotationConfig per dial event. Methods
// are safe for concurrent use; state caches are per-resolver so two
// listeners with the same template still mint independent nonces.
//
// The resolver is intentionally separate from BuildConfig so a single
// BuildConfig can carry a different resolver per listener without
// per-site map lookups on the hot dial path — proxybuild assembles the
// resolver and installs it via BuildConfig.SetRotationForListener.
type RotationResolver struct {
	cfg RotationConfig

	// perConn caches URLs by ConnID for the RotationPerConnection policy.
	// Entries are deleted from ReleaseConnection when the connector
	// closes the ConnectionStack.
	perConn sync.Map // map[string]*url.URL

	// perTargetHost caches URLs by target host for the
	// RotationPerTargetHost policy. Uses the ALPNCache-shape LRU+TTL
	// pattern; entries expire lazily when the LRU is full.
	perTargetHost *rotationHostCache

	// sticky stores the lifetime-of-listener URL for RotationSticky.
	// Protected by stickyMu.
	stickyMu sync.RWMutex
	sticky   *url.URL
}

// NewRotationResolver constructs a RotationResolver. cfg.Template is
// not validated here; the proxybuild layer probe-expands at config
// apply time. Resolve performs the per-dial expansion and surfaces any
// expansion / parse / CRLF guard error to the caller.
//
// hostCacheSize / hostCacheTTL bound the per-target-host cache. Zero
// values fall back to DefaultRotationPerHostCacheSize /
// DefaultRotationPerHostCacheTTL respectively.
func NewRotationResolver(cfg RotationConfig, hostCacheSize int, hostCacheTTL time.Duration) *RotationResolver {
	if hostCacheSize <= 0 {
		hostCacheSize = DefaultRotationPerHostCacheSize
	}
	if hostCacheTTL <= 0 {
		hostCacheTTL = DefaultRotationPerHostCacheTTL
	}
	return &RotationResolver{
		cfg:           cfg,
		perTargetHost: newRotationHostCache(hostCacheSize, hostCacheTTL),
	}
}

// Policy returns the resolver's rotation policy. Read by
// status surfaces (ListenerStatus.UpstreamProxyRotationPolicy).
func (r *RotationResolver) Policy() RotationPolicy {
	if r == nil {
		return ""
	}
	return r.cfg.Policy
}

// Template returns the resolver's URL template verbatim. Use
// RedactProxyURL before surfacing to operators; the template carries
// userinfo macros that may resolve to credentials.
func (r *RotationResolver) Template() string {
	if r == nil {
		return ""
	}
	return r.cfg.Template
}

// Resolve picks (or mints) the upstream proxy URL for the next dial
// triggered by a connection on listenerName targeting targetHost. ctx
// is consulted for ConnID (per_connection scope). Returns the URL plus
// nil on success, nil + error on macro expansion / CRLF / parse
// failure. The caller is responsible for fail-closed handling: do NOT
// fall back to direct dial on a non-nil error — that would silently
// bypass the configured upstream proxy.
func (r *RotationResolver) Resolve(ctx context.Context, listenerName, targetHost string) (*url.URL, error) {
	if r == nil {
		return nil, nil
	}

	switch r.cfg.Policy {
	case RotationPerRequest:
		return r.expandFresh()

	case RotationPerConnection:
		connID := ConnIDFromContext(ctx)
		if connID == "" {
			// No ConnID on ctx — fall back to a fresh mint. This is
			// not a programming error: control-plane callers can
			// install a resolver but never set ConnID. Per-conn
			// scope only makes sense on the live data path where
			// FullListener attaches ConnID via ContextWithConnID.
			return r.expandFresh()
		}
		if cached, ok := r.perConn.Load(connID); ok {
			return cached.(*url.URL), nil
		}
		u, err := r.expandFresh()
		if err != nil {
			return nil, err
		}
		// LoadOrStore handles the race where two dials on the same
		// ConnID race here: the loser observes the winner's URL.
		actual, _ := r.perConn.LoadOrStore(connID, u)
		return actual.(*url.URL), nil

	case RotationPerTargetHost:
		// Empty targetHost is unusual (the caller would not normally
		// reach the resolver without a target) but treat it as a
		// fresh-mint fallback rather than a panic-inducing edge.
		if targetHost == "" {
			return r.expandFresh()
		}
		// Use the full "host:port" so distinct services on the same
		// host (e.g. example.com:443 vs example.com:8443) get
		// distinct rotation slots. Operators who want host-level
		// (not service-level) scoping must normalise upstream port
		// configuration; the resolver itself never aggregates.
		if cached, ok := r.perTargetHost.get(targetHost); ok {
			return cached, nil
		}
		u, err := r.expandFresh()
		if err != nil {
			return nil, err
		}
		r.perTargetHost.set(targetHost, u)
		return u, nil

	case RotationSticky:
		r.stickyMu.RLock()
		s := r.sticky
		r.stickyMu.RUnlock()
		if s != nil {
			return s, nil
		}
		u, err := r.expandFresh()
		if err != nil {
			return nil, err
		}
		r.stickyMu.Lock()
		// Recheck under write lock in case a concurrent first-Resolve
		// already set sticky.
		if r.sticky != nil {
			s = r.sticky
			r.stickyMu.Unlock()
			return s, nil
		}
		r.sticky = u
		r.stickyMu.Unlock()
		return u, nil

	default:
		return nil, fmt.Errorf("upstream_proxy.rotation: unknown policy %q", r.cfg.Policy)
	}
}

// ReleaseConnection drops any per-connection state held by the resolver
// for connID. Called from ConnectionStack.Close so per_connection
// entries do not leak after the client disconnects. No-op for policies
// that do not maintain per-conn state.
func (r *RotationResolver) ReleaseConnection(connID string) {
	if r == nil || connID == "" {
		return
	}
	r.perConn.Delete(connID)
}

// Reset clears all resolver-side state caches. Called from
// configure_tool / proxy_start when the operator reloads the rotation
// configuration so the next dial mints fresh. In-flight connections
// keep the URL they already captured; only future dials see the new
// state.
func (r *RotationResolver) Reset() {
	if r == nil {
		return
	}
	r.perConn.Range(func(k, _ any) bool {
		r.perConn.Delete(k)
		return true
	})
	r.perTargetHost.clear()
	r.stickyMu.Lock()
	r.sticky = nil
	r.stickyMu.Unlock()
}

// expandFresh runs the macro expansion + CRLF guard + ParseUpstreamProxy
// against a fresh nonce. Used by every policy that needs a brand-new
// URL (per_request always; per_connection / per_target_host / sticky on
// first-use).
func (r *RotationResolver) expandFresh() (*url.URL, error) {
	kv := map[string]string{
		macro.ReservedKeyPrefix + "nonce": uuid.NewString(),
	}
	return expandAndParseTemplate(r.cfg.Template, kv)
}
