package proxybuild

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// alpnOffersForForwardProtocol returns the ALPN advertise list the proxy
// presents to the client during the MITM handshake, derived from the
// operator-declared ForwardConfig.Protocol.
//
// The list is operator-declared (not negotiated from the upstream side):
// forward callers know what protocol they want to terminate as, and the
// post-handshake dispatch arm is selected from the negotiated ALPN. This
// is intentionally different from the live MITM CONNECT path, where the
// ALPN advertise list is derived from the upstream-negotiated protocol so
// the proxy faithfully relays the upstream's choice (CLAUDE.md MITM
// Principle 2: each protocol has its own canonical form).
//
// Mapping:
//
//	"auto"      → ["h2", "http/1.1"]
//	"http"      → ["http/1.1"]
//	"http2"     → ["h2"]
//	"grpc"      → ["h2"]
//	"websocket" → ["http/1.1"]
//	"sse"       → ["http/1.1"]
//	"raw"       → nil (no ALPN extension on the wire)
//
// An unknown value returns nil so a caller that somehow reaches here with
// a non-validated value still gets a working handshake (the post-dispatch
// switch will reject the connection downstream).
func alpnOffersForForwardProtocol(protocol string) []string {
	switch protocol {
	case "", "auto":
		return []string{"h2", "http/1.1"}
	case "http", "websocket", "sse":
		return []string{"http/1.1"}
	case "http2", "grpc":
		return []string{"h2"}
	default:
		return nil
	}
}

// mitmServerConfigForForward builds a *tls.Config suitable for terminating
// the client-side TLS handshake on a TCP forward listener. The returned
// config honours the wire SNI via its GetCertificate callback (Decision
// U1): when the client presents an SNI value, the proxy issues a MITM cert
// for that hostname; when the client omits SNI, the proxy falls back to
// the operator-declared targetHost.
//
// Differences from cert.Issuer.MITMServerConfig (which the live MITM CONNECT
// path uses):
//
//   - The CONNECT path knows the cert hostname authoritatively before the
//     ClientHello arrives (extracted from the CONNECT request line). It is
//     therefore safe to pin the cert hostname server-side and ignore the
//     SNI value. The forward TCP path does NOT have that information — the
//     accepted conn carries no application-layer authority, only the
//     operator's declared Target — so honoring SNI is the only way to
//     produce a cert whose CN/SAN matches the name the client thought it
//     was connecting to.
//
//   - The Issuer-cached *tls.Config is keyed on (hostname, alpnOffers)
//     which assumes a fixed hostname; that does not match the per-handshake
//     SNI-driven dispatch we need here. We build one *tls.Config per
//     forwardEntry lifetime; the cert LRU (cert.Issuer.cache) is still
//     shared so the per-hostname cert is reused across handshakes.
//
// Session-ticket / version-floor / GetCertificate semantics mirror
// cert.Issuer.MITMServerConfig: TLS 1.2 minimum, lazy session ticket key
// (the *tls.Config is reused for the listener's lifetime so the key is
// stable), and a defensive copy of alpnOffers (crypto/tls retains the
// slice).
func mitmServerConfigForForward(issuer *cert.Issuer, targetHost string, alpnOffers []string) *tls.Config {
	// Normalise the fallback hostname so the issuer lookup (which lowercases
	// internally) is performed once at config-build time instead of per
	// handshake.
	fallback := strings.ToLower(strings.TrimSpace(targetHost))

	cfg := &tls.Config{
		// MinVersion floors at TLS 1.2 to match cert.Issuer.MITMServerConfig
		// and the rest of the proxy's TLS surface. All modern clients
		// support TLS 1.2+ (CWE-757).
		MinVersion: tls.VersionTLS12,

		// ClientSessionCache mirrors what crypto/tls auto-initialises on
		// MITMServerConfig — explicit here so the cache size is predictable
		// (small per-listener LRU is enough; clients reconnect with fresh
		// tickets often).
		ClientSessionCache: tls.NewLRUClientSessionCache(64),

		// GetCertificate honors the wire SNI when present. When SNI is
		// empty the fallback (operator-declared Target hostname) is used
		// so a client connecting by IP literal still gets a usable cert.
		// The Issuer's per-hostname cert LRU absorbs all repeat traffic.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(strings.TrimSpace(hello.ServerName))
			if host == "" {
				host = fallback
			}
			if host == "" {
				return nil, fmt.Errorf("proxybuild: mitmServerConfigForForward: empty cert hostname (no SNI and no target fallback)")
			}
			return issuer.GetCertificate(host)
		},
	}
	if len(alpnOffers) > 0 {
		// Defensive copy: tls.Config retains a reference and the caller may
		// reuse / mutate the source slice after this returns.
		cfg.NextProtos = append([]string(nil), alpnOffers...)
	}
	return cfg
}

// targetHostOnly strips the optional ":port" suffix off an operator-declared
// Target. The forward config Target is "host:port" (validated at config
// load); the cert hostname is the host part only.
//
// Falls back to the input verbatim if it does not parse as host:port — this
// is best-effort because the caller has already validated Target.
func targetHostOnly(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

// handleTCPForwardTLSConn is the per-accepted-connection entry for forwards
// that declare TLS=true (USK-915). It runs the client-side TLS MITM
// handshake using a forward-local SNI-honoring *tls.Config, fires the
// (tls, on_handshake, side="server") plugin hook, emits a Warn log when
// the wire SNI differs from the declared Target host, and dispatches the
// TLS-wrapped conn to the existing L7 / L4 handlers based on the
// negotiated ALPN.
//
// Lifecycle:
//
//   - Sanity check that the parent stack's Issuer is wired. CA regen races
//     or a deconfigured listener fall through to a state="error" Stream via
//     buildTLSStackBuildErrorRecorder.
//   - Run tlslayer.Server with the per-entry cached *tls.Config. Any
//     handshake failure is wrapped with connector.ErrClientTLSMITMHandshake
//     and recorded as FailureReason="client_tls_error".
//   - On success, dispatch by negotiated ALPN — "h2" → handleTCPForwardH2Conn
//     with ForwardProtocolHTTP2, "http/1.1" or "" → handleTCPForwardConn
//     with the declared protocol (websocket / sse / http stay on the H1
//     arm; auto resolves into the L7 dispatcher's own peek path).
func (m *Manager) handleTCPForwardTLSConn(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	clientConn net.Conn,
) {
	connID := connector.GenerateConnID()
	clientAddr := clientConn.RemoteAddr().String()
	targetHost := targetHostOnly(entry.target)
	connLogger := m.logger.With(
		"conn_id", connID,
		"remote_addr", clientAddr,
		"name", parentListenerName,
		"port", entry.port,
		"target", entry.target,
		"protocol", entry.protocol,
		"via", "tcp-forward-tls",
	)

	connCtx := connector.ContextWithConnID(ctx, connID)
	connCtx = connector.ContextWithClientAddr(connCtx, clientAddr)
	connCtx = connector.ContextWithListenerName(connCtx, parentListenerName)
	connCtx = connector.ContextWithLogger(connCtx, connLogger)
	connCtx = connector.ContextWithForwardTarget(connCtx, entry.target)

	// Look up the parent Stack from the manager. The forward listener piggy-
	// backs on the parent's FlowStore + plugin engine; if the parent is gone
	// drop the conn cleanly.
	parentStack := m.Stack(parentListenerName)
	if parentStack == nil {
		_ = clientConn.Close()
		connLogger.Debug("tcp forward tls parent listener no longer running; dropping connection")
		return
	}

	// Defensive: the listener-start guard already rejects fc.TLS=true with
	// a nil Issuer, but a CA regen race could deconfigure the Issuer between
	// listener start and per-conn handshake. Fail-soft into the error
	// recorder so the operator sees the issue in the flow store.
	if parentStack.BuildConfig == nil || parentStack.BuildConfig.Issuer == nil {
		_ = clientConn.Close()
		err := fmt.Errorf("proxybuild: tcp forward tls: no CA Issuer configured")
		connLogger.Error("tcp forward tls handshake aborted", "error", err)
		if rec := buildTLSStackBuildErrorRecorder(parentStack.FlowStore, nil, parentListenerName, connLogger); rec != nil {
			rec(connCtx, entry.target, fmt.Errorf("%w: %w", connector.ErrClientTLSMITMHandshake, err))
		}
		return
	}

	alpnOffers := alpnOffersForForwardProtocol(entry.protocol)
	tlsCfg := entry.tlsServerCfg
	if tlsCfg == nil {
		// Listener-start should have constructed and cached the tls.Config.
		// Build one defensively so the per-conn handshake still has a
		// usable config (e.g. tests that exercise this entry without going
		// through startTCPForwardListener).
		tlsCfg = mitmServerConfigForForward(parentStack.BuildConfig.Issuer, targetHost, alpnOffers)
	}

	tlsConn, clientSnap, err := tlslayer.Server(connCtx, clientConn, tlsCfg)
	if err != nil {
		// Wrap with the canonical client-side sentinel so the recorder
		// classifies this as FailureReason="client_tls_error" (matches the
		// live MITM CONNECT path's classification — USK-858).
		wrapped := fmt.Errorf("%w for %s: %w", connector.ErrClientTLSMITMHandshake, entry.target, err)
		connLogger.Debug("tcp forward tls client handshake failed", "error", err)
		if rec := buildTLSStackBuildErrorRecorder(parentStack.FlowStore, nil, parentListenerName, connLogger); rec != nil {
			rec(connCtx, entry.target, wrapped)
		}
		_ = clientConn.Close()
		return
	}

	// Fire the (tls, on_handshake, side="server") plugin hook for parity
	// with the live MITM CONNECT path (stack_builder.go:1161). No-op when
	// the engine is nil.
	fireForwardTLSHandshakeHook(connCtx, parentStack.PluginV2Engine, "server", clientSnap)

	// Warn when the wire SNI differs from the operator-declared Target
	// host. One Warn log per connection — no dedup. Operators that
	// intentionally forward many SNI values to a single Target (rare) can
	// filter on the log key set.
	if clientSnap != nil && clientSnap.SNI != "" && !strings.EqualFold(clientSnap.SNI, targetHost) {
		connLogger.Warn("tcp forward tls: client SNI differs from declared target host",
			"sni", clientSnap.SNI,
			"target_host", targetHost,
		)
	}

	negotiatedALPN := ""
	if clientSnap != nil {
		negotiatedALPN = clientSnap.ALPN
	}

	connLogger.Debug("tcp forward tls handshake complete",
		"alpn", negotiatedALPN,
		"sni", func() string {
			if clientSnap != nil {
				return clientSnap.SNI
			}
			return ""
		}(),
	)

	// Dispatch by negotiated ALPN. The operator-declared protocol determines
	// the advertised list and the post-dispatch filter (websocket/sse
	// expectation, grpc content-type), but the underlying transport arm is
	// chosen by what the client + server actually agreed on.
	m.dispatchForwardTLSByALPN(connCtx, parentListenerName, entry, clientSnap, tlsConn, negotiatedALPN, connLogger)
}

// dispatchForwardTLSByALPN routes a TLS-terminated forward connection to
// the H2 or H1 dispatch arm based on the negotiated ALPN, threading a
// forwardConnOverride that carries the rewritten Protocol and the client
// TLS snapshot. Split out of handleTCPForwardTLSConn so the cyclomatic
// complexity of the parent stays under the lint threshold.
func (m *Manager) dispatchForwardTLSByALPN(
	connCtx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	clientSnap *envelope.TLSSnapshot,
	tlsConn net.Conn,
	negotiatedALPN string,
	connLogger *slog.Logger,
) {
	switch negotiatedALPN {
	case "h2":
		fcOverride := *entry.fc
		if entry.protocol == "grpc" {
			fcOverride.Protocol = "grpc"
		} else {
			fcOverride.Protocol = "http2"
		}
		fcOverride.TLS = false
		override := &forwardConnOverride{
			protocol:          fcOverride.Protocol,
			fc:                &fcOverride,
			tlsTerminated:     true,
			clientTLSSnapshot: clientSnap,
		}
		m.handleTCPForwardH2ConnWithOverride(connCtx, parentListenerName, entry, &fcOverride, override, tlsConn)
	case "http/1.1", "":
		fcOverride := *entry.fc
		fcOverride.Protocol = chooseH1ForwardProtocol(entry.protocol)
		fcOverride.TLS = false
		override := &forwardConnOverride{
			protocol:          fcOverride.Protocol,
			fc:                &fcOverride,
			tlsTerminated:     true,
			clientTLSSnapshot: clientSnap,
		}
		m.handleTCPForwardConnWithOverride(connCtx, parentListenerName, entry, override, tlsConn)
	default:
		connLogger.Warn("tcp forward tls negotiated unexpected ALPN; dropping connection",
			"alpn", negotiatedALPN,
		)
		_ = tlsConn.Close()
	}
}

// chooseH1ForwardProtocol returns the ForwardConfig.Protocol value the H1
// dispatch arm should run with when the negotiated ALPN is http/1.1 (or
// empty — Go's crypto/tls completes the handshake silently when there is
// no ALPN overlap and the client almost certainly speaks HTTP/1.x next).
//
//   - websocket / sse / http / raw / auto / "" — keep the operator-declared
//     protocol so the existing per-arm filter / dispatch (the WS expectation
//     filter, the SSE expectation filter, the auto-peek path) is selected.
//   - http2 / grpc — operator declared a protocol that requires h2 but the
//     client negotiated h1; fall back to plain http so the H1 dispatcher
//     can at least produce sensible envelopes (we cannot synthesise h2
//     frames on an http/1.1 stream).
func chooseH1ForwardProtocol(declared string) string {
	switch declared {
	case "websocket", "sse", "http", "raw", "auto", "":
		return declared
	default:
		return "http"
	}
}

// fireForwardTLSHandshakeHook dispatches the (tls, on_handshake, side=...)
// plugin hook on the forward path. No-op when the engine is nil or the
// snapshot is missing. Errors are swallowed (USK-671 fail-soft); a noisy
// plugin must not break the forward data path.
//
// Mirrors connector.fireTLSHandshakeHook (private to the connector
// package — duplicated here rather than exported because the hook surface
// is a small two-line dispatch and exporting would expand the connector's
// public API beyond what the rest of the codebase needs).
func fireForwardTLSHandshakeHook(ctx context.Context, engine *pluginv2.Engine, side string, snap *envelope.TLSSnapshot) {
	if engine == nil || snap == nil {
		return
	}
	payload := pluginv2.BuildTLSHandshakeDict(side, snap)
	if _, err := engine.FireLifecycle(ctx, pluginv2.ProtoTLS, pluginv2.EventOnHandshake, nil, payload); err != nil {
		slog.WarnContext(ctx, "pluginv2 tls on_handshake hook error",
			"error", err, "side", side)
	}
}

// configureForwardTLS prepares the per-entry MITM tls.Config cache.
// Called at listener start when fc.TLS=true and the parent Issuer is known
// to be non-nil; the cached *tls.Config is reused for every accepted
// connection on this forward entry so crypto/tls's session-ticket key
// stays stable.
//
// Returns an error when no Issuer is configured. Returning an error from
// listener start is the operator-visible failure path; the per-conn
// handler additionally fails-soft for CA regen races (see
// handleTCPForwardTLSConn defensive guard).
func configureForwardTLS(entry *tcpForwardEntry, fc *config.ForwardConfig, issuer *cert.Issuer) error {
	if entry == nil || fc == nil {
		return fmt.Errorf("proxybuild: configureForwardTLS: nil entry / fc")
	}
	if issuer == nil {
		return fmt.Errorf("proxybuild: configureForwardTLS: tls=true requires a configured CA Issuer")
	}
	host := targetHostOnly(fc.Target)
	alpnOffers := alpnOffersForForwardProtocol(fc.Protocol)
	entry.tlsServerCfg = mitmServerConfigForForward(issuer, host, alpnOffers)
	return nil
}
