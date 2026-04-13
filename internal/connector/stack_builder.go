package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
)

// BuildConfig holds configuration for BuildConnectionStack.
type BuildConfig struct {
	// ProxyConfig is the loaded proxy configuration containing
	// RawPassthroughHosts and TLS settings.
	ProxyConfig *config.ProxyConfig

	// Issuer dynamically generates TLS server certificates for MITM.
	Issuer *cert.Issuer

	// InsecureSkipVerify disables TLS certificate verification on upstream.
	InsecureSkipVerify bool

	// TLSFingerprint selects the uTLS browser fingerprint profile for upstream.
	TLSFingerprint string

	// ClientCert is the global mTLS client certificate for upstream, if any.
	ClientCert *tls.Certificate

	// UpstreamProxy, if non-nil, tunnels upstream connections through an
	// HTTP CONNECT or SOCKS5 proxy.
	UpstreamProxy *url.URL

	// HostTLSResolver resolves per-host TLS overrides (InsecureSkipVerify,
	// ClientCert, RootCAs). Nil means use global settings for all hosts.
	HostTLSResolver *HostTLSResolver
}

// BuildConnectionStack constructs a ConnectionStack for the given CONNECT
// target and client connection, based on per-host configuration policy.
//
// Two modes are supported:
//   - raw_passthrough: client [TLS MITM → ByteChunk], upstream [TLS → ByteChunk]
//   - default (HTTP MITM): client [TLS MITM → HTTP/1.x Layer], upstream [TLS → HTTP/1.x Layer]
//
// The client-side TLS MITM handshake is performed inside this function
// because the stack builder owns the TLS layer decision.
func BuildConnectionStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	if cfg == nil || cfg.ProxyConfig == nil {
		return nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil config")
	}
	if cfg.Issuer == nil {
		return nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil issuer")
	}

	connID := uuid.New().String()

	if cfg.ProxyConfig.IsRawPassthrough(target) {
		return buildRawPassthroughStack(ctx, clientConn, target, connID, cfg)
	}

	return buildHTTPMITMStack(ctx, clientConn, target, connID, cfg)
}

// buildHTTPMITMStack builds a [TLS → HTTP/1.x] stack on both sides.
//
// Client side: TLS MITM server handshake → HTTP/1.x layer (parses requests)
// Upstream side: DialUpstreamRaw → HTTP/1.x layer (parses responses)
func buildHTTPMITMStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	// --- Client-side TLS MITM ---

	mitmCert, err := cfg.Issuer.GetCertificate(host)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{*mitmCert},
	}

	clientTLSConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: client TLS MITM handshake for %s: %w", target, err)
	}

	slog.Debug("connector: client-side MITM handshake complete",
		"target", target,
		"conn_id", connID,
	)

	// --- Upstream TLS ---

	upstreamTLSCfg := &tls.Config{
		ServerName: host,
	}

	insecureSkip := cfg.InsecureSkipVerify
	clientCert := cfg.ClientCert

	// Apply per-host TLS overrides if configured.
	if cfg.HostTLSResolver != nil {
		resolved, resolveErr := cfg.HostTLSResolver.Resolve(target)
		if resolveErr != nil {
			clientTLSConn.Close()
			return nil, nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, resolveErr)
		}
		if resolved != nil {
			if resolved.InsecureSkipVerify != nil {
				insecureSkip = *resolved.InsecureSkipVerify
			}
			if resolved.ClientCert != nil {
				clientCert = resolved.ClientCert
			}
			if resolved.RootCAs != nil {
				upstreamTLSCfg.RootCAs = resolved.RootCAs
			}
		}
	}

	upstreamConn, _, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.TLSFingerprint,
		ClientCert:         clientCert,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      cfg.UpstreamProxy,
	})
	if err != nil {
		clientTLSConn.Close()
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	slog.Debug("connector: upstream connection established",
		"target", target,
		"conn_id", connID,
	)

	// --- Build EnvelopeContext ---

	envCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        clientSnap,
	}

	// --- Build the stack ---

	stack := NewConnectionStack(connID)

	// Client: HTTP/1.x layer over the MITM'd TLS conn (parses requests)
	clientLayer := http1.New(clientTLSConn, connID+"/client", envelope.Send,
		http1.WithScheme("https"),
		http1.WithEnvelopeContext(envCtx),
	)
	stack.PushClient(clientLayer)

	// Upstream: HTTP/1.x layer over the upstream TLS conn (parses responses)
	upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
		http1.WithScheme("https"),
		http1.WithEnvelopeContext(envCtx),
	)
	stack.PushUpstream(upstreamLayer)

	return stack, clientSnap, nil
}

// buildRawPassthroughStack builds a [TLS → ByteChunk] stack on both sides.
//
// Client side: TLS MITM server handshake → ByteChunk layer (reads client→server)
// Upstream side: DialUpstreamRaw → ByteChunk layer (reads server→client)
func buildRawPassthroughStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	// --- Client-side TLS MITM ---

	mitmCert, err := cfg.Issuer.GetCertificate(host)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{*mitmCert},
	}

	clientTLSConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: client TLS MITM handshake for %s: %w", target, err)
	}

	slog.Debug("connector: client-side MITM handshake complete",
		"target", target,
		"conn_id", connID,
	)

	// --- Upstream TLS ---

	upstreamTLSCfg := &tls.Config{
		ServerName: host,
	}

	insecureSkip := cfg.InsecureSkipVerify
	clientCert := cfg.ClientCert

	// Apply per-host TLS overrides if configured.
	if cfg.HostTLSResolver != nil {
		resolved, resolveErr := cfg.HostTLSResolver.Resolve(target)
		if resolveErr != nil {
			clientTLSConn.Close()
			return nil, nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, resolveErr)
		}
		if resolved != nil {
			if resolved.InsecureSkipVerify != nil {
				insecureSkip = *resolved.InsecureSkipVerify
			}
			if resolved.ClientCert != nil {
				clientCert = resolved.ClientCert
			}
			if resolved.RootCAs != nil {
				upstreamTLSCfg.RootCAs = resolved.RootCAs
			}
		}
	}

	upstreamConn, _, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.TLSFingerprint,
		ClientCert:         clientCert,
		// N2: offer http/1.1 only. In raw_passthrough mode ALPN is not
		// critical (bytes are relayed as-is after TLS), but we need a
		// plausible value for the handshake. N6 integrates ALPN cache
		// and can propagate the client's original ALPN offer.
		OfferALPN:     []string{"http/1.1"},
		UpstreamProxy: cfg.UpstreamProxy,
	})
	if err != nil {
		clientTLSConn.Close()
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	slog.Debug("connector: upstream connection established",
		"target", target,
		"conn_id", connID,
	)

	// --- Build the stack ---

	stack := NewConnectionStack(connID)

	// Client: ByteChunk layer over the MITM'd TLS conn (reads client→server)
	clientLayer := bytechunk.New(clientTLSConn, connID+"/client", envelope.Send)
	stack.PushClient(clientLayer)

	// Upstream: ByteChunk layer over the upstream TLS conn (reads server→client)
	upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
	stack.PushUpstream(upstreamLayer)

	return stack, clientSnap, nil
}
