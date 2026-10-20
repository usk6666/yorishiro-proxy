package connector

import (
	"fmt"
	"net"
)

// UpstreamTarget is the input of BuildConnectionStack: it keeps "where the
// proxy dials upstream" apart from "which TLS name the MITM speaks" (USK-1315).
//
// CONNECT and SOCKS5 carry a single authority and pass it as both fields
// (SameUpstreamTarget), so every derivation is unchanged for them. A
// transparent listener dials the original destination IP:port while the
// TLS name comes from the client's ClientHello SNI, so the two differ.
//
// Both fields are "host:port" authorities and are used verbatim — no case
// folding, no bracket rewriting (MITM Principle #1). The routing table:
//
//   - Dial: the upstream TCP dial (and the upstream-proxy CONNECT authority
//     when an upstream proxy is configured), ContextWithDialTarget (the
//     per_target_host rotation key), EnvelopeContext.TargetHost on both legs,
//     the h2 pool key's HostPort and the ALPN cache key's HostPort.
//   - TLS: the client-facing MITM certificate name, the upstream TLS
//     ServerName, per-host TLS overrides (resolvePerHostTLS),
//     raw_passthrough_hosts / TLS passthrough name matching, the h2 pool
//     key's ServerName ("sn") and the ALPN cache key's ServerName.
type UpstreamTarget struct {
	// Dial is the "host:port" the proxy connects to upstream.
	Dial string
	// TLS is the "host:port" TLS authority. Its host part names the MITM
	// certificate and the upstream SNI; the whole authority is what
	// raw_passthrough_hosts is matched against.
	TLS string
}

// SameUpstreamTarget returns an UpstreamTarget that dials target and uses
// target as its TLS authority — the CONNECT / SOCKS5 shape, where the
// client named a single authority.
func SameUpstreamTarget(target string) UpstreamTarget {
	return UpstreamTarget{Dial: target, TLS: target}
}

// tlsAuthority returns the "host:port" authority every TLS-name decision is
// keyed on.
func (ut UpstreamTarget) tlsAuthority() string {
	// Red-commit scaffold (USK-1315): every TLS-name decision still reads
	// the dial target. The routing commit returns ut.TLS.
	return ut.Dial
}

// tlsHost returns the host part of the TLS authority (the MITM certificate
// name and the upstream ServerName). An authority without a port is
// returned as-is, matching extractHost.
func (ut UpstreamTarget) tlsHost() string {
	return extractHost(ut.tlsAuthority())
}

// validate splits both authorities with net.SplitHostPort and fails closed
// when either is not a well-formed "host:port". There is no fallback from
// one field to the other: a missing TLS authority is an error, never a
// silent "use the dial target". The dial error keeps the pre-USK-1315
// "connector: invalid target" shape. Host emptiness is not re-checked here:
// the CONNECT / SOCKS5 scope gates already reject it before the builder
// runs, and this refactor does not change what the builder accepts.
// Returns the TLS host on success.
func (ut UpstreamTarget) validate() (string, error) {
	if _, _, err := net.SplitHostPort(ut.Dial); err != nil {
		return "", fmt.Errorf("connector: invalid target %q: %w", ut.Dial, err)
	}
	tlsHost, _, err := net.SplitHostPort(ut.tlsAuthority())
	if err != nil {
		return "", fmt.Errorf("connector: invalid TLS authority %q: %w", ut.tlsAuthority(), err)
	}
	return tlsHost, nil
}

// isRawPassthrough reports whether the TLS authority is listed in
// raw_passthrough_hosts. Shared by BuildConnectionStack and the CONNECT /
// SOCKS5 handlers so the name decision is made in one place.
func (ut UpstreamTarget) isRawPassthrough(cfg *BuildConfig) bool {
	if cfg == nil || cfg.ProxyConfig == nil {
		return false
	}
	return cfg.ProxyConfig.IsRawPassthrough(ut.tlsAuthority())
}

// UpstreamTargetOf returns the UpstreamTarget stack was built for. Stacks
// that BuildConnectionStack did not build (plain HTTP forward, h2c,
// tcp_forward) carry no split; for them the callback's single target is
// both the dial target and the TLS authority, which is what those builders
// already used it as.
func UpstreamTargetOf(stack *ConnectionStack, target string) UpstreamTarget {
	if stack != nil {
		if ut, ok := stack.UpstreamTarget(); ok {
			return ut
		}
	}
	return SameUpstreamTarget(target)
}
