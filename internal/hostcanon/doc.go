// Package hostcanon holds the host comparison forms shared by the
// host-matching seams of the data path: TargetScope and the per-host
// RateLimiter in internal/connector, the TLS passthrough list, the
// raw passthrough list in internal/config, and the per-host TLS settings
// (host_tls: transport.HostTLSRegistry and connector.HostTLSResolver).
//
// A client may spell one destination several ways ("localhost." and
// "localhost", "[::ffff:127.0.0.1]" and "127.0.0.1", "0:0::1" and "::1").
// A list that names a host must compare those spellings equal or its
// decision depends on how the client happened to write the host. Every
// function here is comparison-only: callers keep dialing, logging,
// recording and storing the host exactly as written (MITM Principle 1).
//
// There are two comparison forms, and the choice between them is a policy
// decision, not a convenience:
//
//   - Fold is the deny-like form. It also folds legacy inet_aton IPv4
//     spellings ("127.1", "2130706433", "0x7f.0.0.1") into dotted-quad,
//     because a libc resolver or an upstream proxy reads them as that
//     address. Folding more spellings onto one key can only tighten a
//     deny or a rate limit, so the over-approximation is safe there.
//   - FoldDialEquivalent is the allow-like form. It folds only spellings
//     verified to dial the same destination, and leaves legacy IPv4
//     spellings verbatim: Go's pure resolver rejects the all-digit ones
//     and looks the others up in DNS, so folding them onto an allow-like
//     entry (one that means less inspection) could exempt a connection
//     that lands somewhere else. Per-host TLS entries use it too
//     (DialEquivalentPatternKey / DialEquivalentLookupKeys): an entry is
//     mixed-direction — a client certificate or tls_verify: false lowers
//     protection toward the named host, a ca_bundle or tls_verify: true
//     raises it — so neither over- nor under-folding is safe there.
//
// The package imports only the standard library so that internal/config,
// internal/connector and internal/connector/transport can all use it
// without an import cycle.
package hostcanon
