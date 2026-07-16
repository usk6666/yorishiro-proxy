package connector

import (
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/tlsfingerprint"
)

// peekClientHelloSNIAndALPN reads the first TLS record from clientConn
// without consuming it (when the conn is a *PeekConn — every connector
// entry point wraps the inbound conn in PeekConn before dispatching) and
// extracts both the server_name extension's host_name and the offered
// ALPN ProtocolNameList in wire order. The two return slots cover the
// distinct fields the sniff-first MITM path needs:
//
//   - sni: drives the MITM cert lookup (TLS SNI extension is its only
//     wire source; cert presentation must not be guessed).
//   - alpn: forwarded verbatim to upstream so the proxy's MITM advertises
//     the upstream's pick back to the client (RFC 7301 transparency,
//     including the demo1.nextcloud.com RFC 7301 §3.2 violation case).
//
// Failure semantics (fail-soft per CLAUDE.md MITM Principle #5):
//
//   - clientConn is not a *PeekConn (test-only / non-listener path) →
//     return ("", nil).
//   - SetReadDeadline failure (rare; closed conn) → return ("", nil).
//   - Peek failure (timeout / EOF / closed mid-handshake) → return
//     ("", nil). Logged at Debug because these are routine on the wire.
//   - Buffer does not contain a TLS Handshake record (errNotClientHello)
//     or extension block is truncated (errClientHelloIncomplete) →
//     return ("", nil). Both are swallowed silently — they are the
//     canonical "no ClientHello to sniff" sentinels.
//   - Other parse errors → return whatever was extracted so far and
//     log at Debug. The caller's fallback path then handles the gap.
//   - Partial success: SNI extracted but ALPN extension is truncated or
//     malformed → return (sni, nil). This is lossless — the cert
//     presentation path keeps the SNI it needs; the ALPN extension is
//     forwarded as nil so the sniff-first branch falls back to the
//     legacy widening logic for the ALPN axis only. Callers must NOT
//     assume that a non-empty sni implies a non-nil alpn.
//
// The peek is bounded by clientHelloPeekTimeout. Clearing the read
// deadline before return is critical: bufio.Reader.Peek reads from the
// underlying conn under the deadline, and leaving the deadline armed
// would torpedo the subsequent MITM handshake (tlslayer.Server reads
// from the same *PeekConn).
//
// USK-997: sibling of peekClientHelloSNI. The two helpers share the
// peek window + deadline pattern but differ in what they extract;
// keeping them as separate entry points keeps the passthrough hot path
// (which never needs ALPN) on the smaller, one-purpose function.
//
// USK-1015: the peek also computes the client's JA3/JA4 fingerprints from
// the same buffered ClientHello (no extra read, no consumption). The
// fingerprints are pure observation overlay carried on the returned
// ClientHelloPeek; they never steer the build path. When the peek fails,
// the ClientHello is malformed, or it exceeds the peek cap the fingerprint
// fields stay empty — consistent with the SNI/ALPN fallback semantics.
func peekClientHelloSNIAndALPN(clientConn net.Conn) ClientHelloPeek {
	pc, ok := clientConn.(*PeekConn)
	if !ok {
		return ClientHelloPeek{}
	}
	if err := pc.SetReadDeadline(time.Now().Add(clientHelloPeekTimeout)); err != nil {
		slog.Debug("connector: client hello peek deadline arm failed", "error", err)
		return ClientHelloPeek{}
	}
	defer func() {
		// Clear the deadline regardless of peek outcome so the subsequent
		// MITM TLS handshake (tlslayer.Server reads from the same conn)
		// is not torpedoed by a pending timeout.
		_ = pc.SetReadDeadline(time.Time{})
	}()

	// Two-stage peek (USK-997 wire-up gotcha): bufio.Reader.Peek(n) blocks
	// until n bytes are buffered OR an error occurs. Asking for 4096 bytes
	// upfront forces a wait on every connection whose ClientHello is
	// smaller than that, defeating the point of the peek and adding a
	// 5s tax to every MITM handshake (deadline timeout). Instead:
	//   1. Peek the 5-byte TLS record header to learn the record length.
	//   2. Peek exactly recordHeaderLen + recordLen (bounded by the
	//      hard cap clientHelloPeekSize) to get the full ClientHello.
	// This returns immediately once the ClientHello bytes are buffered
	// — the typical case is one short read that yields ~300 bytes —
	// without any timeout-based fallback wait.
	const recordHeaderLen = 5
	headerBuf, err := pc.Peek(recordHeaderLen)
	if err != nil && len(headerBuf) == 0 {
		slog.Debug("connector: client hello header peek failed", "error", err)
		return ClientHelloPeek{}
	}
	if len(headerBuf) < recordHeaderLen {
		// Truncated header — treat as "no ClientHello"; same as the
		// errClientHelloIncomplete fall-through below.
		return ClientHelloPeek{}
	}
	// TLS record length is bytes [3:5] (big-endian uint16).
	recordLen := int(headerBuf[3])<<8 | int(headerBuf[4])
	wantBytes := recordHeaderLen + recordLen
	if wantBytes > clientHelloPeekSize {
		// ClientHello larger than our hard cap — fall back silently
		// (Slowloris safety; Resolved Decision #21). The fingerprint is
		// simply not computed for oversized ClientHellos (USK-1015 known
		// limitation), matching today's SNI/ALPN fallback.
		return ClientHelloPeek{}
	}
	buf, err := pc.Peek(wantBytes)
	if err != nil && len(buf) == 0 {
		// True peek failure (timeout / EOF / closed). Fall back silently
		// so the caller's existing path (cache hit / miss / pool) handles
		// the connection. Debug-logged because routine on the wire.
		slog.Debug("connector: client hello peek failed", "error", err)
		return ClientHelloPeek{}
	}

	// USK-1015: compute JA3/JA4 from the same buffered ClientHello. Pure
	// overlay — the peek leaves the bytes for the real handshake untouched.
	// Fail-soft: a malformed hello yields empty fingerprints.
	ja3, ja4 := tlsfingerprint.Compute(buf)

	// Parse extensions block once via the shared helper (USK-996 extracted
	// this seam specifically so SNI + ALPN share the TLS framing dance).
	exts, extErr := parseClientHelloExtensions(buf)
	if extErr != nil {
		if !errors.Is(extErr, errNotClientHello) && !errors.Is(extErr, errClientHelloIncomplete) {
			slog.Debug("connector: client hello extensions parse failed",
				"error", extErr, "buffered", len(buf))
		}
		// Even when SNI/ALPN extraction fails we may still have valid
		// fingerprints (e.g. a hello with no extensions block). Return them
		// so ALPN-less / HTTP/1.1-only clients still get JA3/JA4.
		return ClientHelloPeek{ClientJA3: ja3, ClientJA4: ja4}
	}

	// SNI: empty (no extension) and parse error both fold into "" — the
	// findSNIInExtensions contract returns ("", nil) for "no SNI" and a
	// non-nil error only on truncation. Treat truncation as no-SNI to
	// preserve the caller's fallback behaviour.
	sni, sniErr := findSNIInExtensions(exts)
	if sniErr != nil {
		slog.Debug("connector: client hello SNI parse failed",
			"error", sniErr, "buffered", len(buf))
		sni = ""
	}

	// ALPN: similarly fail-soft. A truncated ALPN extension data block
	// surfaces as errClientHelloIncomplete from parseALPNExtension; we
	// keep whatever SNI we found and report alpn=nil so the caller falls
	// back for the ALPN axis only (User-Confirmed Decision #U3).
	alpnList, alpnErr := findALPNInExtensions(exts)
	if alpnErr != nil {
		slog.Debug("connector: client hello ALPN parse failed",
			"error", alpnErr, "buffered", len(buf))
		alpnList = nil
	}

	return ClientHelloPeek{
		SNI:       sni,
		ALPN:      alpnList,
		ClientJA3: ja3,
		ClientJA4: ja4,
	}
}
