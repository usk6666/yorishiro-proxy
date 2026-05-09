package connector

import (
	"errors"
	"fmt"
)

// errClientHelloIncomplete is returned by parseClientHelloSNI when the peek
// buffer does not yet contain a complete ClientHello extension list. The
// caller (PeekClientHelloSNI) should retry the peek with a larger window or
// abandon SNI extraction.
var errClientHelloIncomplete = errors.New("connector: client hello incomplete")

// errNotClientHello is returned when the first byte of the peek buffer is
// not a TLS Handshake content type (0x16) or the inner handshake type is
// not ClientHello (0x01). The proxy treats this as "no SNI to record" and
// proceeds with the relay; the audit flow simply records SNI="".
var errNotClientHello = errors.New("connector: not a TLS ClientHello record")

// tlsContentTypeHandshake is the TLS 1.2/1.3 ContentType byte for handshake
// messages (RFC 8446 §5.1).
const tlsContentTypeHandshake = 0x16

// tlsHandshakeTypeClientHello is the Handshake type for ClientHello
// (RFC 8446 §4).
const tlsHandshakeTypeClientHello = 0x01

// tlsExtensionServerName is the ExtensionType value for the SNI extension
// (RFC 6066 §3, IANA-assigned 0).
const tlsExtensionServerName = 0x0000

// tlsServerNameTypeHostname is the NameType for "host_name" inside the
// server_name extension (RFC 6066 §3).
const tlsServerNameTypeHostname = 0x00

// parseClientHelloSNI extracts the SNI host_name value from a TLS
// ClientHello carried at the start of buf. Returns an empty string with
// nil error when the ClientHello does not include the SNI extension or
// includes it with no host_name entry — both are legal per RFC 6066 and
// must not cause the caller to abort the relay.
//
// Returns errClientHelloIncomplete when buf truncates a length-prefixed
// region; the caller should peek more bytes (up to the configured cap)
// and retry. Returns errNotClientHello when the first byte is not a
// Handshake record or the inner handshake type is not ClientHello — the
// caller treats this as "no SNI" and continues without retry.
//
// Other errors (legacy_version mismatch, malformed TLS record framing)
// are surfaced verbatim for diagnostic logging but never fatal: the
// caller's audit flow records SNI="" and relays the bytes anyway. This
// matches the L4-capable principle — the proxy must remain
// passthrough-faithful even when the first record is junk.
func parseClientHelloSNI(buf []byte) (string, error) {
	hello, err := unwrapClientHelloBody(buf)
	if err != nil {
		return "", err
	}
	exts, err := skipToExtensions(hello)
	if err != nil {
		return "", err
	}
	return findSNIInExtensions(exts)
}

// unwrapClientHelloBody validates the TLS record + Handshake headers and
// returns the ClientHello body bytes (the portion after the 4-byte
// Handshake header, sized by the Handshake.length field).
func unwrapClientHelloBody(buf []byte) ([]byte, error) {
	// TLS record header: 1 byte type, 2 bytes legacy_record_version, 2
	// bytes record length. The record length covers the TLS Plaintext
	// fragment that follows.
	const recordHeaderLen = 5
	if len(buf) < recordHeaderLen {
		return nil, errClientHelloIncomplete
	}
	if buf[0] != tlsContentTypeHandshake {
		return nil, errNotClientHello
	}
	recordLen := int(buf[3])<<8 | int(buf[4])
	if recordLen <= 0 {
		return nil, fmt.Errorf("connector: TLS record length %d", recordLen)
	}
	body := buf[recordHeaderLen:]
	if len(body) < recordLen {
		return nil, errClientHelloIncomplete
	}
	body = body[:recordLen]

	// Handshake header: 1 byte msg_type, 3 bytes length.
	const handshakeHeaderLen = 4
	if len(body) < handshakeHeaderLen {
		return nil, errClientHelloIncomplete
	}
	if body[0] != tlsHandshakeTypeClientHello {
		return nil, errNotClientHello
	}
	handshakeLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if handshakeLen <= 0 {
		return nil, fmt.Errorf("connector: handshake length %d", handshakeLen)
	}
	hello := body[handshakeHeaderLen:]
	if len(hello) < handshakeLen {
		return nil, errClientHelloIncomplete
	}
	return hello[:handshakeLen], nil
}

// skipToExtensions advances past the fixed-size and length-prefixed fields
// at the start of a ClientHello body and returns the extensions block
// (the portion after the 2-byte extensions length prefix). Returns an
// empty slice + nil error when the body has no extensions block at all
// (legal for older TLS versions / SSLv3 fallbacks).
func skipToExtensions(hello []byte) ([]byte, error) {
	rest := hello
	// legacy_version (2) + Random (32)
	const versionRandomLen = 2 + 32
	if len(rest) < versionRandomLen {
		return nil, errClientHelloIncomplete
	}
	rest = rest[versionRandomLen:]

	// legacy_session_id: 1-byte length + payload
	rest, err := skipLengthPrefixed(rest, 1)
	if err != nil {
		return nil, err
	}
	// cipher_suites: 2-byte length + payload
	rest, err = skipLengthPrefixed(rest, 2)
	if err != nil {
		return nil, err
	}
	// legacy_compression_methods: 1-byte length + payload
	rest, err = skipLengthPrefixed(rest, 1)
	if err != nil {
		return nil, err
	}
	// extensions: 2-byte length + payload
	if len(rest) < 2 {
		// Older TLS / SSLv3 ClientHellos may omit the extension block
		// entirely. Treat as "no SNI" rather than incomplete.
		return nil, nil
	}
	extLen := int(rest[0])<<8 | int(rest[1])
	rest = rest[2:]
	if len(rest) < extLen {
		return nil, errClientHelloIncomplete
	}
	return rest[:extLen], nil
}

// skipLengthPrefixed consumes a length-prefixed region whose length
// integer occupies prefixLen bytes (1 or 2 — the only sizes used in TLS
// ClientHello). Returns the remainder of the buffer after the region or
// errClientHelloIncomplete when the buffer is shorter than the prefix
// indicates.
func skipLengthPrefixed(buf []byte, prefixLen int) ([]byte, error) {
	if len(buf) < prefixLen {
		return nil, errClientHelloIncomplete
	}
	var n int
	switch prefixLen {
	case 1:
		n = int(buf[0])
	case 2:
		n = int(buf[0])<<8 | int(buf[1])
	default:
		return nil, fmt.Errorf("connector: unsupported length prefix size %d", prefixLen)
	}
	rest := buf[prefixLen:]
	if len(rest) < n {
		return nil, errClientHelloIncomplete
	}
	return rest[n:], nil
}

// findSNIInExtensions scans an extensions block for the server_name
// extension and returns its host_name entry, if any. Empty string + nil
// error means "no SNI extension present" or "SNI extension present but
// no host_name entry" — both legal per RFC 6066.
func findSNIInExtensions(exts []byte) (string, error) {
	for len(exts) >= 4 {
		extType := int(exts[0])<<8 | int(exts[1])
		extDataLen := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if len(exts) < extDataLen {
			return "", errClientHelloIncomplete
		}
		extData := exts[:extDataLen]
		exts = exts[extDataLen:]

		if extType != tlsExtensionServerName {
			continue
		}
		return parseServerNameExtension(extData), nil
	}
	return "", nil
}

// parseServerNameExtension returns the host_name value carried in the
// server_name extension data, or an empty string when the extension is
// malformed or carries no host_name entry. The function is deliberately
// fail-soft — the audit flow records SNI="" rather than abort.
func parseServerNameExtension(extData []byte) string {
	// server_name extension layout (RFC 6066 §3):
	//   ServerNameList server_name_list     (2-byte length prefix)
	//   ServerName entries:
	//     NameType name_type                (1 byte; host_name = 0)
	//     opaque HostName<1..2^16-1>        (2-byte length prefix; for host_name)
	if len(extData) < 2 {
		return ""
	}
	listLen := int(extData[0])<<8 | int(extData[1])
	entries := extData[2:]
	if len(entries) < listLen {
		return ""
	}
	entries = entries[:listLen]
	for len(entries) >= 3 {
		nameType := entries[0]
		nameLen := int(entries[1])<<8 | int(entries[2])
		entries = entries[3:]
		if len(entries) < nameLen {
			return ""
		}
		name := entries[:nameLen]
		entries = entries[nameLen:]
		if nameType == tlsServerNameTypeHostname {
			return string(name)
		}
	}
	return ""
}
