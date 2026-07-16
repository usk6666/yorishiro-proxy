// Package tlsfingerprint computes JA3 and JA4 client fingerprints from a
// raw TLS ClientHello record.
//
// The package is deliberately self-contained and stdlib-only (crypto/md5,
// crypto/sha256, encoding/hex): it parses the ClientHello independently of
// the connector's SNI/ALPN peek parser so it can be unit-tested against
// captured wire bytes and reused from any data-path peek site.
//
// Wire-fidelity contract (CLAUDE.md MITM Principle #3): the input byte
// slice is never mutated. JA3 preserves the wire order of ciphers,
// extensions, curves, and point formats. JA4's internal SORTING of ciphers
// and extensions is part of the published JA4 definition and produces
// derived data only — the caller's raw bytes and the JA3 view are untouched.
//
// Fail-soft contract (MITM Principle #5): a truncated or malformed
// ClientHello yields empty fingerprints ("", "") rather than a panic or a
// hard error. Callers treat an empty result as "no fingerprint observed",
// consistent with the connector's SNI/ALPN fallback behaviour.
//
// References:
//   - JA3: https://github.com/salesforce/ja3 (SSLVersion,Ciphers,Extensions,
//     EllipticCurves,EllipticCurvePointFormats — decimal, GREASE removed,
//     wire order; MD5 of the joined string).
//   - JA4 (TLS client): https://github.com/FoxIO-LLC/ja4 (JA4_a metadata,
//     JA4_b = truncated SHA256 of the sorted cipher list, JA4_c = truncated
//     SHA256 of the sorted extension list (SNI + ALPN excluded) plus the
//     signature-algorithm list in wire order). Hand-rolled here; the FoxIO
//     reference library is not imported because its JA4+ suite carries the
//     FoxIO-1.1 licence.
package tlsfingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// TLS record / handshake framing constants.
const (
	recordHeaderLen        = 5
	contentTypeHandshake   = 0x16
	handshakeTypeClientHi  = 0x01
	handshakeHeaderLen     = 4
	legacyVersionRandomLen = 2 + 32
)

// Extension type constants relevant to fingerprinting (IANA-assigned).
const (
	extServerName          = 0x0000 // RFC 6066
	extSupportedGroups     = 0x000a // RFC 8422 (a.k.a. elliptic_curves)
	extECPointFormats      = 0x000b // RFC 8422
	extSignatureAlgorithms = 0x000d // RFC 8446
	extALPN                = 0x0010 // RFC 7301
	extSupportedVersions   = 0x002b // RFC 8446
)

// Compute parses a raw TLS ClientHello record (including the 5-byte TLS
// record header) and returns the client's JA3 and JA4 fingerprints.
//
// On any truncation or malformation both return values are empty strings;
// Compute never panics on attacker-controlled input.
func Compute(record []byte) (ja3, ja4 string) {
	hello, ok := clientHelloBody(record)
	if !ok {
		return "", ""
	}
	f, ok := parseClientHello(hello)
	if !ok {
		return "", ""
	}
	return f.ja3(), f.ja4()
}

// isGREASE reports whether v is one of the 16 GREASE values defined by
// RFC 8701 (0x0a0a, 0x1a1a, ... 0xfafa): the high byte equals the low byte
// and each nibble of the low byte is 0xA.
func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// clientHelloBody validates the TLS record and Handshake headers and returns
// the ClientHello body (the bytes after the 4-byte Handshake header, sized by
// the Handshake length field). ok is false on any framing truncation or when
// the record is not a Handshake/ClientHello.
func clientHelloBody(record []byte) (hello []byte, ok bool) {
	if len(record) < recordHeaderLen {
		return nil, false
	}
	if record[0] != contentTypeHandshake {
		return nil, false
	}
	recordLen := int(record[3])<<8 | int(record[4])
	body := record[recordHeaderLen:]
	if recordLen <= 0 || len(body) < recordLen {
		return nil, false
	}
	body = body[:recordLen]

	if len(body) < handshakeHeaderLen {
		return nil, false
	}
	if body[0] != handshakeTypeClientHi {
		return nil, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hs := body[handshakeHeaderLen:]
	if hsLen <= 0 || len(hs) < hsLen {
		return nil, false
	}
	return hs[:hsLen], true
}

// fields holds the decoded ClientHello values needed for JA3 / JA4.
type fields struct {
	legacyVersion uint16
	ciphers       []uint16 // GREASE removed, wire order
	extensions    []uint16 // GREASE removed, wire order
	curves        []uint16 // supported_groups, GREASE removed, wire order
	pointFormats  []uint16 // ec_point_formats, wire order
	sigAlgs       []uint16 // signature_algorithms, GREASE removed, wire order
	highestVer    uint16   // from supported_versions, else legacyVersion
	hasSNI        bool
	firstALPN     string
}

// parseClientHello decodes the ClientHello body into fields. ok is false when
// the fixed structure (version, session_id, cipher_suites, compression,
// extensions block) is truncated. Individual extension internals are parsed
// fail-soft: a malformed inner extension contributes no values rather than
// aborting the whole fingerprint.
func parseClientHello(hello []byte) (fields, bool) {
	var f fields
	c := cursor{b: hello}

	ver, ok := c.uint16()
	if !ok {
		return f, false
	}
	f.legacyVersion = ver
	f.highestVer = ver

	if !c.skip(32) { // Random
		return f, false
	}
	if _, ok := c.vector(1); !ok { // legacy_session_id
		return f, false
	}
	cipherBytes, ok := c.vector(2) // cipher_suites
	if !ok {
		return f, false
	}
	f.ciphers = filterGREASE(uint16List(cipherBytes))
	if _, ok := c.vector(1); !ok { // legacy_compression_methods
		return f, false
	}

	// Extensions block is optional (legal for very old ClientHellos). When
	// absent we still produce a fingerprint from the fields gathered so far.
	extBlock, ok := c.vector(2)
	if !ok {
		if c.remaining() == 0 {
			return f, true
		}
		return f, false
	}
	if !parseExtensions(extBlock, &f) {
		return f, false
	}
	return f, true
}

// parseExtensions walks the extensions block, recording extension types in
// wire order (GREASE removed) and decoding the extensions relevant to the
// fingerprint. Returns false only when the extension framing itself is
// truncated (an extension claims more data than remains).
func parseExtensions(block []byte, f *fields) bool {
	c := cursor{b: block}
	for c.remaining() > 0 {
		extType, ok := c.uint16()
		if !ok {
			return false
		}
		data, ok := c.vector(2)
		if !ok {
			return false
		}
		if isGREASE(extType) {
			continue
		}
		f.extensions = append(f.extensions, extType)

		switch extType {
		case extServerName:
			f.hasSNI = true
		case extSupportedGroups:
			f.curves = filterGREASE(uint16Vector(data, 2))
		case extECPointFormats:
			f.pointFormats = uint16Bytes(vectorPayload(data, 1))
		case extSignatureAlgorithms:
			f.sigAlgs = filterGREASE(uint16Vector(data, 2))
		case extALPN:
			f.firstALPN = firstALPNProtocol(data)
		case extSupportedVersions:
			if hv, ok := highestVersion(data); ok {
				f.highestVer = hv
			}
		}
	}
	return true
}

// ja3 builds the JA3 string and returns its MD5 hex digest. Returns "" when
// no cipher/extension data was observed at all (an all-empty ClientHello is
// not a meaningful fingerprint).
func (f fields) ja3() string {
	if len(f.ciphers) == 0 && len(f.extensions) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(f.legacyVersion)))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(f.ciphers))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(f.extensions))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(f.curves))
	sb.WriteByte(',')
	sb.WriteString(joinDecimal(f.pointFormats))

	sum := md5.Sum([]byte(sb.String())) //nolint:gosec // JA3 is defined as MD5
	return hex.EncodeToString(sum[:])
}

// ja4 builds the JA4 (TLS client) fingerprint: JA4_a_JA4_b_JA4_c.
func (f fields) ja4() string {
	if len(f.ciphers) == 0 && len(f.extensions) == 0 {
		return ""
	}
	return f.ja4a() + "_" + f.ja4b() + "_" + f.ja4c()
}

// ja4a builds the human-readable JA4_a section.
func (f fields) ja4a() string {
	sni := "i"
	if f.hasSNI {
		sni = "d"
	}
	alpn := "00"
	if f.firstALPN != "" {
		first := f.firstALPN[0]
		last := f.firstALPN[len(f.firstALPN)-1]
		alpn = string([]byte{first, last})
	}
	return fmt.Sprintf("t%s%s%s%s%s",
		ja4Version(f.highestVer),
		sni,
		count2(len(f.ciphers)),
		count2(len(f.extensions)),
		alpn,
	)
}

// ja4b builds the JA4_b section: truncated SHA256 of the SORTED cipher list.
func (f fields) ja4b() string {
	if len(f.ciphers) == 0 {
		return "000000000000"
	}
	return sha256Trunc12(strings.Join(sortedHex(f.ciphers), ","))
}

// ja4c builds the JA4_c section: truncated SHA256 of the SORTED extension
// list (SNI 0x0000 and ALPN 0x0010 excluded) joined with an underscore to
// the signature-algorithm list in wire order.
func (f fields) ja4c() string {
	extsForC := make([]uint16, 0, len(f.extensions))
	for _, e := range f.extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		extsForC = append(extsForC, e)
	}
	raw := strings.Join(sortedHex(extsForC), ",") + "_" + strings.Join(hexList(f.sigAlgs), ",")
	return sha256Trunc12(raw)
}

// ---- small helpers ----

// cursor is a bounds-checked forward reader over a byte slice.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) skip(n int) bool {
	if n < 0 || c.remaining() < n {
		return false
	}
	c.pos += n
	return true
}

func (c *cursor) uint16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := uint16(c.b[c.pos])<<8 | uint16(c.b[c.pos+1])
	c.pos += 2
	return v, true
}

// vector reads a length-prefixed region (prefixLen is 1 or 2 bytes) and
// returns its payload, advancing past it.
func (c *cursor) vector(prefixLen int) ([]byte, bool) {
	if c.remaining() < prefixLen {
		return nil, false
	}
	var n int
	switch prefixLen {
	case 1:
		n = int(c.b[c.pos])
	case 2:
		n = int(c.b[c.pos])<<8 | int(c.b[c.pos+1])
	default:
		return nil, false
	}
	start := c.pos + prefixLen
	if start+n > len(c.b) {
		return nil, false
	}
	c.pos = start + n
	return c.b[start : start+n], true
}

// uint16List interprets b as a packed sequence of big-endian uint16 values.
// Trailing odd bytes are ignored (fail-soft).
func uint16List(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

// uint16Bytes interprets b as a packed sequence of single bytes widened to
// uint16 (used for ec_point_formats which are 1-byte enums).
func uint16Bytes(b []byte) []uint16 {
	out := make([]uint16, 0, len(b))
	for _, x := range b {
		out = append(out, uint16(x))
	}
	return out
}

// vectorPayload returns the payload of a length-prefixed region at the start
// of b, or nil when truncated (fail-soft).
func vectorPayload(b []byte, prefixLen int) []byte {
	c := cursor{b: b}
	p, ok := c.vector(prefixLen)
	if !ok {
		return nil
	}
	return p
}

// uint16Vector returns the uint16 list carried in a length-prefixed region at
// the start of b (e.g. supported_groups: 2-byte list length then uint16s).
func uint16Vector(b []byte, prefixLen int) []uint16 {
	return uint16List(vectorPayload(b, prefixLen))
}

// firstALPNProtocol returns the first ProtocolName from an ALPN extension's
// data, or "" when absent/malformed. ALPN data: 2-byte list length, then
// entries of 1-byte name length + name bytes.
func firstALPNProtocol(data []byte) string {
	list := vectorPayload(data, 2)
	c := cursor{b: list}
	name, ok := c.vector(1)
	if !ok || len(name) == 0 {
		return ""
	}
	return string(name)
}

// highestVersion returns the highest non-GREASE version from a
// supported_versions extension (1-byte list length, then uint16 versions).
func highestVersion(data []byte) (uint16, bool) {
	vers := filterGREASE(uint16Vector(data, 1))
	best := uint16(0)
	for _, v := range vers {
		if v > best {
			best = v
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// filterGREASE returns a new slice with RFC 8701 GREASE values removed,
// preserving order. The input slice is never mutated.
func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if isGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// joinDecimal joins values as decimal integers separated by '-'.
func joinDecimal(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

// hexList formats values as 4-digit lowercase hex, preserving order.
func hexList(vals []uint16) []string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return parts
}

// sortedHex formats values as 4-digit lowercase hex and sorts them ascending
// (lexicographic == numeric for zero-padded hex). Input order is preserved
// in the caller's slice; sorting happens on the derived hex copy only.
func sortedHex(vals []uint16) []string {
	parts := hexList(vals)
	sort.Strings(parts)
	return parts
}

// sha256Trunc12 returns the first 12 hex chars of the SHA256 of s.
func sha256Trunc12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// count2 formats n as a zero-padded 2-digit decimal, capped at 99 per the
// JA4 spec.
func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// ja4Version maps a TLS version to its 2-character JA4 code.
func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}
