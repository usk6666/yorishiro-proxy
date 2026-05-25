package connector

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
)

// buildClientHello assembles a minimal TLS 1.2/1.3 ClientHello with the
// supplied SNI host_name. Layout follows RFC 5246 §7.4.1.2 / RFC 8446
// §4.1.2 / RFC 6066 §3.
//
// The function returns the complete TLS record bytes (5-byte header +
// handshake message) so test cases can feed it directly to
// parseClientHelloSNI.
func buildClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	return buildClientHelloWithExts(t, sni, nil)
}

// buildClientHelloWithExts assembles a TLS ClientHello with optional SNI
// host_name and optional ALPN protocol offer list. Either or both may be
// supplied; passing "" for sni or nil/empty for alpnOffers omits that
// extension entirely. The function returns the complete TLS record bytes.
func buildClientHelloWithExts(t *testing.T, sni string, alpnOffers []string) []byte {
	t.Helper()

	// Random 32 bytes (legacy_random).
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// ClientHello body fields.
	body := []byte{}
	// legacy_version: TLS 1.2 = 0x0303
	body = append(body, 0x03, 0x03)
	// random
	body = append(body, random...)
	// legacy_session_id: empty
	body = append(body, 0x00)
	// cipher_suites: TLS_AES_128_GCM_SHA256 (0x1301), single entry
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	// legacy_compression_methods: null only (0x00), length 1
	body = append(body, 0x01, 0x00)

	// Extensions:
	exts := []byte{}
	if sni != "" {
		// server_name extension data:
		//   server_name_list:
		//     ServerNameList length (2)
		//     [NameType (1) + HostName length (2) + HostName payload]
		serverNameEntry := []byte{tlsServerNameTypeHostname}
		serverNameEntry = append(serverNameEntry,
			byte(len(sni)>>8), byte(len(sni)),
		)
		serverNameEntry = append(serverNameEntry, []byte(sni)...)

		serverNameList := []byte{
			byte(len(serverNameEntry) >> 8), byte(len(serverNameEntry)),
		}
		serverNameList = append(serverNameList, serverNameEntry...)

		// Extension header: type (2) + ext_data length (2)
		exts = append(exts, 0x00, 0x00) // extension_type = server_name
		exts = append(exts,
			byte(len(serverNameList)>>8), byte(len(serverNameList)),
		)
		exts = append(exts, serverNameList...)
	}
	if alpnOffers != nil {
		exts = append(exts, buildALPNExtension(t, alpnOffers)...)
	}
	// Extensions length prefix.
	body = append(body,
		byte(len(exts)>>8), byte(len(exts)),
	)
	body = append(body, exts...)

	// Handshake header: msg_type (1) + length (3)
	handshake := []byte{tlsHandshakeTypeClientHello}
	handshake = append(handshake,
		byte(len(body)>>16), byte(len(body)>>8), byte(len(body)),
	)
	handshake = append(handshake, body...)

	// TLS record header: type (1) + version (2) + length (2)
	record := []byte{tlsContentTypeHandshake, 0x03, 0x01}
	record = append(record,
		byte(len(handshake)>>8), byte(len(handshake)),
	)
	record = append(record, handshake...)
	return record
}

// buildALPNExtension returns the wire bytes for an ALPN extension carrying
// the supplied ProtocolNameList. Layout follows RFC 7301 §3.1.
//
// Passing an empty (non-nil) offers slice produces a well-formed
// extension with a zero-entry ProtocolNameList — legal per RFC 7301.
func buildALPNExtension(t *testing.T, offers []string) []byte {
	t.Helper()

	// ProtocolNameList entries: each is uint8 length + name bytes.
	var entries []byte
	for _, name := range offers {
		if len(name) > 0xff {
			t.Fatalf("ALPN name %q too long for uint8 length prefix", name)
		}
		entries = append(entries, byte(len(name)))
		entries = append(entries, []byte(name)...)
	}
	// ProtocolNameList: uint16 length + entries.
	list := []byte{
		byte(len(entries) >> 8), byte(len(entries)),
	}
	list = append(list, entries...)

	// Extension header: type (2) + ext_data length (2) + ext_data.
	ext := []byte{
		byte(tlsExtensionALPN >> 8), byte(tlsExtensionALPN),
		byte(len(list) >> 8), byte(len(list)),
	}
	ext = append(ext, list...)
	return ext
}

func TestParseClientHelloSNI_PresentHostname(t *testing.T) {
	want := "example.com"
	rec := buildClientHello(t, want)
	got, err := parseClientHelloSNI(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("SNI = %q, want %q", got, want)
	}
}

func TestParseClientHelloSNI_PunycodeHostname(t *testing.T) {
	// Verbatim wire bytes are case- and punycode-preserved.
	want := "xn--bcher-kva.example"
	rec := buildClientHello(t, want)
	got, err := parseClientHelloSNI(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("SNI = %q, want %q", got, want)
	}
}

func TestParseClientHelloSNI_NoSNIExtension(t *testing.T) {
	rec := buildClientHello(t, "")
	got, err := parseClientHelloSNI(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("SNI = %q, want empty", got)
	}
}

func TestParseClientHelloSNI_NotHandshake(t *testing.T) {
	// Application data record (type 0x17).
	rec := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00}
	_, err := parseClientHelloSNI(rec)
	if !errors.Is(err, errNotClientHello) {
		t.Errorf("err = %v, want errNotClientHello", err)
	}
}

func TestParseClientHelloSNI_NotClientHello(t *testing.T) {
	// Handshake record but inner type is ServerHello (0x02).
	rec := []byte{tlsContentTypeHandshake, 0x03, 0x03, 0x00, 0x04,
		0x02, 0x00, 0x00, 0x00, // msg_type=ServerHello, length=0
	}
	_, err := parseClientHelloSNI(rec)
	if !errors.Is(err, errNotClientHello) {
		t.Errorf("err = %v, want errNotClientHello", err)
	}
}

func TestParseClientHelloSNI_TooShort(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{tlsContentTypeHandshake},
		{tlsContentTypeHandshake, 0x03, 0x03}, // missing length
	}
	for i, buf := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			_, err := parseClientHelloSNI(buf)
			if !errors.Is(err, errClientHelloIncomplete) {
				t.Errorf("err = %v, want errClientHelloIncomplete", err)
			}
		})
	}
}

func TestParseClientHelloSNI_TruncatedRecordBody(t *testing.T) {
	// Record header advertises 200 bytes but body is only 4 bytes.
	rec := []byte{tlsContentTypeHandshake, 0x03, 0x03, 0x00, 0xc8,
		0x01, 0x00, 0x00, 0x00, // partial handshake header
	}
	_, err := parseClientHelloSNI(rec)
	if !errors.Is(err, errClientHelloIncomplete) {
		t.Errorf("err = %v, want errClientHelloIncomplete", err)
	}
}

func TestParseClientHelloALPN_OffersInWireOrder(t *testing.T) {
	cases := []struct {
		name   string
		offers []string
	}{
		{name: "browser_shape_h2_http11", offers: []string{"h2", "http/1.1"}},
		{name: "http11_only", offers: []string{"http/1.1"}},
		{name: "h2_only_utls_repro", offers: []string{"h2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := buildClientHelloWithExts(t, "example.com", tc.offers)
			got, err := parseClientHelloALPN(rec)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !stringSlicesEqual(got, tc.offers) {
				t.Errorf("ALPN offers = %v, want %v", got, tc.offers)
			}
		})
	}
}

func TestParseClientHelloALPN_NoALPNExtension(t *testing.T) {
	// SNI present, no ALPN extension at all.
	rec := buildClientHello(t, "example.com")
	got, err := parseClientHelloALPN(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("ALPN offers = %v, want nil", got)
	}
}

func TestParseClientHelloALPN_EmptyProtocolNameList(t *testing.T) {
	// ALPN extension present but ProtocolNameList carries zero entries.
	// Legal per RFC 7301 §3.1 — fail-soft to (nil, nil).
	rec := buildClientHelloWithExts(t, "", []string{})
	got, err := parseClientHelloALPN(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("ALPN offers = %v, want nil", got)
	}
}

func TestParseClientHelloALPN_TruncatedExtensionData(t *testing.T) {
	// Hand-craft a ClientHello whose ALPN extension declares a longer
	// ext_data length than the actual bytes present. We patch the ALPN
	// extension's ext_data length field at the deterministic offset for
	// a no-SNI / single-ALPN record produced by buildClientHelloWithExts.
	rec := buildClientHelloWithExts(t, "", []string{"h2"})

	// Layout of the produced record (no SNI, ALPN only):
	//   [0..4]   TLS record header (5 bytes)
	//   [5..8]   Handshake header (4 bytes)
	//   [9..10]  legacy_version (2 bytes)
	//   [11..42] random (32 bytes)
	//   [43]     legacy_session_id length (1 byte; 0)
	//   [44..47] cipher_suites length+payload (2+2 bytes)
	//   [48..49] compression methods length+payload (1+1 bytes)
	//   [50..51] extensions length (2 bytes)
	//   [52..53] ALPN extension type (0x00 0x10)
	//   [54..55] ALPN ext_data length (the field we patch)
	const alpnExtDataLenOffset = 54
	if len(rec) < alpnExtDataLenOffset+2 {
		t.Fatalf("record too short: %d bytes", len(rec))
	}
	if rec[52] != byte(tlsExtensionALPN>>8) || rec[53] != byte(tlsExtensionALPN) {
		t.Fatalf("ALPN extension not at expected offset; got %x %x", rec[52], rec[53])
	}
	// Inflate the ext_data length far beyond what trails it in the record.
	rec[alpnExtDataLenOffset] = 0xff
	rec[alpnExtDataLenOffset+1] = 0xff

	_, err := parseClientHelloALPN(rec)
	if !errors.Is(err, errClientHelloIncomplete) {
		t.Errorf("err = %v, want errClientHelloIncomplete", err)
	}
}

func TestParseClientHelloALPN_SNIAndALPNIndependent(t *testing.T) {
	// Single ClientHello carries both SNI and ALPN; the two parsers must
	// extract independent fields without interference.
	wantSNI := "example.com"
	wantALPN := []string{"h2", "http/1.1"}
	rec := buildClientHelloWithExts(t, wantSNI, wantALPN)

	gotSNI, err := parseClientHelloSNI(rec)
	if err != nil {
		t.Fatalf("parseClientHelloSNI: unexpected error: %v", err)
	}
	if gotSNI != wantSNI {
		t.Errorf("SNI = %q, want %q", gotSNI, wantSNI)
	}

	gotALPN, err := parseClientHelloALPN(rec)
	if err != nil {
		t.Fatalf("parseClientHelloALPN: unexpected error: %v", err)
	}
	if !stringSlicesEqual(gotALPN, wantALPN) {
		t.Errorf("ALPN offers = %v, want %v", gotALPN, wantALPN)
	}
}

func TestParseClientHelloALPN_NotHandshake(t *testing.T) {
	// Application data record (type 0x17) — propagated from
	// parseClientHelloExtensions / unwrapClientHelloBody.
	rec := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00}
	_, err := parseClientHelloALPN(rec)
	if !errors.Is(err, errNotClientHello) {
		t.Errorf("err = %v, want errNotClientHello", err)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
