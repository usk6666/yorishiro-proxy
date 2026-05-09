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

	// Extensions (only SNI when sni != ""):
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
