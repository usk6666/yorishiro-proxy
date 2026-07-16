package tlsfingerprint

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// ---- ClientHello builder helpers ----

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func u24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// vec8 / vec16 prepend a 1- / 2-byte big-endian length prefix.
func vec8(payload []byte) []byte  { return append([]byte{byte(len(payload))}, payload...) }
func vec16(payload []byte) []byte { return append(u16(uint16(len(payload))), payload...) }

// ext builds an extension: type(2) + length-prefixed data(2).
func ext(t uint16, data []byte) []byte { return concat(u16(t), vec16(data)) }

// helloOpts configures the synthetic ClientHello builder.
type helloOpts struct {
	includeSNI  bool
	includeALPN bool
	ciphers     []uint16 // raw list (may include GREASE)
	omitCiphers bool
}

// buildClientHello assembles a full TLS ClientHello record (with the 5-byte
// record header) shaped to match the hand-computed golden vectors.
func buildClientHello(o helloOpts) []byte {
	ciphers := o.ciphers
	if ciphers == nil && !o.omitCiphers {
		ciphers = []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	}
	var cipherBytes []byte
	for _, c := range ciphers {
		cipherBytes = append(cipherBytes, u16(c)...)
	}

	sniData := vec16(concat([]byte{0x00}, vec16([]byte("a")))) // one host_name entry "a"
	sgData := vec16(concat(u16(0x0a0a), u16(0x001d), u16(0x0017), u16(0x0018)))
	ecData := vec8([]byte{0x00})
	saData := vec16(concat(u16(0x0403), u16(0x0804), u16(0x0401)))
	alpnData := vec16(concat(vec8([]byte("h2")), vec8([]byte("http/1.1"))))
	svData := vec8(concat(u16(0x0a0a), u16(0x0304), u16(0x0303)))

	var exts []byte
	exts = append(exts, ext(0x1a1a, nil)...) // GREASE
	if o.includeSNI {
		exts = append(exts, ext(0x0000, sniData)...)
	}
	exts = append(exts, ext(0x000a, sgData)...)
	exts = append(exts, ext(0x000b, ecData)...)
	exts = append(exts, ext(0x000d, saData)...)
	if o.includeALPN {
		exts = append(exts, ext(0x0010, alpnData)...)
	}
	exts = append(exts, ext(0x0012, nil)...) // signed_certificate_timestamp
	exts = append(exts, ext(0x002b, svData)...)
	exts = append(exts, ext(0x0033, nil)...) // key_share (empty)

	helloBody := concat(
		u16(0x0303),        // legacy_version
		make([]byte, 32),   // Random
		vec8(nil),          // legacy_session_id (empty)
		vec16(cipherBytes), // cipher_suites
		vec8([]byte{0x00}), // legacy_compression_methods (null)
		vec16(exts),        // extensions
	)

	handshake := concat([]byte{0x01}, u24(len(helloBody)), helloBody)
	return concat([]byte{0x16, 0x03, 0x01}, u16(uint16(len(handshake))), handshake)
}

func TestComputeGoldenVector(t *testing.T) {
	// Golden JA3/JA4 computed independently (Python hashlib) from the exact
	// wire fields the builder emits:
	//   JA3 string: 771,4865-4866-4867-49195-49199,0-10-11-13-16-18-43-51,29-23-24,0
	//   JA4_a:      t13d0508h2   (TCP, TLS1.3, SNI present, 5 ciphers, 8 exts, alpn h2)
	//   JA4_b:      sha256("1301,1302,1303,c02b,c02f")[:12]
	//   JA4_c:      sha256("000a,000b,000d,0012,002b,0033_0403,0804,0401")[:12]
	const (
		wantJA3 = "4b808534aaed88ea8efee030f1b46c4d"
		wantJA4 = "t13d0508h2_e133e205ac38_4e31876e0826"
	)
	record := buildClientHello(helloOpts{includeSNI: true, includeALPN: true})
	ja3, ja4 := Compute(record)
	if ja3 != wantJA3 {
		t.Errorf("JA3 = %q, want %q", ja3, wantJA3)
	}
	if ja4 != wantJA4 {
		t.Errorf("JA4 = %q, want %q", ja4, wantJA4)
	}
}

func TestComputeNoSNI(t *testing.T) {
	record := buildClientHello(helloOpts{includeSNI: false, includeALPN: true})
	_, ja4 := Compute(record)
	// SNI absent → JA4_a SNI flag 'i'; ext count drops from 8 to 7.
	if !strings.HasPrefix(ja4, "t13i0507h2_") {
		t.Errorf("JA4 = %q, want prefix t13i0507h2_", ja4)
	}
}

func TestComputeNoALPN(t *testing.T) {
	record := buildClientHello(helloOpts{includeSNI: true, includeALPN: false})
	_, ja4 := Compute(record)
	// ALPN absent → JA4_a alpn chars "00"; ext count drops to 7.
	if !strings.HasPrefix(ja4, "t13d050700_") {
		t.Errorf("JA4 = %q, want prefix t13d050700_", ja4)
	}
}

func TestComputeGREASEExcluded(t *testing.T) {
	// The builder always injects GREASE cipher 0x0a0a and GREASE extension
	// 0x1a1a plus GREASE entries in supported_groups / supported_versions.
	// The golden vector already proves they are stripped (5 ciphers, 8 exts,
	// curves 29-23-24). Here assert isGREASE directly on the RFC 8701 set.
	for _, g := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0xfafa} {
		if !isGREASE(g) {
			t.Errorf("isGREASE(%#04x) = false, want true", g)
		}
	}
	for _, n := range []uint16{0x1301, 0x0000, 0x000a, 0x0a0b, 0x1a2a} {
		if isGREASE(n) {
			t.Errorf("isGREASE(%#04x) = true, want false", n)
		}
	}
}

func TestComputeEmptyCipherList(t *testing.T) {
	// A ClientHello with zero cipher suites → JA4_b sentinel.
	record := buildClientHello(helloOpts{includeSNI: true, includeALPN: true, ciphers: []uint16{}})
	_, ja4 := Compute(record)
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 = %q, want 3 underscore-separated sections", ja4)
	}
	if parts[1] != "000000000000" {
		t.Errorf("JA4_b = %q, want 000000000000 for empty cipher list", parts[1])
	}
	if !strings.HasPrefix(parts[0], "t13d00") {
		t.Errorf("JA4_a = %q, want cipher count 00", parts[0])
	}
}

func TestComputeMalformed(t *testing.T) {
	full := buildClientHello(helloOpts{includeSNI: true, includeALPN: true})
	tests := []struct {
		name   string
		record []byte
	}{
		{"nil", nil},
		{"short header", []byte{0x16, 0x03}},
		{"not handshake", []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
		{"truncated body", full[:len(full)-40]},
		{"truncated mid extensions", full[:60]},
		{"handshake type not clienthello", func() []byte {
			c := append([]byte(nil), full...)
			c[recordHeaderLen] = 0x02 // ServerHello
			return c
		}()},
		{"zero record length", []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ja3, ja4 := Compute(tt.record)
			if ja3 != "" || ja4 != "" {
				t.Errorf("Compute(%s) = (%q, %q), want empty", tt.name, ja3, ja4)
			}
		})
	}
}

func TestComputeDeterministic(t *testing.T) {
	record := buildClientHello(helloOpts{includeSNI: true, includeALPN: true})
	ja3a, ja4a := Compute(record)
	ja3b, ja4b := Compute(record)
	if ja3a != ja3b || ja4a != ja4b {
		t.Errorf("non-deterministic: (%q,%q) vs (%q,%q)", ja3a, ja4a, ja3b, ja4b)
	}
	// Input must not be mutated by Compute (wire-fidelity).
	before := append([]byte(nil), record...)
	Compute(record)
	if string(before) != string(record) {
		t.Error("Compute mutated its input slice")
	}
}

// TestComputeRealFirefoxHello runs the parser against a genuine
// utls-generated Firefox ClientHello. It asserts the JA4_a metadata prefix
// (t = TCP, 13 = TLS 1.3, d = SNI present) and that both fingerprints are
// non-empty and stable — a realism check beyond the synthetic golden vector.
func TestComputeRealFirefoxHello(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uConn := utls.UClient(c1, &utls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	}, utls.HelloFirefox_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	raw := uConn.HandshakeState.Hello.Raw // handshake message (type+len+body)
	if len(raw) == 0 {
		t.Fatal("empty ClientHello raw")
	}
	record := concat([]byte{0x16, 0x03, 0x01}, u16(uint16(len(raw))), raw)

	ja3, ja4 := Compute(record)
	if ja3 == "" || ja4 == "" {
		t.Fatalf("empty fingerprints for real Firefox hello: ja3=%q ja4=%q", ja3, ja4)
	}
	if len(ja3) != 32 {
		t.Errorf("JA3 = %q, want 32-char md5 hex", ja3)
	}
	if !strings.HasPrefix(ja4, "t13d") {
		t.Errorf("JA4 = %q, want t13d prefix (TCP/TLS1.3/SNI)", ja4)
	}
	// JA4 shape: t<ver><sni><cc><ec><alpn>_<12hex>_<12hex>
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("JA4 = %q, malformed section lengths", ja4)
	}
}
