package tlsfingerprint

import (
	"crypto/tls"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// helloJA3 generates a ClientHello for the given uTLS profile and returns its
// JA3 hash. JA3 normalizes out the per-handshake random fields (client random,
// session id, key shares) and captures the stable wire shape — cipher suites,
// extension list/order, curves, and point formats — which is exactly what
// differs between Firefox parrot versions.
func helloJA3(t *testing.T, id utls.ClientHelloID) string {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uConn := utls.UClient(c1, &utls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	}, id)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState(%s): %v", id.Str(), err)
	}
	raw := uConn.HandshakeState.Hello.Raw // handshake message (type+len+body)
	if len(raw) == 0 {
		t.Fatalf("empty ClientHello raw for %s", id.Str())
	}
	record := concat([]byte{0x16, 0x03, 0x01}, u16(uint16(len(raw))), raw)
	ja3, _ := Compute(record)
	if ja3 == "" {
		t.Fatalf("empty JA3 for %s", id.Str())
	}
	return ja3
}

// TestFirefoxAutoProfilePinnedTo120 is a DRIFT DETECTOR for USK-1014.
//
// uTLS v1.8.2 (the latest release, pinned in go.mod) ships no Firefox parrot
// newer than HelloFirefox_120 (2023-11), and aliases HelloFirefox_Auto to it.
// FF120 is therefore the ceiling of the Firefox TLS fingerprint the proxy can
// present: coherent with a real Firefox 120 JA3, but older than the FF~150 UA
// that camoufox advertises. See docs/rfc/envelope.md §3.4.3 "Known limitations"
// and §11 for the residual-coherence rationale and re-open trigger.
//
// This test pins HelloFirefox_Auto to the FF120 wire shape via an
// observable property (the JA3 of the generated ClientHello), NOT the symbol
// name. When a future uTLS bump adds a Firefox parrot newer than 120,
// HelloFirefox_Auto will re-alias to it and its JA3 will diverge from the
// explicit HelloFirefox_120 pin, breaking this test.
//
// A FAILURE HERE MEANS: uTLS now ships a newer Firefox parrot — revisit
// USK-1014. Bumping the parrot narrows/closes the residual coherence gap
// documented in §3.4.3, and the H2 send-shape pin in
// internal/layer/http2/fingerprint.go (firefox* constants) should be
// re-captured against the new Firefox version to stay coherent.
func TestFirefoxAutoProfilePinnedTo120(t *testing.T) {
	autoJA3 := helloJA3(t, utls.HelloFirefox_Auto)
	pin120JA3 := helloJA3(t, utls.HelloFirefox_120)

	if autoJA3 != pin120JA3 {
		t.Fatalf("HelloFirefox_Auto JA3 %q != HelloFirefox_120 JA3 %q: "+
			"uTLS now aliases Firefox_Auto to a parrot newer than 120 — "+
			"revisit USK-1014 (FF120 fingerprint ceiling) and re-capture the "+
			"H2 send-shape in internal/layer/http2/fingerprint.go.", autoJA3, pin120JA3)
	}

	// Belt-and-suspenders: the advertised profile version string. This is a
	// less-robust struct-field check (kept secondary to the JA3 wire assertion
	// above) but names the ceiling explicitly for readers of a drift failure.
	if v := utls.HelloFirefox_Auto.Version; v != "120" {
		t.Fatalf("HelloFirefox_Auto.Version = %q, want \"120\": uTLS Firefox "+
			"ceiling moved — revisit USK-1014.", v)
	}
}
