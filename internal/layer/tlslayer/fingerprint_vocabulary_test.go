package tlslayer

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
)

// browserProfileProbeLimit bounds the scan used to enumerate
// transport.BrowserProfile. The constants are declared with iota+1 and no
// explicit values, so a contiguous scan from 1 reaches every one of them
// with generous headroom.
const browserProfileProbeLimit = 32

// TestFingerprintVocabularyMatchesResolutionTables binds the three
// independently-maintained TLS-fingerprint tables together (USK-1032):
//
//  1. config.tlsFingerprintNames — the vocabulary the config file, the
//     -tls-fingerprint CLI flag, and the MCP proxy_start / configure tools
//     accept. Reached here through config.TLSFingerprintNamesList.
//  2. transport.ParseBrowserProfile — the resend / fuzz dial axis.
//  3. tlslayer.utlsProfileIDs — the live MITM dial axis.
//
// Acceptance and resolution are maintained separately, so a name added to
// (1) alone would be blessed by config validation and then fail-hard in
// clientUTLS on every live MITM dial, while the resend axis silently
// degraded to a Go-native ClientHello through InitTLSTransport's fail-soft
// fallback — re-opening by drift the CWE-636 class USK-1021 closed.
//
// The assertions are deliberately bidirectional. A one-directional guard
// ("every vocabulary name resolves") passes happily when a profile is added
// to a resolution table that the vocabulary does not list, which is the
// direction that makes a parrot unreachable from every entry point. Both
// the element-wise checks and the cardinality checks must fail if either
// side gains or loses an entry.
func TestFingerprintVocabularyMatchesResolutionTables(t *testing.T) {
	parrots := parrotFingerprintNames(t)
	parrotSet := make(map[string]bool, len(parrots))
	for _, name := range parrots {
		parrotSet[name] = true
	}

	// Forward: every vocabulary name must survive the dial seam and resolve
	// in both tables.
	for _, name := range parrots {
		t.Run(name, func(t *testing.T) {
			if got := config.UTLSProfileFor(name); got != name {
				t.Errorf("config.UTLSProfileFor(%q) = %q, want it to pass through unchanged: "+
					"only the %q sentinel may be rewritten at the dial seam", name, got, "none")
			}
			profile, err := transport.ParseBrowserProfile(name)
			if err != nil {
				t.Errorf("transport.ParseBrowserProfile(%q): %v — vocabulary name has no "+
					"resend/fuzz-axis profile", name, err)
			} else if got := profile.String(); got != name {
				t.Errorf("transport.ParseBrowserProfile(%q).String() = %q, want a stable "+
					"round-trip", name, got)
			}
			if utlsProfileIDs[name] == nil {
				t.Errorf("utlsProfileIDs[%q] is absent — vocabulary name has no live-MITM "+
					"ClientHelloID, so clientUTLS fail-hards on every dial that requests it", name)
			}
		})
	}

	// Reverse: every live-MITM table key must be a vocabulary name. Without
	// this, a parrot can exist that no entry point will ever accept.
	for name := range utlsProfileIDs {
		if !parrotSet[name] {
			t.Errorf("utlsProfileIDs has %q, which is not a parrot name in the shared "+
				"vocabulary (%s) — no entry point can select it",
				name, config.TLSFingerprintNamesList())
		}
	}

	// Reverse: every named transport.BrowserProfile must be a vocabulary
	// name. BrowserProfile's name table is unexported, so it is enumerated
	// through String(), which returns a "BrowserProfile(N)" placeholder for
	// values it does not name. A new parrot on the resend/fuzz axis needs a
	// constant and a name-table entry to be usable at all, so it surfaces
	// here.
	named := 0
	for i := 1; i <= browserProfileProbeLimit; i++ {
		name := transport.BrowserProfile(i).String()
		if strings.HasPrefix(name, "BrowserProfile(") {
			continue
		}
		named++
		if !parrotSet[name] {
			t.Errorf("transport.BrowserProfile(%d) is named %q, which is not a parrot name "+
				"in the shared vocabulary (%s) — no entry point can select it",
				i, name, config.TLSFingerprintNamesList())
		}
	}

	// Cardinality: the element-wise checks above only prove containment.
	// These make an addition or removal on *either* side fail, including
	// one that happens to satisfy every containment check on its own.
	if len(utlsProfileIDs) != len(parrots) {
		t.Errorf("len(utlsProfileIDs) = %d, len(parrot vocabulary) = %d %v — the live-MITM "+
			"table and the accepted vocabulary must stay in lockstep",
			len(utlsProfileIDs), len(parrots), parrots)
	}
	if named != len(parrots) {
		t.Errorf("named transport.BrowserProfile values = %d, len(parrot vocabulary) = %d %v — "+
			"the resend/fuzz table and the accepted vocabulary must stay in lockstep",
			named, len(parrots), parrots)
	}
}

// parrotFingerprintNames splits the shared vocabulary into the names that
// must resolve to a uTLS parrot profile: everything except the "none"
// opt-out sentinel, which config.UTLSProfileFor collapses to "" before any
// table lookup happens.
func parrotFingerprintNames(t *testing.T) []string {
	t.Helper()

	list := config.TLSFingerprintNamesList()
	names := make([]string, 0, 8)
	sawNone := false
	for _, name := range strings.Split(list, ", ") {
		if name == "none" {
			sawNone = true
			continue
		}
		names = append(names, name)
	}
	// Guard the exclusion itself: if the sentinel is ever renamed, fail here
	// rather than silently shifting what this test covers.
	if !sawNone {
		t.Fatalf("vocabulary %q no longer contains the %q sentinel; this test's exclusion is stale",
			list, "none")
	}
	if len(names) == 0 {
		t.Fatalf("vocabulary %q yielded no parrot names", list)
	}
	return names
}
