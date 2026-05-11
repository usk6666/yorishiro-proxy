//go:build e2e && !e2e_smoke

package http2_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2frame "github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-825: regression guard for the live failure mode reported during
// USK-820 land testing. Strict h2 clients (curl, Chrome, golang.org/x/net/http2)
// reply with GOAWAY(PROTOCOL_ERROR, last_stream_id=0) when a server sends
// SETTINGS_ENABLE_PUSH=1 (or any non-zero value, including the legacy
// pre-USK-825 default of 1) on the first preface — RFC 9113 §7.2.2 says
// "Servers MUST NOT explicitly set this value." Before USK-825 the proxy
// ServerRole emitted 1, so every h2 client → proxy MITM connection
// terminated with GOAWAY(PROTOCOL_ERROR, debug_data="SETTINGS: server
// attempted to enable push").
//
// This test reconstructs that exact scenario by hand-rolling a strict
// in-process client peer that reads the SETTINGS, asserts the constraint,
// and replies GOAWAY(PROTOCOL_ERROR) if violated — same response shape
// observed from real strict h2 clients in the live reproduction.
//
// Placed in the exhaustive (full) tier per CLAUDE.md guidance: this test
// exercises the live data-path Layer.New() boot but does not run through
// the full proxy listener / pipeline so it is not part of the merge-gate
// smoke set.

// TestServerRole_StrictClient_AcceptsEnablePushOmitted stands up an
// in-process h2 peer that simulates a strict client and verifies the
// proxy ServerRole Layer's preface SETTINGS omits SETTINGS_ENABLE_PUSH
// entirely (RFC 9113 §7.2.2). Pre-fix this test would have failed with
// the peer issuing GOAWAY(PROTOCOL_ERROR).
func TestServerRole_StrictClient_AcceptsEnablePushOmitted(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	// Spawn the strict client peer first so it can write the preface and
	// read the SETTINGS as soon as the Layer responds.
	type peerResult struct {
		gotSettings []h2frame.Setting
		// goawayCode is set only if the strict peer rejected the SETTINGS.
		goawayCode uint32
		err        error
	}
	peerDone := make(chan peerResult, 1)
	go func() {
		settings, code, err := strictClientPeer(cliConn)
		peerDone <- peerResult{gotSettings: settings, goawayCode: code, err: err}
	}()

	// Drive the proxy ServerRole Layer against the pipe. The Layer reads
	// the preface and writes its SETTINGS during New(); the strict peer
	// asserts on those SETTINGS.
	l, err := intHTTP2.New(srvConn, "test-strict-client", intHTTP2.ServerRole,
		intHTTP2.WithEnvelopeContext(envelope.EnvelopeContext{}))
	if err != nil {
		t.Fatalf("intHTTP2.New(ServerRole): %v", err)
	}
	defer l.Close()

	// Wait for the peer to finish reading and validating the preface SETTINGS.
	select {
	case res := <-peerDone:
		if res.err != nil {
			t.Fatalf("strict client peer error: %v", res.err)
		}
		if res.goawayCode != 0 {
			t.Fatalf("strict client sent GOAWAY(code=%d, %s) — proxy ServerRole emitted non-conformant SETTINGS",
				res.goawayCode, intHTTP2.ErrCodeString(res.goawayCode))
		}
		// Primary assertion: SETTINGS_ENABLE_PUSH must be absent from the
		// wire SETTINGS frame. RFC 9113 §7.2.2 forbids servers from
		// explicitly setting any value; strict clients reject 0 and 1 alike.
		for _, s := range res.gotSettings {
			if s.ID == h2frame.SettingEnablePush {
				t.Fatalf("ServerRole emitted ENABLE_PUSH=%d on the wire, want setting absent (RFC 9113 §7.2.2)", s.Value)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("strict client peer did not return within deadline")
	}
}

// strictClientPeer writes the HTTP/2 client preface to conn, reads the first
// SETTINGS frame from the server, then validates the RFC 9113 §7.2.2 SETTINGS_ENABLE_PUSH
// constraint for servers ("MUST NOT explicitly set this value"). On violation
// it sends GOAWAY(PROTOCOL_ERROR) — replicating the strict h2 client behaviour
// observed in the live USK-825 reproduction (curl / golang.org/x/net/http2).
// On success it returns the observed settings so the caller can additionally
// assert the wire absence.
func strictClientPeer(conn net.Conn) (settings []h2frame.Setting, goawayCode uint32, err error) {
	// Send the 24-byte client preface so the server's New() can return.
	if _, werr := conn.Write([]byte(intHTTP2.ClientPreface)); werr != nil {
		return nil, 0, werr
	}

	rd := h2frame.NewReader(conn)
	wr := h2frame.NewWriter(conn)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, ferr := rd.ReadFrame()
		if ferr != nil {
			return nil, 0, ferr
		}
		if f.Header.Type != h2frame.TypeSettings {
			continue
		}
		if f.Header.Flags.Has(h2frame.FlagAck) {
			continue
		}
		params, perr := f.SettingsParams()
		if perr != nil {
			return nil, 0, perr
		}
		settings = params

		// RFC 9113 §7.2.2: servers MUST NOT explicitly set ENABLE_PUSH; a
		// strict client MUST treat receipt of any non-zero value as a
		// connection PROTOCOL_ERROR. We mirror that behaviour here for
		// any emitted value (including 0), since §7.2.2 forbids the
		// explicit set outright.
		for _, p := range params {
			if p.ID == h2frame.SettingEnablePush {
				const codeProtocol uint32 = 0x01
				if werr := wr.WriteGoAway(0, codeProtocol, []byte("SETTINGS: server attempted to enable push")); werr != nil {
					return settings, 0, werr
				}
				goawayCode = codeProtocol
				return settings, goawayCode, nil
			}
		}
		// SETTINGS validated — that's all the test needs.
		return settings, 0, nil
	}
	return nil, 0, errors.New("timed out waiting for server SETTINGS")
}
