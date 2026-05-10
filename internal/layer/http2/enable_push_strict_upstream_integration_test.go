//go:build e2e && !e2e_smoke

package http2_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2frame "github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-820: regression guard for the live failure mode reported in the
// Phase 5 pentest retest. Strict upstreams (Google Frontend, nghttp2-server)
// reply with GOAWAY(PROTOCOL_ERROR, last_stream_id=0) when a client sends
// SETTINGS_ENABLE_PUSH=1 on the first preface — RFC 9113 §6.5.2 requires
// clients to send 0. Before USK-820 the proxy ClientRole emitted 1, so
// every first stream was refused.
//
// This test reconstructs that exact scenario by hand-rolling a strict
// in-process server peer that decodes the SETTINGS, asserts the constraint,
// and replies GOAWAY(PROTOCOL_ERROR) if violated — same response shape
// observed from real strict upstreams in the live reproduction.
//
// Placed in the exhaustive (full) tier per CLAUDE.md guidance: this test
// exercises the live data-path Layer.New() boot but does not run through
// the full proxy listener / pipeline so it is not part of the merge-gate
// smoke set.

// TestClientRole_StrictUpstream_AcceptsEnablePushZero stands up an in-process
// h2 peer that simulates a strict upstream and verifies the proxy
// ClientRole Layer's preface SETTINGS contains ENABLE_PUSH=0 (not 1).
// Pre-fix this test would have failed with a GOAWAY(PROTOCOL_ERROR).
func TestClientRole_StrictUpstream_AcceptsEnablePushZero(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()
	defer srvConn.Close()

	// Spawn the strict server peer first so it can read the preface and
	// SETTINGS as soon as the Layer writes them.
	type peerResult struct {
		gotSettings []h2frame.Setting
		// goawayCode is set only if the strict peer rejected the SETTINGS.
		goawayCode uint32
		err        error
	}
	peerDone := make(chan peerResult, 1)
	go func() {
		settings, code, err := strictUpstreamPeer(srvConn)
		peerDone <- peerResult{gotSettings: settings, goawayCode: code, err: err}
	}()

	// Drive the proxy ClientRole Layer against the pipe. The Layer writes
	// the preface + SETTINGS during New(); the strict peer reads them.
	l, err := intHTTP2.New(cliConn, "test-strict-upstream", intHTTP2.ClientRole,
		intHTTP2.WithEnvelopeContext(envelope.EnvelopeContext{}))
	if err != nil {
		t.Fatalf("intHTTP2.New(ClientRole): %v", err)
	}
	defer l.Close()

	// Wait for the peer to finish reading and validating the preface SETTINGS.
	select {
	case res := <-peerDone:
		if res.err != nil {
			t.Fatalf("strict upstream peer error: %v", res.err)
		}
		if res.goawayCode != 0 {
			t.Fatalf("strict upstream sent GOAWAY(code=%d, %s) — proxy ClientRole emitted non-conformant SETTINGS",
				res.goawayCode, intHTTP2.ErrCodeString(res.goawayCode))
		}
		// Locate ENABLE_PUSH in the wire SETTINGS and assert it is 0.
		var found bool
		for _, s := range res.gotSettings {
			if s.ID == h2frame.SettingEnablePush {
				found = true
				if s.Value != 0 {
					t.Fatalf("ClientRole emitted ENABLE_PUSH=%d on the wire, want 0 (RFC 9113 §6.5.2)", s.Value)
				}
			}
		}
		// Per RFC 9113 §6.5.2, clients MAY also omit the setting (default 0).
		// Our current implementation emits the field explicitly; if a future
		// USK-* retires the explicit emit in favor of omit-when-default,
		// this branch keeps the test passing without weakening the guard.
		if !found {
			t.Logf("ClientRole did not emit explicit ENABLE_PUSH (acceptable: omit means default 0)")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("strict upstream peer did not return within deadline")
	}
}

// strictUpstreamPeer reads the HTTP/2 client preface and the first SETTINGS
// frame from conn, then validates the RFC 9113 §6.5.2 SETTINGS_ENABLE_PUSH
// constraint for clients (must be 0). On violation it sends
// GOAWAY(PROTOCOL_ERROR) — replicating the GFE / nghttp2-server response
// observed in the live USK-820 reproduction. On success it returns the
// observed settings so the caller can additionally assert the wire value.
func strictUpstreamPeer(conn net.Conn) (settings []h2frame.Setting, goawayCode uint32, err error) {
	// Read 24-byte client preface.
	preface := make([]byte, len(intHTTP2.ClientPreface))
	if _, rerr := io.ReadFull(conn, preface); rerr != nil {
		return nil, 0, rerr
	}
	if string(preface) != intHTTP2.ClientPreface {
		return nil, 0, errors.New("bad preface")
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

		// RFC 9113 §6.5.2: a client MUST send ENABLE_PUSH=0; a server MUST
		// treat any other value as a connection PROTOCOL_ERROR.
		for _, p := range params {
			if p.ID == h2frame.SettingEnablePush && p.Value != 0 {
				const codeProtocol uint32 = 0x01
				if werr := wr.WriteGoAway(0, codeProtocol, []byte("ENABLE_PUSH from client must be 0")); werr != nil {
					return settings, 0, werr
				}
				goawayCode = codeProtocol
				return settings, goawayCode, nil
			}
		}
		// SETTINGS validated — that's all the test needs.
		return settings, 0, nil
	}
	return nil, 0, errors.New("timed out waiting for client SETTINGS")
}
