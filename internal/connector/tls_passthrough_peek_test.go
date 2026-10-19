package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// passthroughPeekPromptBound is the latency budget for the observed
// passthrough relay to fire OnStart once the client has sent its first
// bytes. It is far below clientHelloPeekTimeout (5 s) so a peek that waits
// for the deadline is unambiguously caught, yet generous enough for a
// loaded CI runner. USK-1170.
const passthroughPeekPromptBound = time.Second

// observedRelayResult is what runObservedPassthroughRelay reports back.
type observedRelayResult struct {
	obs           PassthroughObservation
	startLatency  time.Duration
	upstreamBytes []byte
}

// runObservedPassthroughRelay drives the real observer-aware passthrough
// relay (RelayTLSPassthroughObserved) between a net.Pipe client wrapped in
// PeekConn — the shape every connector entry point hands the relay — and a
// real TCP loopback upstream that records every byte it receives.
//
// clientSend runs on its own goroutine and writes the client's first bytes.
// It must not close the client conn unless closing is the scenario under
// test (a client that has sent its ClientHello waits for ServerHello, it
// does not hang up). The helper measures the time from launching
// clientSend to OnStart, then closes the client so the relay ends, and
// returns the bytes the upstream observed.
func runObservedPassthroughRelay(t *testing.T, clientSend func(c net.Conn)) observedRelayResult {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer ln.Close()

	upstreamGot := make(chan []byte, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			upstreamGot <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		b, _ := io.ReadAll(c)
		upstreamGot <- b
	}()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	pc := NewPeekConn(proxySide)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	started := make(chan PassthroughObservation, 1)
	observer := PassthroughObserverFunc{
		Start: func(_ context.Context, obs PassthroughObservation) {
			started <- obs
		},
	}

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RelayTLSPassthroughObserved(ctx, pc, ln.Addr().String(),
			DialRawOpts{DialTimeout: 5 * time.Second}, observer)
	}()

	t0 := time.Now()
	go clientSend(clientSide)

	var res observedRelayResult
	select {
	case res.obs = <-started:
		res.startLatency = time.Since(t0)
	case <-time.After(10 * time.Second):
		t.Fatal("OnStart never fired")
	}

	_ = clientSide.Close()

	select {
	case <-relayDone:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not return after client close")
	}
	select {
	case res.upstreamBytes = <-upstreamGot:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream sink did not finish")
	}
	return res
}

// TestRelayTLSPassthroughObserved_RealClientHello_PromptStartWithSNI drives
// a real crypto/tls ClientHello through the observed passthrough relay and
// asserts OnStart fires promptly (the peek must not wait for the 5 s
// deadline) and still carries SNI + JA3/JA4. Replaces the old helper-level
// TestPeekClientHelloSNI_PassthroughFingerprints. USK-1170.
func TestRelayTLSPassthroughObserved_RealClientHello_PromptStartWithSNI(t *testing.T) {
	res := runObservedPassthroughRelay(t, func(c net.Conn) {
		tc := tls.Client(c, &tls.Config{
			ServerName:         "pass.example.com",
			InsecureSkipVerify: true, //nolint:gosec // test
		})
		_ = tc.Handshake() // blocks for ServerHello until the test closes c
	})

	if res.startLatency >= passthroughPeekPromptBound {
		t.Errorf("OnStart fired after %v, want < %v (peek waited for its deadline)",
			res.startLatency, passthroughPeekPromptBound)
	}
	if res.obs.SNI != "pass.example.com" {
		t.Errorf("SNI = %q, want pass.example.com", res.obs.SNI)
	}
	if len(res.obs.ClientJA3) != 32 {
		t.Errorf("ClientJA3 = %q, want 32-char md5 hex", res.obs.ClientJA3)
	}
	if res.obs.ClientJA4 == "" {
		t.Errorf("ClientJA4 is empty, want a fingerprint")
	}
	if len(res.upstreamBytes) == 0 || res.upstreamBytes[0] != tlsContentTypeHandshake {
		t.Errorf("upstream did not receive the ClientHello record (got %d bytes)", len(res.upstreamBytes))
	}
}

// TestRelayTLSPassthroughObserved_EdgeInputs covers ClientHello shapes the
// first-record peek cannot (or must not) parse. Each must start the relay
// promptly, not panic, record no SNI, and forward the client's bytes to the
// upstream byte-for-byte (passthrough fidelity). USK-1170.
func TestRelayTLSPassthroughObserved_EdgeInputs(t *testing.T) {
	// Two-record ClientHello: one handshake message fragmented across two
	// TLS records (RFC 8446 §5.1 permits this). Built from the same
	// ClientHello shape the parser unit tests use.
	full := buildClientHelloWithExts(t, "split.example.com", []string{"h2", "http/1.1"})
	hs := full[5:]
	half := len(hs) / 2
	record := func(frag []byte) []byte {
		r := []byte{tlsContentTypeHandshake, 0x03, 0x01, byte(len(frag) >> 8), byte(len(frag))}
		return append(r, frag...)
	}
	twoRecords := append(record(hs[:half]), record(hs[half:])...)

	tests := []struct {
		name       string
		send       []byte
		closeAfter bool // client hangs up right after sending
	}{
		{
			name: "two-record ClientHello",
			send: twoRecords,
		},
		{
			// Application-data content type with a small declared length
			// that the client never fills: the peek must recognise it is
			// not a handshake record instead of waiting for the body.
			name: "non-handshake record with small unfilled length",
			send: []byte{0x17, 0x03, 0x03, 0x00, 0x40, 'x', 'y', 'z'},
		},
		{
			name: "handshake record with zero length",
			send: []byte{tlsContentTypeHandshake, 0x03, 0x01, 0x00, 0x00},
		},
		{
			name:       "truncated record header then EOF",
			send:       []byte{tlsContentTypeHandshake, 0x03},
			closeAfter: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runObservedPassthroughRelay(t, func(c net.Conn) {
				_, _ = c.Write(tt.send)
				if tt.closeAfter {
					_ = c.Close()
				}
			})
			if res.startLatency >= passthroughPeekPromptBound {
				t.Errorf("OnStart fired after %v, want < %v (peek waited for its deadline)",
					res.startLatency, passthroughPeekPromptBound)
			}
			if res.obs.SNI != "" {
				t.Errorf("SNI = %q, want empty for an unparseable first record", res.obs.SNI)
			}
			if !bytes.Equal(res.upstreamBytes, tt.send) {
				t.Errorf("upstream received %x, want byte-identical %x", res.upstreamBytes, tt.send)
			}
		})
	}
}
