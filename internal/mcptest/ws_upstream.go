package mcptest

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// WSHitCounter records how many WebSocket data frames the upstream test
// server actually received from the proxy. Tests use it as the durable
// SafetyFilter assertion: when pipeline.SafetyStep drops a Send-direction
// WS envelope, the upstream handler never sees the frame so the counter
// does not advance.
//
// Concurrency: increments happen on the per-connection serve goroutine;
// reads happen on the test goroutine. Total / PerOpcode use atomic loads
// (Total) plus a mutex (PerOpcode) for the per-opcode map. Mirrors the
// shape of GRPCHitCounter / GRPCWebHitCounter so cross-protocol assertions
// stay symmetrical.
type WSHitCounter struct {
	total atomic.Int64

	mu      sync.Mutex
	opcodes map[byte]int64
}

// NewWSHitCounter constructs an empty counter. Exported for tests that
// want to share a counter across multiple upstreams.
func NewWSHitCounter() *WSHitCounter {
	return &WSHitCounter{opcodes: make(map[byte]int64)}
}

// Total returns the cumulative number of WS data frames recorded by the
// harness WebSocket handler.
func (c *WSHitCounter) Total() int64 {
	if c == nil {
		return 0
	}
	return c.total.Load()
}

// PerOpcode returns the number of frames received with the given WS
// opcode (e.g. wslayer.OpcodeText, wslayer.OpcodeBinary). Zero if the
// opcode has not been observed.
func (c *WSHitCounter) PerOpcode(opcode byte) int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opcodes[opcode]
}

// record is invoked from inside the WS upstream serve goroutine for each
// data frame (text/binary/continuation). Control frames (ping/pong/close)
// are explicitly excluded so the durable SafetyFilter assertion is not
// muddled by transport housekeeping.
func (c *WSHitCounter) record(opcode byte) {
	if c == nil {
		return
	}
	c.total.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opcodes[opcode]++
}

// wsAcceptMagic is the magic GUID defined by RFC 6455 §1.3 — appended to
// the client's Sec-WebSocket-Key, SHA-1 hashed, and base64-encoded to
// produce Sec-WebSocket-Accept.
const wsAcceptMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// computeWSAccept returns the Sec-WebSocket-Accept header value for the
// given Sec-WebSocket-Key per RFC 6455 §1.3.
func computeWSAccept(key string) string {
	h := sha1.New() //nolint:gosec // RFC 6455 mandates SHA-1 for the handshake; not used for security
	_, _ = io.WriteString(h, key)
	_, _ = io.WriteString(h, wsAcceptMagic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// buildWSUpstream stands up an HTTP/1.1 TLS server (NextProtos=http/1.1)
// that performs the RFC 6455 WebSocket handshake on /ws and counts every
// data frame received. The returned *httptest.Server shell is shaped
// exactly like the one buildGRPCUpstream / buildGRPCWebUpstream return
// (URL, Listener, Config, TLS) so the harness cleanup path does not need
// to fork by upstream protocol.
//
// The handler intentionally hijacks the underlying net.Conn so we can
// run the WS frame loop without involving net/http's body machinery —
// the proxy's WS layer expects a raw TCP byte stream after the 101
// response, not chunked HTTP body framing. Frame parsing reuses
// internal/layer/ws/frame.go (ws.ReadFrame / ws.WriteFrame) so no
// per-test re-implementation of the WS wire format exists in mcptest.
//
// MITM Implementation Principle 5 (graceful malformed input):
//   - Non-WS HTTP requests respond with 400 Bad Request and DO NOT panic.
//   - ws.ReadFrame returns a typed error on truncated frames; the serve
//     loop treats every such error as connection-terminating and exits
//     cleanly without leaking goroutines.
func buildWSUpstream() (*httptest.Server, *FingerprintObserver, *WSHitCounter, error) {
	leafCert, err := newSelfSignedLeaf("localhost", "127.0.0.1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		// WebSocket upgrade is HTTP/1.1 only; explicitly pin ALPN so the
		// proxy's protocol-detection step never accidentally selects h2.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	tlsCfg, fpObs := installFingerprintObserver(base)

	hits := NewWSHitCounter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgradeRequest(r) {
			http.Error(w, "mcptest ws upstream: not a WebSocket upgrade", http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			http.Error(w, "mcptest ws upstream: missing Sec-WebSocket-Key", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "mcptest ws upstream: hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, fmt.Sprintf("mcptest ws upstream: hijack: %v", err), http.StatusInternalServerError)
			return
		}
		// From here on, w is unusable — the underlying connection is ours.
		serveWSConnection(conn, brw, key, hits)
	})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen: %w", err)
	}

	wrapped := &wsListener{
		Listener: tcpLn,
		tlsCfg:   tlsCfg,
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	wrapped.serveDone.Add(1)
	go wrapped.serve()

	srv := &httptest.Server{
		Listener: wrapped,
		// Config must be non-nil because httptest.Server.Close calls
		// s.Config.SetKeepAlivesEnabled. Use the real *http.Server here
		// so that call propagates to the listener-driven instance.
		Config: wrapped.server,
		URL:    "https://" + tcpLn.Addr().String(),
		TLS:    tlsCfg,
	}
	return srv, fpObs, hits, nil
}

// isWebSocketUpgradeRequest reports whether r carries the headers
// required by RFC 6455 §4.2.1 for a WebSocket upgrade. The check is
// case-insensitive on header values per the Connection / Upgrade header
// rules; the Header.Get accessor already canonicalises header names.
func isWebSocketUpgradeRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	return true
}

// headerContainsToken reports whether the given header value (a
// comma-separated list per RFC 7230 §3.2.6) contains the case-insensitive
// token. Used for Connection: upgrade detection.
func headerContainsToken(headerValue, token string) bool {
	for _, raw := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(raw), token) {
			return true
		}
	}
	return false
}

// serveWSConnection completes the RFC 6455 §1.3 handshake by writing the
// 101 Switching Protocols response, then enters a frame-read loop that
// records every data frame on hits and echoes text/binary frames back to
// the client. Control frames are honored: Ping is answered with Pong,
// Close terminates the loop after echoing the close frame back. The
// connection is always closed on return.
func serveWSConnection(conn net.Conn, brw *bufio.ReadWriter, key string, hits *WSHitCounter) {
	defer conn.Close()

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + computeWSAccept(key) + "\r\n" +
		"\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	// brw.Reader still holds any bytes net/http buffered past the
	// request headers (typically zero — clients wait for the 101 before
	// sending frames — but the contract permits buffered preamble bytes).
	// Use the bufio.Reader directly so those buffered bytes are not lost.
	reader := brw.Reader

	for {
		// Bound each frame read so a wedged client cannot keep this
		// goroutine alive past test cleanup. The deadline is generous
		// (15s) to tolerate slow CI hosts.
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, err := wslayer.ReadFrame(reader)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		switch f.Opcode {
		case wslayer.OpcodeText, wslayer.OpcodeBinary, wslayer.OpcodeContinuation:
			// Data frames are the SafetyFilter assertion target — record
			// then echo. The pipeline.SafetyStep contract is to drop
			// matching Send envelopes, so blocked frames never reach
			// here and the counter stays put.
			hits.record(f.Opcode)
			echo := &wslayer.Frame{
				Fin:     true,
				Opcode:  f.Opcode,
				Payload: append([]byte(nil), f.Payload...),
			}
			if werr := wslayer.WriteFrame(conn, echo); werr != nil {
				return
			}
		case wslayer.OpcodePing:
			pong := &wslayer.Frame{
				Fin:     true,
				Opcode:  wslayer.OpcodePong,
				Payload: append([]byte(nil), f.Payload...),
			}
			if werr := wslayer.WriteFrame(conn, pong); werr != nil {
				return
			}
		case wslayer.OpcodeClose:
			// Echo the close frame back per RFC 6455 §5.5.1, then exit.
			closeFrame := &wslayer.Frame{
				Fin:     true,
				Opcode:  wslayer.OpcodeClose,
				Payload: append([]byte(nil), f.Payload...),
			}
			_ = wslayer.WriteFrame(conn, closeFrame)
			return
		default:
			// Unknown opcode — ignore and continue. ws.ReadFrame already
			// validated frame-level constraints (size, control-frame fin),
			// so we cannot crash on a well-formed but novel opcode.
		}
	}
}

// wsListener is the listener handed to httptest.Server. It owns a single
// Accept goroutine that promotes each connection to TLS and dispatches
// to the http.Server handler. Close shuts the http.Server down inside a
// sync.Once so both httptest.Server.Close and t.Cleanup paths converge
// on the same teardown without panicking on a double-close.
type wsListener struct {
	net.Listener

	tlsCfg *tls.Config
	server *http.Server

	serveDone sync.WaitGroup
	once      sync.Once
}

func (l *wsListener) serve() {
	defer l.serveDone.Done()
	tlsLn := tls.NewListener(l.Listener, l.tlsCfg)
	// http.Server.Serve returns http.ErrServerClosed when Shutdown /
	// Close fires. Other errors mean Accept itself failed, which is
	// indistinguishable from "test cleanup" for our purposes — exit
	// cleanly either way so Close does not block.
	_ = l.server.Serve(tlsLn)
}

func (l *wsListener) Close() error {
	l.once.Do(func() {
		// http.Server.Close terminates Serve and closes the listener
		// (which propagates to our wrapped TCP listener via the tls
		// listener wrapper). Call it inside Once because httptest.Server
		// teardown and t.Cleanup may both call us.
		_ = l.server.Close()
		// l.Listener.Close is already invoked by http.Server.Close via
		// the tls listener wrapper, but call it again as a safety net.
		// net.Listener.Close on an already-closed listener returns
		// ErrClosed, which is fine to swallow.
		_ = l.Listener.Close()
		l.serveDone.Wait()
	})
	return nil
}
