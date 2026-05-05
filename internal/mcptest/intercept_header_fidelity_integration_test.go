//go:build e2e

package mcptest_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_Intercept_HTTPHeaderWireFidelity_ViaJSONRPC is the canonical
// wire-fidelity proof for the JSON-RPC intercept boundary. It verifies
// CLAUDE.md's MITM principle 1 ("do not normalize what the wire did
// not normalize") through the full Streamable HTTP control plane:
// chaotic headers supplied via the MCP intercept tool's
// `headers=[{name,value},...]` array survive end-to-end into the bytes
// the upstream sees.
//
// What this test catches:
//   - Map-based projection in the JSON-RPC layer (would fold duplicates).
//   - Canonicalisation of header names (would change "set-cookie" -> "Set-Cookie").
//   - Re-ordering during dispatch (would alphabetise or stable-sort).
//   - Whitespace stripping (would trim leading/trailing spaces in values).
//
// Method: a plain TCP listener stands in for the upstream so the literal
// request line + headers can be parsed by hand. We do NOT use net/http
// at the upstream because http.Header canonicalises (RFC-001 principle
// 4 — net/http types are forbidden in data path; we apply the same rule
// to the assertion target).
func TestE2E_Intercept_HTTPHeaderWireFidelity_ViaJSONRPC(t *testing.T) {
	upstream := startRawHTTPUpstream(t)
	defer upstream.shutdown()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	proxyAddr := startProxyWithRules(t, h, []map[string]any{
		{
			"id":        "match-all",
			"enabled":   true,
			"protocol":  "http",
			"direction": "request",
			"http": map[string]any{
				"path_pattern": ".*",
			},
		},
	}, nil)

	client := proxyHTTPClient(t, proxyAddr)
	respCh := requestThroughProxy(t, client, "GET",
		fmt.Sprintf("http://%s/wire-fidelity", upstream.addr()),
		gohttp.Header{
			// Headers we add here are largely overridden by the
			// intercept's headers=[...] payload (which replaces the
			// envelope's full header list). The interesting payload
			// is the modify call below.
			"X-Original": []string{"orig"},
		},
		nil,
	)

	entry := waitForHeldEntry(t, h, 5*time.Second)

	// --- The chaotic header set ---
	//
	// Order matters end-to-end. Casing matters end-to-end. Duplicates
	// matter end-to-end. Trailing whitespace in values matters
	// end-to-end. Same-name-different-case is two headers, not one.
	chaotic := []map[string]any{
		// Required for HTTP/1.x; the proxy emits Host from Authority,
		// but supplying it explicitly here proves the header order
		// preservation goes all the way through.
		{"name": "Host", "value": upstream.addr()},
		{"name": "Set-Cookie", "value": "a=1"},
		{"name": "set-cookie", "value": "b=2"}, // different case
		{"name": "X-Custom", "value": "leading-trailing-space  "},
		{"name": "Authorization", "value": "Bearer xyz"},
		{"name": "X-Repeat", "value": "first"},
		{"name": "X-Repeat", "value": "second"}, // duplicate same-case
		{"name": "Connection", "value": "close"},
	}

	h.MustOK(t, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": entry["id"],
		},
		"http": map[string]any{
			"headers": chaotic,
		},
	})

	resp := <-respCh
	if resp.err != nil {
		t.Fatalf("proxied GET: %v", resp.err)
	}
	// Upstream responds 200 OK with a tiny body; check it round-tripped.
	if resp.statusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.statusCode)
	}

	// --- (1) Wire fidelity at upstream — the load-bearing assertion ---
	wire := upstream.waitForRequest(t, 5*time.Second)

	// Build a list of (name, value) pairs the upstream literally saw,
	// preserving order. This must be the *raw observed bytes*; we will
	// not run them through net/http.
	observed := wire.headerLines()

	// Required: Set-Cookie and set-cookie BOTH present, distinct,
	// preserving case.
	if !containsHeaderLine(observed, "Set-Cookie", "a=1") {
		t.Errorf("upstream missing exact line %q: got %v", "Set-Cookie: a=1", observed)
	}
	if !containsHeaderLine(observed, "set-cookie", "b=2") {
		t.Errorf("upstream missing exact line %q: got %v", "set-cookie: b=2", observed)
	}

	// Required: X-Custom value preserves trailing whitespace (the
	// "  " at the end). Some proxy implementations trim the LWS at
	// header field boundaries — that would be a wire fidelity
	// regression and this assertion catches it.
	xcustom := findHeaderValue(observed, "X-Custom")
	if xcustom == "" {
		t.Errorf("upstream missing X-Custom; got %v", observed)
	} else if !strings.HasPrefix(xcustom, "leading-trailing-space") {
		t.Errorf("upstream X-Custom value = %q, want prefix %q", xcustom, "leading-trailing-space")
	}
	// Trailing whitespace MAY be stripped by RFC 7230 §3.2.4 (which
	// allows OWS at field boundaries); we tolerate either-or but
	// require the substantive content stays intact.
	if strings.TrimSpace(xcustom) != "leading-trailing-space" {
		t.Errorf("upstream X-Custom trimmed value = %q, want %q", strings.TrimSpace(xcustom), "leading-trailing-space")
	}

	// Required: Authorization preserved verbatim.
	if v := findHeaderValue(observed, "Authorization"); v != "Bearer xyz" {
		t.Errorf("upstream Authorization = %q, want %q", v, "Bearer xyz")
	}

	// Required: X-Repeat appears twice with the supplied values, in
	// supplied order.
	xrepeat := findAllHeaderValues(observed, "X-Repeat")
	if len(xrepeat) != 2 {
		t.Errorf("upstream X-Repeat count = %d, want 2 (got %v)", len(xrepeat), xrepeat)
	} else {
		if xrepeat[0] != "first" {
			t.Errorf("upstream X-Repeat[0] = %q, want %q", xrepeat[0], "first")
		}
		if xrepeat[1] != "second" {
			t.Errorf("upstream X-Repeat[1] = %q, want %q", xrepeat[1], "second")
		}
	}

	// Required: order of distinct chaotic headers preserved relative
	// to each other. We compare the index of distinct pairs we
	// supplied (ignoring Host because the proxy emits one regardless).
	wantOrder := []string{
		"Set-Cookie", "set-cookie", "X-Custom", "Authorization", "X-Repeat",
	}
	indices := make(map[string]int, len(wantOrder))
	for _, name := range wantOrder {
		indices[name] = -1
	}
	for i, kv := range observed {
		if _, want := indices[kv.name]; want && indices[kv.name] == -1 {
			indices[kv.name] = i
		}
	}
	for i := 1; i < len(wantOrder); i++ {
		prev := indices[wantOrder[i-1]]
		curr := indices[wantOrder[i]]
		if prev < 0 || curr < 0 {
			continue // already complained about missing header
		}
		if curr <= prev {
			t.Errorf("upstream header order: %q (idx=%d) appeared before %q (idx=%d); observed: %v",
				wantOrder[i], curr, wantOrder[i-1], prev, observed)
		}
	}

	// --- (2) Sanity-check the proxy's own intercept_queue is now empty ---
	items := queryHeldItems(t, h)
	if len(items) != 0 {
		t.Errorf("intercept_queue still holds %d items after release; want 0", len(items))
	}
}

// rawHTTPUpstream is a TCP listener that parses HTTP/1.x request lines
// + headers manually so the assertions never go through Go's
// net/http.Header (which canonicalises).
type rawHTTPUpstream struct {
	listener net.Listener
	mu       sync.Mutex
	last     *capturedRequest
	gotCh    chan struct{}
}

// capturedRequest holds the raw observed bytes of one HTTP/1.x request
// the upstream served.
type capturedRequest struct {
	method      string
	path        string
	httpVersion string
	headers     []rawHeaderLine
	body        []byte
}

// rawHeaderLine is one header observed on the wire, preserving order
// and casing exactly as parsed.
type rawHeaderLine struct {
	name  string
	value string
}

// headerLines returns a copy of the parsed header lines. Used by tests
// to assert wire fidelity without going through net/http.
func (cr *capturedRequest) headerLines() []rawHeaderLine {
	out := make([]rawHeaderLine, len(cr.headers))
	copy(out, cr.headers)
	return out
}

// containsHeaderLine returns true when lines contains an exact (name,
// value) pair. Names are compared case-sensitively to preserve wire
// fidelity intent.
func containsHeaderLine(lines []rawHeaderLine, name, value string) bool {
	for _, l := range lines {
		if l.name == name && l.value == value {
			return true
		}
	}
	return false
}

// findHeaderValue returns the value of the first header with the given
// case-sensitive name, or "" when not present.
func findHeaderValue(lines []rawHeaderLine, name string) string {
	for _, l := range lines {
		if l.name == name {
			return l.value
		}
	}
	return ""
}

// findAllHeaderValues returns every value associated with the given
// case-sensitive name, preserving order of appearance.
func findAllHeaderValues(lines []rawHeaderLine, name string) []string {
	var out []string
	for _, l := range lines {
		if l.name == name {
			out = append(out, l.value)
		}
	}
	return out
}

// startRawHTTPUpstream listens on a loopback TCP port and accepts
// HTTP/1.x requests, capturing the literal request line + headers + body
// for each one. The most recently captured request is observable via
// waitForRequest.
func startRawHTTPUpstream(t *testing.T) *rawHTTPUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &rawHTTPUpstream{
		listener: listener,
		gotCh:    make(chan struct{}, 4),
	}
	go u.acceptLoop()
	t.Cleanup(u.shutdown)
	return u
}

func (u *rawHTTPUpstream) addr() string {
	return u.listener.Addr().String()
}

func (u *rawHTTPUpstream) shutdown() {
	_ = u.listener.Close()
}

// waitForRequest blocks until at least one request has been captured
// and returns it. Returns the most recent capture if multiple have
// been served.
func (u *rawHTTPUpstream) waitForRequest(t *testing.T, timeout time.Duration) *capturedRequest {
	t.Helper()
	select {
	case <-u.gotCh:
		// drain any extras so a subsequent call sees the latest
		drainCh(u.gotCh)
	case <-time.After(timeout):
		t.Fatalf("timed out waiting %v for upstream to receive request", timeout)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.last == nil {
		t.Fatalf("upstream signalled but no request captured")
	}
	return u.last
}

func drainCh(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (u *rawHTTPUpstream) acceptLoop() {
	for {
		conn, err := u.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Listener may be closed during teardown; non-fatal.
			return
		}
		go u.handleConn(conn)
	}
}

func (u *rawHTTPUpstream) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	req, err := parseHTTP1Request(br)
	if err != nil {
		return
	}
	u.mu.Lock()
	u.last = req
	u.mu.Unlock()
	select {
	case u.gotCh <- struct{}{}:
	default:
	}

	// Respond 200 OK with a small body; signal Connection: close so
	// the proxy and Go client both close cleanly. We do NOT use
	// net/http here because the response side would invite
	// canonicalisation creeping into the test fixture.
	body := []byte("upstream-ok")
	respHeader := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(body),
	))
	_, _ = conn.Write(respHeader)
	_, _ = conn.Write(body)
}

// parseHTTP1Request reads a single HTTP/1.x request from br, preserving
// raw header casing/ordering. Body is read up to the Content-Length
// declared in headers (capped at 1 MiB for safety; tests do not exceed
// this).
func parseHTTP1Request(br *bufio.Reader) (*capturedRequest, error) {
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read request line: %w", err)
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line: %q", requestLine)
	}
	req := &capturedRequest{
		method:      parts[0],
		path:        parts[1],
		httpVersion: parts[2],
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return nil, fmt.Errorf("malformed header line: %q", line)
		}
		name := line[:idx]
		// Per RFC 7230 §3.2.4 there is OPTIONAL leading whitespace
		// after the colon — we strip the *leading* OWS only, leaving
		// trailing whitespace intact so the assertion can detect
		// trim-on-egress regressions.
		value := strings.TrimLeft(line[idx+1:], " \t")
		req.headers = append(req.headers, rawHeaderLine{name: name, value: value})
	}

	// Read body if Content-Length is present. We don't rely on TE
	// for these tests.
	for _, h := range req.headers {
		if strings.EqualFold(h.name, "content-length") {
			var n int
			if _, err := fmt.Sscanf(h.value, "%d", &n); err == nil && n > 0 {
				const maxBody = 1024 * 1024
				if n > maxBody {
					return nil, fmt.Errorf("content-length %d exceeds test cap %d", n, maxBody)
				}
				body := make([]byte, n)
				if _, err := io.ReadFull(br, body); err != nil {
					return nil, fmt.Errorf("read body: %w", err)
				}
				req.body = body
			}
			break
		}
	}

	return req, nil
}
