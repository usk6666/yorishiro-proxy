package connector

import (
	"bufio"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// forwardTargetCases are request heads in the shapes curl / browsers send
// to an explicit forward proxy (absolute-form + Host), plus the edge cases
// peekForwardTarget already pins (target_port_test.go,
// host_name_leg_parsing_test.go).
var forwardTargetCases = []struct {
	name    string
	raw     string
	want    string
	wantErr bool
}{
	{name: "absolute-form wins over Host", raw: "GET http://a.example/x HTTP/1.1\r\nHost: b.example\r\n\r\n", want: "a.example:80"},
	{name: "absolute-form upper-case scheme keeps authority case", raw: "GET HTTP://A.Example:8080/ HTTP/1.1\r\nHost: b.example\r\n\r\n", want: "A.Example:8080"},
	{name: "https absolute-form falls back to Host", raw: "GET https://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n", want: "b.example:80"},
	{name: "origin-form Host default port", raw: "GET / HTTP/1.1\r\nHost: b.example\r\n\r\n", want: "b.example:80"},
	{name: "origin-form Host explicit port", raw: "GET / HTTP/1.1\r\nHost: b.example:8081\r\n\r\n", want: "b.example:8081"},
	{name: "origin-form Host OWS trimmed", raw: "GET / HTTP/1.1\r\nHost:   b.example  \r\n\r\n", want: "b.example:80"},
	{name: "absolute-form IPv6", raw: "GET http://[::1]:8080/ HTTP/1.1\r\nHost: x\r\n\r\n", want: "[::1]:8080"},
	{name: "origin-form IPv6 no port", raw: "GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", want: "[::1]:80"},
	{name: "first Host wins", raw: "GET / HTTP/1.1\r\nhost: first.example\r\nHost: second.example\r\n\r\n", want: "first.example:80"},
	{name: "service-name port refused", raw: "GET / HTTP/1.1\r\nHost: b.example:postgresql\r\n\r\n", wantErr: true},
	{name: "out-of-range port refused", raw: "GET http://b.example:70000/ HTTP/1.1\r\nHost: x\r\n\r\n", wantErr: true},
	{name: "absolute-form without authority refused", raw: "GET http:///x HTTP/1.1\r\nHost: b.example\r\n\r\n", wantErr: true},
	{name: "origin-form without Host refused", raw: "GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n", wantErr: true},
	{name: "CONNECT refused", raw: "CONNECT b.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n", wantErr: true},
	{name: "whitespace before colon is not Host", raw: "GET / HTTP/1.1\r\nHost : b.example\r\n\r\n", wantErr: true},
	// The parser folds the continuation into the value; the peek must see
	// the same value (it used to stop at the first line). The folded name
	// passes SplitTargetHostPort, as any unresolvable name does; the dial
	// then fails.
	{name: "obs-fold Host folded like the parser", raw: "GET / HTTP/1.1\r\nHost: b.example\r\n c.example\r\n\r\n", want: "b.example c.example:80"},
}

// parsedTargetOf runs raw through the HTTP/1 parser the client Layer uses
// and resolves the target from the parsed request.
func parsedTargetOf(t *testing.T, raw string) (string, error) {
	t.Helper()
	req, err := parser.ParseRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parser.ParseRequest(%q): %v", raw, err)
	}
	return resolveForwardTarget(req.Method, req.RequestURI, req.Headers)
}

// TestResolveForwardTarget_Table is T17: the resolver every request of a
// forward-proxy connection is routed by (USK-1410).
func TestResolveForwardTarget_Table(t *testing.T) {
	for _, c := range forwardTargetCases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsedTargetOf(t, c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("resolveForwardTarget = %q, nil; want error", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("resolveForwardTarget = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// TestResolveForwardTarget_PeekParity is T17's parity half: the first
// request's peek and every parsed request resolve the same target, so a
// connection never switches upstream on a difference between two readers
// of the same bytes (USK-1410).
func TestResolveForwardTarget_PeekParity(t *testing.T) {
	for _, c := range forwardTargetCases {
		t.Run(c.name, func(t *testing.T) {
			peeked, perr := peekTargetOf(t, c.raw)
			parsed, rerr := parsedTargetOf(t, c.raw)
			if (perr != nil) != (rerr != nil) || peeked != parsed {
				t.Fatalf("peek = %q, %v; parsed = %q, %v; want identical", peeked, perr, parsed, rerr)
			}
		})
	}
}
