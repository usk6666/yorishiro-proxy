// upstream_proxy.go holds upstream-proxy helpers: HTTP CONNECT and SOCKS5
// tunnelling to an upstream proxy plus the parsing / redaction helpers for
// proxy URLs. CRLF injection (CWE-93) guards apply to the HTTP CONNECT path.
package connector

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// supportedUpstreamSchemes defines the valid schemes for upstream proxy URLs.
var supportedUpstreamSchemes = map[string]bool{
	"http":   true,
	"socks5": true,
}

// ParseUpstreamProxy parses and validates an upstream proxy URL string.
// Supported schemes: http://host:port, socks5://host:port, socks5://user:pass@host:port.
// Returns nil for an empty string (no upstream proxy).
func ParseUpstreamProxy(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream proxy URL: %w", err)
	}

	if !supportedUpstreamSchemes[u.Scheme] {
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q: supported schemes are http and socks5", u.Scheme)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("upstream proxy URL has no host: %s", rawURL)
	}

	// Ensure host:port format.
	host, port, splitErr := net.SplitHostPort(u.Host)
	if splitErr != nil {
		return nil, fmt.Errorf("upstream proxy URL must include a port (e.g. %s://host:port): %s", u.Scheme, rawURL)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("upstream proxy URL has empty host or port: %s", rawURL)
	}

	return u, nil
}

// RedactProxyURL returns a copy of the raw proxy URL string with the password
// portion of userinfo replaced by "xxxxx". If the URL cannot be parsed or has
// no password, it is returned unchanged.
func RedactProxyURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User == nil {
		return rawURL
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return rawURL
	}
	u.User = url.UserPassword(u.User.Username(), "xxxxx")
	return u.String()
}

// DialViaUpstreamProxy dials the target address through the upstream proxy.
// For HTTP proxies, it sends a CONNECT request and returns the tunneled connection.
// For SOCKS5 proxies, it uses the golang.org/x/net/proxy package.
// This function is used for CONNECT tunnel establishment (passthrough, WebSocket)
// where we need a raw TCP connection through the proxy.
func DialViaUpstreamProxy(ctx context.Context, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	if proxyURL == nil {
		return nil, fmt.Errorf("proxyURL is nil")
	}

	switch proxyURL.Scheme {
	case "http":
		return dialViaHTTPProxy(ctx, proxyURL, targetAddr, timeout)
	case "socks5":
		return dialViaSOCKS5Proxy(ctx, proxyURL, targetAddr, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

// dialViaHTTPProxy dials the target through an HTTP CONNECT proxy.
func dialViaHTTPProxy(ctx context.Context, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	// Validate targetAddr to prevent CRLF injection (CWE-93) in the CONNECT request line.
	if strings.ContainsAny(targetAddr, "\r\n") {
		return nil, fmt.Errorf("invalid target address: contains CR/LF characters")
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dial HTTP proxy %s: %w", proxyURL.Host, err)
	}

	connectReq := buildCONNECTRequest(targetAddr, proxyURL)

	// Set a deadline for the CONNECT handshake to prevent indefinite blocking
	// if the proxy accepts the TCP connection but hangs during the HTTP exchange.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set CONNECT deadline on proxy %s: %w", proxyURL.Host, err)
	}

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT to proxy %s: %w", proxyURL.Host, err)
	}

	if err := readAndValidateCONNECTResponse(conn, targetAddr, proxyURL.Host); err != nil {
		conn.Close()
		return nil, err
	}

	// Clear the deadline so subsequent I/O on the tunneled connection is not
	// constrained by the CONNECT handshake timeout.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reset deadline after CONNECT to proxy %s: %w", proxyURL.Host, err)
	}

	return conn, nil
}

// buildCONNECTRequest constructs an HTTP CONNECT request string for the given
// target address, including proxy authentication if credentials are present.
func buildCONNECTRequest(targetAddr string, proxyURL *url.URL) string {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	req += "\r\n"
	return req
}

// readAndValidateCONNECTResponse reads the HTTP CONNECT response from the proxy
// connection byte by byte and validates that it indicates success (200 status).
func readAndValidateCONNECTResponse(conn net.Conn, targetAddr, proxyHost string) error {
	var respBuf [4096]byte
	total := 0
	for total < len(respBuf) {
		n, err := conn.Read(respBuf[total : total+1])
		if err != nil {
			return fmt.Errorf("read CONNECT response from proxy %s: %w", proxyHost, err)
		}
		total += n

		// Check for \r\n\r\n (end of HTTP headers).
		if total >= 4 &&
			respBuf[total-4] == '\r' &&
			respBuf[total-3] == '\n' &&
			respBuf[total-2] == '\r' &&
			respBuf[total-1] == '\n' {
			break
		}
	}

	respStr := string(respBuf[:total])
	if len(respStr) < 12 {
		return fmt.Errorf("incomplete CONNECT response from proxy %s", proxyHost)
	}

	// Status line format: HTTP/1.x SSS reason
	statusCode := respStr[9:12]
	if statusCode != "200" {
		truncated := respStr
		if len(truncated) > 64 {
			truncated = truncated[:64]
		}
		return fmt.Errorf("CONNECT to %s via proxy %s failed: %s", targetAddr, proxyHost, truncated)
	}

	return nil
}

// dialViaSOCKS5Proxy dials the target through a SOCKS5 proxy.
func dialViaSOCKS5Proxy(ctx context.Context, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth = &proxy.Auth{
			User:     username,
			Password: password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer for %s: %w", proxyURL.Host, err)
	}

	// proxy.ContextDialer is the interface for context-aware dialing.
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		// Fallback to non-context-aware dialing.
		conn, dialErr := dialer.Dial("tcp", targetAddr)
		if dialErr != nil {
			return nil, fmt.Errorf("SOCKS5 dial %s via %s: %w", targetAddr, proxyURL.Host, dialErr)
		}
		return conn, nil
	}

	conn, err := ctxDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dial %s via %s: %w", targetAddr, proxyURL.Host, err)
	}
	return conn, nil
}
