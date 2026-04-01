//go:build e2e

package proxy_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// --- helpers ----------------------------------------------------------------

// buildSafetyProxy creates a production-wired proxy with the given safety engine.
// It also starts an upstream HTTP server using the provided handler.
// Returns the proxy client, upstream address, and cleanup function.
func buildSafetyProxy(
	t *testing.T,
	ctx context.Context,
	engine *safety.Engine,
	upstreamHandler gohttp.Handler,
) (client *gohttp.Client, upstreamAddr string, cleanup func()) {
	t.Helper()

	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: true,
	}

	listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, engine)

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		proxyCancel()
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: upstreamHandler}
	go upstream.Serve(upstreamListener)

	upstreamAddr = upstreamListener.Addr().String()

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client = &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	cleanup = func() {
		upstream.Close()
		proxyCancel()
	}
	return client, upstreamAddr, cleanup
}

// mustNewInputEngine creates an engine with the given input preset and block action.
func mustNewInputEngine(t *testing.T, preset string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: preset, Action: "block"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// mustNewOutputEngine creates an engine with the given output presets (mask action).
func mustNewOutputEngine(t *testing.T, presets ...string) *safety.Engine {
	t.Helper()
	rules := make([]safety.RuleConfig, len(presets))
	for i, p := range presets {
		rules[i] = safety.RuleConfig{Preset: p, Action: "mask"}
	}
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: rules,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// mustNewLogOnlyOutputEngine creates an engine with output preset in log_only mode.
func mustNewLogOnlyOutputEngine(t *testing.T, presets ...string) *safety.Engine {
	t.Helper()
	rules := make([]safety.RuleConfig, len(presets))
	for i, p := range presets {
		rules[i] = safety.RuleConfig{Preset: p, Action: "log_only"}
	}
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: rules,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// postBody sends a POST request with the given body through the proxy and
// returns the response status code and body.
func postBody(t *testing.T, client *gohttp.Client, targetURL string, body string) (int, string) {
	t.Helper()
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// getURL sends a GET request through the proxy and returns the response status
// code and body.
func getURL(t *testing.T, client *gohttp.Client, targetURL string) (int, string) {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// --- Input Filter Bypass Resilience Tests ------------------------------------

func TestSafetyFilterBypass_InputFilter_SQLInjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-sql")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	baseURL := fmt.Sprintf("http://%s/api/query", addr)

	tests := []struct {
		name     string
		payload  string
		wantCode int
		target   string // "body" or "query"
	}{
		// Plain destructive SQL — must be blocked
		{
			name:     "plain DROP TABLE in body",
			payload:  "DROP TABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// Case mixing bypass attempt
		{
			name:     "mixed case dRoP tAbLe in body",
			payload:  "dRoP tAbLe users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "all lowercase drop table in body",
			payload:  "drop table users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "all uppercase DROP TABLE in body",
			payload:  "DROP TABLE USERS;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// SQL comment insertion bypass attempt.
		// Note: "DR/**/OP" splits the keyword "DROP" itself with a comment.
		// The regex expects the full word "DROP" followed by whitespace/comment,
		// so this intra-keyword comment injection is a known bypass.
		{
			name:     "SQL comment DR/**/OP TABLE in body (known bypass: intra-keyword comment)",
			payload:  "DR/**/OP TABLE users;",
			wantCode: gohttp.StatusOK,
			target:   "body",
		},
		{
			name:     "SQL comment DROP/*comment*/TABLE in body",
			payload:  "DROP/*comment*/TABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "SQL multi-comment DROP /* x */ TABLE /* y */ users in body",
			payload:  "DROP /* x */ TABLE /* y */ users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// Whitespace variants
		{
			name:     "tab separated DROP\\tTABLE in body",
			payload:  "DROP\tTABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "newline separated DROP\\nTABLE in body",
			payload:  "DROP\nTABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "multiple spaces DROP   TABLE in body",
			payload:  "DROP   TABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// TRUNCATE variants
		{
			name:     "TRUNCATE TABLE in body",
			payload:  "TRUNCATE TABLE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		{
			name:     "mixed case tRunCaTe TaBlE in body",
			payload:  "tRunCaTe TaBlE users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// ALTER TABLE DROP variants
		{
			name:     "ALTER TABLE DROP COLUMN in body",
			payload:  "ALTER TABLE users DROP COLUMN email;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// DROP DATABASE
		{
			name:     "DROP DATABASE in body",
			payload:  "DROP DATABASE production;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// DROP VIEW
		{
			name:     "DROP VIEW in body",
			payload:  "DROP VIEW user_summary;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// EXEC xp_ (SQL Server)
		{
			name:     "EXEC xp_cmdshell in body",
			payload:  "EXEC xp_cmdshell 'whoami';",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// DELETE without WHERE
		{
			name:     "DELETE FROM without WHERE in body",
			payload:  "DELETE FROM users;",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// UPDATE WHERE 1=1
		{
			name:     "UPDATE SET WHERE 1=1 in body",
			payload:  "UPDATE users SET role='admin' WHERE 1=1",
			wantCode: gohttp.StatusForbidden,
			target:   "body",
		},
		// Query string target: when sent through Go's HTTP client, spaces are
		// percent-encoded to %20 so the proxy sees "q=DROP%20TABLE%20users"
		// in the raw URL. The regex matches \s but not %20, so the encoded
		// form passes through. This documents current behaviour.
		{
			name:     "DROP TABLE in query string (percent-encoded by client, passes)",
			payload:  "DROP TABLE users",
			wantCode: gohttp.StatusOK,
			target:   "rawquery",
		},
		// Benign payload — must pass
		{
			name:     "benign SELECT query passes",
			payload:  "SELECT * FROM users WHERE id = 1;",
			wantCode: gohttp.StatusOK,
			target:   "body",
		},
		{
			name:     "benign INSERT passes",
			payload:  "INSERT INTO users (name) VALUES ('test');",
			wantCode: gohttp.StatusOK,
			target:   "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var statusCode int
			switch tt.target {
			case "rawquery":
				// Build a URL with the payload properly encoded in
				// the query string using url.Values.
				v := url.Values{}
				v.Set("q", tt.payload)
				targetURL := baseURL + "?" + v.Encode()
				statusCode, _ = getURL(t, client, targetURL)
			case "body":
				statusCode, _ = postBody(t, client, baseURL, tt.payload)
			default:
				t.Fatalf("unknown target: %q", tt.target)
			}
			if statusCode != tt.wantCode {
				t.Errorf("status = %d, want %d", statusCode, tt.wantCode)
			}
		})
	}
}

// TestSafetyFilterBypass_InputFilter_URLEncoded documents that URL-encoded
// payloads in the body and query string are checked in their raw
// (percent-encoded) form. The safety filter does NOT URL-decode before scanning,
// so percent-encoded destructive SQL like "DROP%20TABLE" is not blocked by the
// current implementation. This test documents this behaviour explicitly.
func TestSafetyFilterBypass_InputFilter_URLEncoded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-sql")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "reached-upstream")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	baseURL := fmt.Sprintf("http://%s/api/query", addr)

	tests := []struct {
		name    string
		payload string
		target  string
		// wantCode documents current behaviour: URL-encoded payloads are NOT
		// decoded, so they pass through the filter.
		wantCode int
	}{
		{
			name:     "URL-encoded DROP%20TABLE in body passes (not decoded)",
			payload:  "DROP%20TABLE%20users%3B",
			target:   "body",
			wantCode: gohttp.StatusOK,
		},
		{
			name:     "double-encoded %2544%2552%254F%2550 in body passes (not decoded)",
			payload:  "%2544%2552%254F%2550%2520TABLE%2520users%253B",
			target:   "body",
			wantCode: gohttp.StatusOK,
		},
		{
			name:     "URL-encoded DROP%20TABLE in query passes (not decoded)",
			payload:  "q=DROP%20TABLE%20users%3B",
			target:   "query",
			wantCode: gohttp.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var statusCode int
			if tt.target == "query" {
				targetURL := baseURL + "?" + tt.payload
				statusCode, _ = getURL(t, client, targetURL)
			} else {
				statusCode, _ = postBody(t, client, baseURL, tt.payload)
			}
			if statusCode != tt.wantCode {
				t.Errorf("status = %d, want %d (current behaviour: URL-encoded payloads are not decoded before scanning)",
					statusCode, tt.wantCode)
			}
		})
	}
}

// TestSafetyFilterBypass_InputFilter_NullByte documents that null-byte-injected
// payloads in the body are checked. The regex engine treats \x00 as a literal
// byte in the body, so "DROP\x00TABLE" does not match "DROP TABLE" and passes.
func TestSafetyFilterBypass_InputFilter_NullByte(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-sql")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "reached-upstream")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	baseURL := fmt.Sprintf("http://%s/api/query", addr)

	// Null byte between DROP and TABLE breaks the regex match.
	// This documents the current behaviour: null bytes are not stripped.
	payload := "DROP\x00TABLE users;"
	statusCode, _ := postBody(t, client, baseURL, payload)
	if statusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d (null byte splits the keyword, regex does not match)",
			statusCode, gohttp.StatusOK)
	}
}

// TestSafetyFilterBypass_InputFilter_OSCommand tests bypass resilience for
// OS command injection patterns.
func TestSafetyFilterBypass_InputFilter_OSCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-os-command")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	baseURL := fmt.Sprintf("http://%s/api/exec", addr)

	tests := []struct {
		name     string
		payload  string
		wantCode int
	}{
		// rm -rf variants
		{
			name:     "rm -rf / in body",
			payload:  "rm -rf /",
			wantCode: gohttp.StatusForbidden,
		},
		{
			name:     "rm -fr / in body",
			payload:  "rm -fr /",
			wantCode: gohttp.StatusForbidden,
		},
		{
			name:     "rm --recursive --force / in body",
			payload:  "rm --recursive --force /tmp",
			wantCode: gohttp.StatusForbidden,
		},
		{
			name:     "rm --force --recursive / in body",
			payload:  "rm --force --recursive /tmp",
			wantCode: gohttp.StatusForbidden,
		},
		// shutdown/reboot
		{
			name:     "shutdown -h now",
			payload:  "shutdown -h now",
			wantCode: gohttp.StatusForbidden,
		},
		{
			name:     "reboot command",
			payload:  "reboot now",
			wantCode: gohttp.StatusForbidden,
		},
		// mkfs
		{
			name:     "mkfs.ext4",
			payload:  "mkfs.ext4 /dev/sda1",
			wantCode: gohttp.StatusForbidden,
		},
		// dd if=
		{
			name:     "dd if=/dev/zero",
			payload:  "dd if=/dev/zero of=/dev/sda",
			wantCode: gohttp.StatusForbidden,
		},
		// Windows format
		{
			name:     "format C:",
			payload:  "format C:",
			wantCode: gohttp.StatusForbidden,
		},
		// Benign commands — must pass
		{
			name:     "ls -la passes",
			payload:  "ls -la /tmp",
			wantCode: gohttp.StatusOK,
		},
		{
			name:     "echo passes",
			payload:  "echo hello world",
			wantCode: gohttp.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode, _ := postBody(t, client, baseURL, tt.payload)
			if statusCode != tt.wantCode {
				t.Errorf("status = %d, want %d", statusCode, tt.wantCode)
			}
		})
	}
}

// TestSafetyFilterBypass_InputFilter_HeaderSQL documents that the destructive-sql
// preset targets only body, URL, and query. Header values containing destructive
// SQL are NOT scanned by the preset. This is by design: the preset's Targets are
// {TargetBody, TargetURL, TargetQuery} and do not include TargetHeaders.
func TestSafetyFilterBypass_InputFilter_HeaderSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-sql")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "upstream-reached")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	targetURL := fmt.Sprintf("http://%s/api/data", addr)

	// Create request with destructive SQL in a custom header.
	req, err := gohttp.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Query", "DROP TABLE users;")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// The preset does NOT scan headers, so the request passes through.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d (preset targets are body/url/query only, not headers)",
			resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "upstream-reached" {
		t.Errorf("body = %q, want %q", body, "upstream-reached")
	}
}

// TestSafetyFilterBypass_InputFilter_MultipartFormData documents that
// multipart/form-data payloads containing destructive SQL in a field value ARE
// blocked, because the entire body (including multipart boundaries) is scanned
// as raw bytes.
func TestSafetyFilterBypass_InputFilter_MultipartFormData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewInputEngine(t, "destructive-sql")
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	targetURL := fmt.Sprintf("http://%s/api/upload", addr)

	// Build a multipart body with destructive SQL in a field.
	boundary := "----TestBoundary123"
	var buf bytes.Buffer
	buf.WriteString("------TestBoundary123\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"query\"\r\n\r\n")
	buf.WriteString("DROP TABLE users;\r\n")
	buf.WriteString("------TestBoundary123--\r\n")

	req, err := gohttp.NewRequestWithContext(context.Background(), "POST", targetURL, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST multipart: %v", err)
	}
	defer resp.Body.Close()

	// The body scanner finds "DROP TABLE" in the raw multipart body.
	if resp.StatusCode != gohttp.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d (body: %s)", resp.StatusCode, gohttp.StatusForbidden, body)
	}
}

// --- Output Filter Tests (Compression, Chunking, Binary) ---------------------

// TestSafetyFilterBypass_OutputFilter_GzipResponse documents that the output
// filter operates on the raw response body bytes. When the upstream sends a
// gzip-compressed body, the filter scans the compressed bytes — NOT the decoded
// content. Therefore PII in a gzip-compressed body is NOT masked.
//
// This is a known limitation: real-world servers almost always use gzip, so the
// output filter is ineffective for compressed responses unless the proxy
// decompresses before scanning.
func TestSafetyFilterBypass_OutputFilter_GzipResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewOutputEngine(t, "email")

	// Upstream sends gzip-compressed body containing an email address.
	piiContent := "Contact: user@example.com for details."
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Disable Go's automatic Accept-Encoding handling by writing raw.
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		gz.Write([]byte(piiContent))
		gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(compressed.Bytes())
	})

	// NOTE: We do not use buildSafetyProxy here because we need
	// DisableCompression: true on the HTTP transport to inspect the raw
	// compressed bytes the proxy forwards.
	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: true,
	}

	listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, engine)
	defer proxyCancel()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()
	targetURL := fmt.Sprintf("http://%s/api/data", upstreamAddr)

	proxyURL, _ := url.Parse("http://" + listener.Addr())

	// Use a transport that does NOT auto-decompress, so we can inspect raw bytes.
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:              gohttp.ProxyURL(proxyURL),
			DisableCompression: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	// Decompress to verify the email is still present (not masked).
	gz, err := gzip.NewReader(bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	decoded, _ := io.ReadAll(gz)
	gz.Close()

	// The email should still be present in the decompressed body because the
	// filter scanned compressed bytes and could not find the regex pattern.
	if !strings.Contains(string(decoded), "user@example.com") {
		t.Errorf("expected PII to remain unmasked in gzip response (known limitation), got: %s", decoded)
	}
}

// TestSafetyFilterBypass_OutputFilter_DeflateResponse documents the same
// limitation as gzip: deflate-compressed bodies bypass the output filter.
func TestSafetyFilterBypass_OutputFilter_DeflateResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewOutputEngine(t, "email")

	piiContent := "Contact: user@example.com for details."
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		var compressed bytes.Buffer
		fw, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
		fw.Write([]byte(piiContent))
		fw.Close()

		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(compressed.Bytes())
	})

	// NOTE: We do not use buildSafetyProxy here because we need
	// DisableCompression: true on the HTTP transport to inspect the raw
	// compressed bytes the proxy forwards.
	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: true,
	}

	listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, engine)
	defer proxyCancel()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()
	targetURL := fmt.Sprintf("http://%s/api/data", upstreamAddr)

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:              gohttp.ProxyURL(proxyURL),
			DisableCompression: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	// Decompress deflate.
	fr := flate.NewReader(bytes.NewReader(rawBody))
	decoded, _ := io.ReadAll(fr)
	fr.Close()

	// PII remains because filter cannot match regex in compressed bytes.
	if !strings.Contains(string(decoded), "user@example.com") {
		t.Errorf("expected PII to remain unmasked in deflate response (known limitation), got: %s", decoded)
	}
}

// TestSafetyFilterBypass_OutputFilter_PlainTextMasking verifies that the output
// filter correctly masks PII in plain-text (uncompressed) responses as a
// baseline comparison to the gzip/deflate tests above.
func TestSafetyFilterBypass_OutputFilter_PlainTextMasking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewOutputEngine(t, "email", "credit-card", "japan-phone")

	tests := []struct {
		name       string
		body       string
		wantMasked string
	}{
		{
			name:       "email is masked",
			body:       "Contact: user@example.com for details.",
			wantMasked: "[MASKED:email]",
		},
		{
			name:       "credit card separated is masked",
			body:       "Card: 4111-1111-1111-1111",
			wantMasked: "[MASKED:credit_card]",
		},
		{
			name:       "phone number is masked",
			body:       "Call 090-1234-5678 for info.",
			wantMasked: "[MASKED:phone]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(gohttp.StatusOK)
				fmt.Fprint(w, tt.body)
			})

			client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
			defer cleanup()

			targetURL := fmt.Sprintf("http://%s/api/data", addr)
			_, body := getURL(t, client, targetURL)

			if !strings.Contains(body, tt.wantMasked) {
				t.Errorf("expected body to contain %q, got: %s", tt.wantMasked, body)
			}
		})
	}
}

// TestSafetyFilterBypass_OutputFilter_BinaryResponse verifies that the output
// filter does not crash or corrupt binary response bodies (e.g., image/png).
func TestSafetyFilterBypass_OutputFilter_BinaryResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewOutputEngine(t, "email", "credit-card")

	// Construct a binary body that contains no PII patterns.
	binaryData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG header
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03, 0x04}

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(binaryData)
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	targetURL := fmt.Sprintf("http://%s/image.png", addr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Binary data should pass through unmodified.
	if !bytes.Equal(body, binaryData) {
		t.Errorf("binary body was modified by output filter: got %d bytes, want %d bytes",
			len(body), len(binaryData))
	}
}

// TestSafetyFilterBypass_OutputFilter_ChunkedPII verifies that PII spanning
// chunk boundaries in a chunked transfer-encoded response is still masked.
// The proxy reassembles the full body before applying the output filter, so
// chunk-boundary splitting should not affect masking.
func TestSafetyFilterBypass_OutputFilter_ChunkedPII(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewOutputEngine(t, "email")

	// The email "user@example.com" will be written across two chunks.
	// The proxy should reassemble the full response body before filtering.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Go's HTTP server uses chunked encoding when Flush is called
		// without setting Content-Length.
		flusher, ok := w.(gohttp.Flusher)
		if !ok {
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}
		w.WriteHeader(gohttp.StatusOK)
		// Write first chunk: "Contact: user"
		w.Write([]byte("Contact: user"))
		flusher.Flush()
		// Write second chunk: "@example.com for info."
		w.Write([]byte("@example.com for info."))
		flusher.Flush()
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	targetURL := fmt.Sprintf("http://%s/api/data", addr)
	_, body := getURL(t, client, targetURL)

	if !strings.Contains(body, "[MASKED:email]") {
		t.Errorf("expected chunked PII to be masked, got: %s", body)
	}
	if strings.Contains(body, "user@example.com") {
		t.Errorf("PII should not be present in masked output, got: %s", body)
	}
}

// TestSafetyFilterBypass_OutputFilter_LogOnlyMode verifies that output filter
// in log_only mode does NOT modify the response body. PII should pass through
// unmodified.
func TestSafetyFilterBypass_OutputFilter_LogOnlyMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine := mustNewLogOnlyOutputEngine(t, "email")

	piiBody := "Contact: user@example.com for details."
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, piiBody)
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	targetURL := fmt.Sprintf("http://%s/api/data", addr)
	_, body := getURL(t, client, targetURL)

	// In log_only mode, the filter should NOT modify the body.
	if body != piiBody {
		t.Errorf("body = %q, want %q (log_only mode should not modify)", body, piiBody)
	}
}

// --- Combined Input + Output Tests ------------------------------------------

// TestSafetyFilterBypass_Combined_InputBlockAndOutputMask verifies that input
// and output filters can be configured simultaneously. Input filter blocks
// destructive payloads while output filter masks PII in allowed responses.
func TestSafetyFilterBypass_Combined_InputBlockAndOutputMask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql", Action: "block"},
		},
		OutputRules: []safety.RuleConfig{
			{Preset: "email", Action: "mask"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "Reply to user@example.com")
	})

	client, addr, cleanup := buildSafetyProxy(t, ctx, engine, upstream)
	defer cleanup()

	baseURL := fmt.Sprintf("http://%s/api/query", addr)

	// Destructive SQL should be blocked.
	t.Run("input_blocked", func(t *testing.T) {
		statusCode, _ := postBody(t, client, baseURL, "DROP TABLE users;")
		if statusCode != gohttp.StatusForbidden {
			t.Errorf("status = %d, want %d", statusCode, gohttp.StatusForbidden)
		}
	})

	// Benign request should reach upstream and have PII masked in response.
	t.Run("output_masked", func(t *testing.T) {
		_, body := getURL(t, client, baseURL)
		if !strings.Contains(body, "[MASKED:email]") {
			t.Errorf("expected email to be masked, got: %s", body)
		}
		if strings.Contains(body, "user@example.com") {
			t.Errorf("PII should not be present in response, got: %s", body)
		}
	})
}
