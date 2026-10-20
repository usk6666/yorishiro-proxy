//go:build e2e && !e2e_smoke

package main

// client_intercept_help_integration_test.go — USK-1153.
//
// The example guard (skill_cli_examples_test.go) proves a clientToolHelp
// example passes InputSchema validation, against no-op handlers. This test
// goes the rest of the way for the intercept help: each modify_and_forward
// example printed by `yorishiro-proxy client intercept --help` is run
// through the real CLI (runClientTool, Streamable HTTP) against a
// production-wired server holding a real HTTP request, and the upstream
// must receive exactly the modification the example asks for.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const (
	interceptHelpUpstreamBody = "upstream-ok"
	// The held request's path and query, before any example modifies it.
	interceptHelpOrigPath  = "/original"
	interceptHelpOrigQuery = "x=1"
)

// observedHTTPRequest is one HTTP/1.x request as the upstream read it off
// the wire: header names keep their wire casing and order.
type observedHTTPRequest struct {
	method, target string
	headers        [][2]string
	body           []byte
}

// rawRecordingUpstream is a minimal HTTP/1.x origin on a raw TCP listener.
// It records each request without net/http normalisation and answers
// 200 interceptHelpUpstreamBody with Connection: close.
type rawRecordingUpstream struct {
	ln   net.Listener
	reqs chan observedHTTPRequest
	wg   sync.WaitGroup
}

func startRawRecordingUpstream(t *testing.T) *rawRecordingUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	u := &rawRecordingUpstream{ln: ln, reqs: make(chan observedHTTPRequest, 16)}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			u.wg.Add(1)
			go func() {
				defer u.wg.Done()
				u.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		u.wg.Wait()
	})
	return u
}

func (u *rawRecordingUpstream) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) != 3 {
		return
	}
	req := observedHTTPRequest{method: parts[0], target: parts[1]}
	contentLength := 0
	for {
		hl, err := br.ReadString('\n')
		if err != nil {
			return
		}
		hl = strings.TrimRight(hl, "\r\n")
		if hl == "" {
			break
		}
		name, value, ok := strings.Cut(hl, ":")
		if !ok {
			return
		}
		value = strings.TrimSpace(value)
		req.headers = append(req.headers, [2]string{name, value})
		if strings.EqualFold(name, "Content-Length") {
			contentLength, _ = strconv.Atoi(value)
		}
	}
	if contentLength > 0 {
		req.body = make([]byte, contentLength)
		if _, err := io.ReadFull(br, req.body); err != nil {
			return
		}
	}
	u.reqs <- req
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(interceptHelpUpstreamBody), interceptHelpUpstreamBody)
}

func (u *rawRecordingUpstream) addr() string { return u.ln.Addr().String() }

// waitForInterceptQueueEntryID polls the intercept_queue resource until an
// entry is held and returns its id.
func waitForInterceptQueueEntryID(t *testing.T, h *mcptest.Harness) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{"resource": "intercept_queue"})
		items, _ := res.Decoded["items"].([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if id, _ := m["id"].(string); id != "" {
					return id
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a held intercept_queue entry")
	return ""
}

type proxiedResult struct {
	status int
	body   string
	err    error
}

func TestE2E_ClientInterceptHelp_ModifyAndForwardExamples(t *testing.T) {
	// The arguments each help example produces, typed exactly as the CLI
	// will type them (same schema, same buildToolParams).
	schemaCtx, schemaSession := newInMemoryToolSession(t)
	schema := fetchToolSchema(schemaCtx, schemaSession, "intercept")
	if schema == nil {
		t.Fatal("intercept tool not in tools/list")
	}

	var examples []cliExample
	for _, ex := range extractHelpExamples("intercept", clientToolHelp["intercept"]) {
		if ex.Err == nil && len(ex.Args) > 1 && ex.Args[0] == "intercept" && ex.Args[1] == "action=modify_and_forward" {
			examples = append(examples, ex)
		}
	}
	if len(examples) == 0 {
		t.Fatal("clientToolHelp[intercept] has no `action=modify_and_forward` example")
	}

	upstream := startRawRecordingUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	defer h.Cleanup()

	res := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"intercept_rules": []map[string]any{{
			"id":        "hold-all-requests",
			"enabled":   true,
			"protocol":  "http",
			"direction": "request",
			"http":      map[string]any{"path_pattern": ".*"},
		}},
	})
	proxyAddr, _ := res.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start returned no listen_addr: %+v", res.Decoded)
	}
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	httpClient := &gohttp.Client{
		Transport: &gohttp.Transport{Proxy: gohttp.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   30 * time.Second,
	}
	conn := harnessClientConnArgs(t, h)

	for _, ex := range examples {
		t.Run(ex.name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			targetPrefix := "http://" + upstream.addr()
			resCh := make(chan proxiedResult, 1)
			go func() {
				resp, err := httpClient.Get(targetPrefix + interceptHelpOrigPath + "?" + interceptHelpOrigQuery)
				if err != nil {
					resCh <- proxiedResult{err: err}
					return
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				resCh <- proxiedResult{status: resp.StatusCode, body: string(b), err: err}
			}()

			id := waitForInterceptQueueEntryID(t, h)

			// The help example verbatim, except for its placeholder id.
			toolArgs := make([]string, 0, len(ex.Args)-1)
			replaced := false
			for _, a := range ex.Args[1:] {
				if strings.HasPrefix(a, "params.intercept_id=") {
					a = "params.intercept_id=" + id
					replaced = true
				}
				toolArgs = append(toolArgs, a)
			}
			if !replaced {
				t.Fatalf("example has no params.intercept_id= placeholder: %q", ex.Args)
			}

			var warnings bytes.Buffer
			params, err := buildToolParams("intercept", toolArgs, schema, &warnings)
			if err != nil || warnings.Len() > 0 {
				t.Fatalf("buildToolParams: err=%v warnings=%q", err, warnings.String())
			}
			if err := runClientTool(ctx, "intercept", append(append([]string{}, conn...), toolArgs...)); err != nil {
				t.Fatalf("`yorishiro-proxy client %s`: %v", strings.Join(ex.Args, " "), err)
			}

			httpMod, _ := params["http"].(map[string]any)
			if len(httpMod) == 0 {
				t.Fatalf("modify_and_forward example sets no http.* field: %q", ex.Args)
			}

			var got observedHTTPRequest
			select {
			case got = <-upstream.reqs:
			case <-time.After(15 * time.Second):
				t.Fatal("upstream received no request after modify_and_forward")
			}

			checked := 0
			if v, ok := httpMod["method"].(string); ok {
				checked++
				if got.method != v {
					t.Errorf("upstream method = %q, want %q", got.method, v)
				}
			}
			// The client sends an absolute-form target through the forward
			// proxy. The HTTP/1.x Layer forwards it verbatim and splices a
			// rewritten path / raw_query behind the wire "scheme://authority"
			// prefix (RFC-001 §9.3, USK-1148), so the upstream must see
			// exactly that target — the untouched original when the example
			// changes neither field.
			wantPath, wantQuery := interceptHelpOrigPath, interceptHelpOrigQuery
			if v, ok := httpMod["path"].(string); ok {
				checked++
				wantPath = v
			}
			if v, ok := httpMod["raw_query"].(string); ok {
				checked++
				wantQuery = v
			}
			wantTarget := targetPrefix + wantPath
			if wantQuery != "" {
				wantTarget += "?" + wantQuery
			}
			if got.target != wantTarget {
				t.Errorf("upstream request-target = %q, want %q", got.target, wantTarget)
			}
			if v, ok := httpMod["body"].(string); ok {
				checked++
				if string(got.body) != v {
					t.Errorf("upstream body = %q, want %q", got.body, v)
				}
			}
			if hs, ok := httpMod["headers"].([]any); ok {
				checked++
				for _, e := range hs {
					kv, _ := e.(map[string]any)
					name, _ := kv["name"].(string)
					value, _ := kv["value"].(string)
					found := false
					for _, gh := range got.headers {
						if gh[0] == name && gh[1] == value {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("upstream missing header line %q: %q; got %q", name, value, got.headers)
					}
				}
				// http.headers is a full replacement, not a merge: the
				// upstream header list must be exactly the supplied list.
				// Headers the Go client sent but the example omits
				// (User-Agent, Accept-Encoding, ...) must not survive.
				// Content-Length is proxy-managed and excluded.
				want := make([][2]string, 0, len(hs))
				for _, e := range hs {
					kv, _ := e.(map[string]any)
					name, _ := kv["name"].(string)
					value, _ := kv["value"].(string)
					want = append(want, [2]string{name, value})
				}
				gotNoCL := make([][2]string, 0, len(got.headers))
				for _, gh := range got.headers {
					if !strings.EqualFold(gh[0], "Content-Length") {
						gotNoCL = append(gotNoCL, gh)
					}
				}
				if fmt.Sprint(gotNoCL) != fmt.Sprint(want) {
					t.Errorf("upstream header list = %q, want exactly the supplied list %q (full replacement, Content-Length excluded)", gotNoCL, want)
				}
			}
			if checked == 0 {
				t.Fatalf("example's http payload %v sets none of method/path/raw_query/body/headers; extend the assertions", httpMod)
			}

			select {
			case r := <-resCh:
				if r.err != nil {
					t.Fatalf("proxied request: %v", r.err)
				}
				if r.status != gohttp.StatusOK || r.body != interceptHelpUpstreamBody {
					t.Errorf("client got %d %q, want 200 %q", r.status, r.body, interceptHelpUpstreamBody)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("client received no response")
			}
		})
	}
}
