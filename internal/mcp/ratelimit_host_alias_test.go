package mcp

import (
	"context"
	"net"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestResendHTTP_RateLimitHostAliasSharesBucket (USK-1263): resend_http to
// "localhost.:P" waits on the same per-host bucket as "localhost", so an
// agent cannot dodge security.set_rate_limits by respelling the host.
func TestResendHTTP_RateLimitHostAliasSharesBucket(t *testing.T) {
	echo := startRateLimitEcho(t)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(echo.URL, "http://"))
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}

	for _, alias := range []string{"localhost.", "LOCALHOST."} {
		t.Run(alias, func(t *testing.T) {
			rl := connector.NewRateLimiter()
			// One token per host that does not refill within the test.
			rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerHostPerSecond: 0.001})
			if d := rl.Check("localhost"); d != nil {
				t.Fatalf("drain Check(localhost) denied: %+v", d)
			}
			cs := setupRateLimitFuzzSession(t, rl)

			authority := net.JoinHostPort(alias, port)
			res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "resend_http",
				Arguments: map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": authority,
					"path":      "/",
					"headers": []map[string]any{
						{"name": "Host", "value": authority},
					},
					"timeout_ms": 300,
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("resend_http to %s succeeded; want a rate-limit wait error (bucket for localhost is drained)", authority)
			}
			msg := ""
			if err != nil {
				msg = err.Error()
			} else {
				msg = extractTextContent(res)
			}
			if !strings.Contains(msg, "rate limit") {
				t.Errorf("resend_http error = %q, want a rate limit wait error", msg)
			}
		})
	}
}
