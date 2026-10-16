package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1141: the max_connections default is stated in three places Go cannot
// derive from the constant — the proxy_start jsonschema struct tag, the
// hand-written yorishiro://schema/proxy_start resource, and the
// yorishiro://help/proxy_start resource. These guards keep each of them in
// step with connector.DefaultMaxConnections, which is what the listener and
// the USK-407 reset path actually apply.

// proxyStartToolSchema returns the proxy_start tool's generated InputSchema
// as a decoded JSON object, exactly as an MCP client receives it from
// tools/list.
func proxyStartToolSchema(t *testing.T) map[string]any {
	t.Helper()

	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tl := range result.Tools {
		if tl.Name != "proxy_start" {
			continue
		}
		if tl.InputSchema == nil {
			t.Fatal("proxy_start tool has no InputSchema")
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal InputSchema: %v", err)
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("unmarshal InputSchema: %v", err)
		}
		return schema
	}
	t.Fatal("proxy_start tool not found in tools/list")
	return nil
}

// readResourceText returns the text of a single-content MCP resource.
func readResourceText(t *testing.T, uri string) string {
	t.Helper()

	cs := setupResourceTestSession(t)
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("ReadResource(%s): %v", uri, err)
	}
	if len(result.Contents) == 0 {
		t.Fatalf("ReadResource(%s): no contents", uri)
	}
	return result.Contents[0].Text
}

func TestProxyStartDocs_MaxConnectionsDefaultMatchesConstant(t *testing.T) {
	want := strconv.Itoa(connector.DefaultMaxConnections)

	t.Run("tool schema description", func(t *testing.T) {
		props := navSchema(t, proxyStartToolSchema(t), "properties")
		desc := schemaDescription(t, props, "max_connections")
		if !strings.Contains(desc, "(default: "+want+")") {
			t.Errorf("proxy_start tool max_connections description = %q, want it to state default %s", desc, want)
		}
	})

	t.Run("schema resource description", func(t *testing.T) {
		var schema map[string]any
		if err := json.Unmarshal([]byte(readResourceText(t, "yorishiro://schema/proxy_start")), &schema); err != nil {
			t.Fatalf("unmarshal schema/proxy_start: %v", err)
		}
		desc := schemaDescription(t, navSchema(t, schema, "properties"), "max_connections")
		if !strings.Contains(desc, "Default: "+want+".") {
			t.Errorf("schema/proxy_start max_connections description = %q, want it to state default %s", desc, want)
		}
	})

	t.Run("help resource", func(t *testing.T) {
		text := readResourceText(t, "yorishiro://help/proxy_start")
		// Scope the match to the max_connections section so another
		// parameter's "Default:" line cannot satisfy it.
		section := regexp.MustCompile(`(?s)### max_connections \(.*?\n(.*?)\n### `).FindStringSubmatch(text)
		if section == nil {
			t.Fatal("help/proxy_start has no max_connections section")
		}
		if !strings.Contains(section[1], "- Default: `"+want+"`") {
			t.Errorf("help/proxy_start max_connections section does not state default %s:\n%s", want, section[1])
		}
	})
}
