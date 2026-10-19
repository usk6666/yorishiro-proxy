package mcp

import (
	"context"
	"io/fs"
	"strings"
	"testing"
)

// TestResources_NoHandWrittenSchemaResources (USK-1153): the server ships no
// hand-written JSON Schema copies of tool inputs. Eight of the seventeen
// yorishiro://schema/* resources had drifted from the InputSchema the go-sdk
// actually validates against (intercept advertised override_* fields that
// are rejected as unknown properties). The only tool schema an agent can
// obtain is the one tools/list returns.
func TestResources_NoHandWrittenSchemaResources(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(result.Resources) == 0 {
		t.Fatal("ListResources returned no resources at all")
	}
	for _, r := range result.Resources {
		if strings.HasPrefix(r.URI, "yorishiro://schema/") {
			t.Errorf("schema resource %s is still registered; tool schemas are served only by tools/list", r.URI)
		}
	}

	embedded, err := fs.Glob(resourcesFS, "resources/*.json")
	if err != nil {
		t.Fatalf("glob embedded resources: %v", err)
	}
	if len(embedded) != 0 {
		t.Errorf("embedded JSON resources = %v, want none", embedded)
	}
}
