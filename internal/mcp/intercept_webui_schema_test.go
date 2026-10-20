package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// webUIInterceptSchemaFixture is the checked-in copy of the intercept
// tool's InputSchema that the WebUI's vitest suite validates its
// Modify & Forward payloads against. Keeping it next to the TypeScript
// builder lets the web tests run without a Go toolchain while this test
// guarantees the copy never drifts from what tools/list advertises.
var webUIInterceptSchemaFixture = filepath.Join("..", "..", "web", "src", "lib", "mcp", "__fixtures__", "intercept.input-schema.json")

// updateWebUISchemaFixtureEnv regenerates the fixture instead of
// comparing against it.
const updateWebUISchemaFixtureEnv = "UPDATE_WEBUI_SCHEMA_FIXTURE"

// TestInterceptInputSchema_MatchesWebUIFixture fails when the intercept
// tool's InputSchema, exactly as an MCP client receives it from
// tools/list, differs from the fixture the WebUI tests validate against.
// Regenerate with UPDATE_WEBUI_SCHEMA_FIXTURE=1.
func TestInterceptInputSchema_MatchesWebUIFixture(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var schema any
	for _, tl := range result.Tools {
		if tl.Name != "intercept" {
			continue
		}
		if tl.InputSchema == nil {
			t.Fatal("intercept tool has no InputSchema")
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal InputSchema: %v", err)
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("unmarshal InputSchema: %v", err)
		}
	}
	if schema == nil {
		t.Fatal("intercept tool not found in tools/list")
	}

	want, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	want = append(want, '\n')

	if os.Getenv(updateWebUISchemaFixtureEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(webUIInterceptSchemaFixture), 0o755); err != nil {
			t.Fatalf("mkdir fixture dir: %v", err)
		}
		if err := os.WriteFile(webUIInterceptSchemaFixture, want, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	got, err := os.ReadFile(webUIInterceptSchemaFixture)
	if err != nil {
		t.Fatalf("read fixture %s: %v (regenerate with %s=1)", webUIInterceptSchemaFixture, err, updateWebUISchemaFixtureEnv)
	}
	var gotSchema any
	if err := json.Unmarshal(got, &gotSchema); err != nil {
		t.Fatalf("fixture %s is not valid JSON: %v", webUIInterceptSchemaFixture, err)
	}
	if !reflect.DeepEqual(gotSchema, schema) {
		t.Fatalf("fixture %s drifted from the intercept InputSchema; regenerate with %s=1\n--- want ---\n%s",
			webUIInterceptSchemaFixture, updateWebUISchemaFixtureEnv, want)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fixture %s is semantically equal but not canonically formatted; regenerate with %s=1",
			webUIInterceptSchemaFixture, updateWebUISchemaFixtureEnv)
	}
}
