package main

// help_param_keys_test.go — USK-1153.
//
// The example guard in skill_cli_examples_test.go only sees lines that run
// `yorishiro-proxy client ...`. The "Parameters" listing of each
// clientToolHelp entry is plain prose to it, so the intercept help kept
// advertising params.override_method / override_url / override_body /
// override_status / override_response_body — fields the server has never
// accepted (the go-sdk rejects unknown properties) — long after the
// examples were fixed. These tests tie the listing lines, and the JSON
// examples of help_intercept.md, to the live InputSchema.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// helpParamLine matches a parameter-listing line of a clientToolHelp entry:
// indented, an optional "--" flag prefix, then a dotted key followed by "="
// (or ":=" for the explicit-JSON form).
var helpParamLine = regexp.MustCompile(`^\s+(?:--)?([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*):?=`)

// helpParamKey is one parameter key advertised by a clientToolHelp entry.
type helpParamKey struct {
	Tool string
	Line int // 1-based within the help string
	Key  string
}

// helpParamKeys returns every parameter key listed by one clientToolHelp
// entry. Example lines (those running the client command) are left to the
// example guard.
func helpParamKeys(tool, help string) []helpParamKey {
	var out []helpParamKey
	for i, line := range strings.Split(help, "\n") {
		if strings.Contains(line, clientCommandMarker) {
			continue
		}
		if m := helpParamLine.FindStringSubmatch(line); m != nil {
			out = append(out, helpParamKey{Tool: tool, Line: i + 1, Key: m[1]})
		}
	}
	return out
}

// unresolvedHelpParamKey reports why key does not name a parameter in the
// tool's live InputSchema, or "" when it does. The walk is the CLI's own
// (resolveKeyPath), so a key the help lists is exactly a key the CLI can
// type and the server will accept.
func unresolvedHelpParamKey(schema *toolSchema, key string) string {
	if schema == nil {
		return "tool is not in the server's tools/list"
	}
	if _, leaf := resolveKeyPath(key, schema); leaf == nil {
		return "not a property of the live InputSchema"
	}
	return ""
}

// minHelpParamKeys is the non-vacuity floor for the parameter-listing
// guard: well below the ~190 keys the help currently lists, far above what
// a broken regex would still match.
const minHelpParamKeys = 100

// TestClientToolHelpParamKeys_ResolveInLiveSchema: every parameter key a
// `yorishiro-proxy client <tool> --help` listing advertises must exist in
// that tool's live InputSchema.
func TestClientToolHelpParamKeys_ResolveInLiveSchema(t *testing.T) {
	ctx, session := newValidationSession(t)

	total := 0
	for _, tool := range sortedKeys(clientToolHelp) {
		schema := fetchToolSchema(ctx, session, tool)
		for _, k := range helpParamKeys(tool, clientToolHelp[tool]) {
			total++
			if why := unresolvedHelpParamKey(schema, k.Key); why != "" {
				t.Errorf("clientToolHelp[%s]:%d: %s: %s", k.Tool, k.Line, k.Key, why)
			}
		}
	}
	if total < minHelpParamKeys {
		t.Errorf("checked %d parameter keys across clientToolHelp, want >= %d (is the listing regex still matching?)", total, minHelpParamKeys)
	}
}

// TestClientToolHelpParamKeys_Controls pins the extractor and the resolver
// with fixtures: a key the schema lacks must be flagged, real keys (top
// level, nested, flag-style, explicit-JSON) must not be, and example lines
// are not parameter listings.
func TestClientToolHelpParamKeys_Controls(t *testing.T) {
	ctx, session := newValidationSession(t)

	help := strings.Join([]string{
		"intercept: fixture.",
		"",
		"Parameters (key=value):",
		"  action=<action>                 required",
		"  params.intercept_id=<id>        nested",
		"  --http.method=<m>               flag style",
		"  ws.opcode:=1                    explicit JSON",
		"  params.bogus=<x>                not in the schema",
		"  http.override_body=<x>          not in the schema either",
		"",
		"Examples:",
		"  yorishiro-proxy client intercept action=release params.nothing_here=1",
	}, "\n")

	keys := helpParamKeys("intercept", help)
	var gotKeys []string
	for _, k := range keys {
		gotKeys = append(gotKeys, k.Key)
	}
	wantKeys := "action params.intercept_id http.method ws.opcode params.bogus http.override_body"
	if strings.Join(gotKeys, " ") != wantKeys {
		t.Fatalf("helpParamKeys = %q, want %q", gotKeys, wantKeys)
	}

	schema := fetchToolSchema(ctx, session, "intercept")
	var flagged []string
	for _, k := range keys {
		if unresolvedHelpParamKey(schema, k.Key) != "" {
			flagged = append(flagged, k.Key)
		}
	}
	if got, want := strings.Join(flagged, " "), "params.bogus http.override_body"; got != want {
		t.Errorf("flagged keys = %q, want %q", got, want)
	}
	if unresolvedHelpParamKey(nil, "action") == "" {
		t.Error("a key of an unknown tool (nil schema) must be flagged")
	}
}

// jsonFence matches a ```json fenced block in a Markdown document.
var jsonFence = regexp.MustCompile("(?s)```json\n(.*?)\n```")

// TestHelpInterceptJSONExamples_AcceptedByLiveSchema: every ```json block
// in help_intercept.md is a complete intercept argument object, and each
// one must pass the server's InputSchema validation.
func TestHelpInterceptJSONExamples_AcceptedByLiveSchema(t *testing.T) {
	ctx, session := newValidationSession(t)

	path := filepath.Join("..", "..", "internal", "mcp", "resources", "help_intercept.md")
	blocks := jsonFence.FindAllStringSubmatch(readDoc(t, path), -1)

	withHTTP, withWS := 0, 0
	for i, m := range blocks {
		t.Run(fmt.Sprintf("block%02d", i+1), func(t *testing.T) {
			var args map[string]any
			if err := json.Unmarshal([]byte(m[1]), &args); err != nil {
				t.Fatalf("not a JSON object: %v\n%s", err, m[1])
			}
			if _, err := session.CallTool(ctx, &gomcp.CallToolParams{Name: "intercept", Arguments: args}); err != nil {
				t.Errorf("server rejects the example: %v\n%s", err, m[1])
			}
		})
		if strings.Contains(m[1], `"http"`) {
			withHTTP++
		}
		if strings.Contains(m[1], `"ws"`) {
			withWS++
		}
	}
	if len(blocks) < 4 {
		t.Errorf("help_intercept.md has %d ```json examples, want >= 4", len(blocks))
	}
	if withHTTP == 0 {
		t.Error("help_intercept.md has no ```json example using the http payload")
	}
	if withWS == 0 {
		t.Error("help_intercept.md has no ```json example using the ws payload")
	}
}
