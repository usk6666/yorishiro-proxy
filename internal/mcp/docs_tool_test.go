package mcp

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// callDocs invokes the docs tool over a real MCP session and returns the
// result. It does not assert on IsError so both the success and the error
// paths can share it.
func callDocs(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "docs",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool docs(%v): %v", args, err)
	}
	return res
}

// callDocsOK invokes the docs tool and fails the test if the tool reported an
// error. It returns the text body.
func callDocsOK(t *testing.T, cs *gomcp.ClientSession, args map[string]any) string {
	t.Helper()
	res := callDocs(t, cs, args)
	if res.IsError {
		t.Fatalf("docs(%v) returned an error: %s", args, textContent(res))
	}
	return textContent(res)
}

func TestDocsTool_RegisteredInToolsList(t *testing.T) {
	cs := setupResourceTestSession(t)

	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var tool *gomcp.Tool
	for _, tl := range result.Tools {
		if tl.Name == "docs" {
			tool = tl
			break
		}
	}
	if tool == nil {
		t.Fatal("docs tool not found in tools/list")
	}

	// The Description is the only thing a confused agent sees before it
	// decides whether documentation is reachable at all. Assert on the
	// discovery keywords and the self-service instruction, not on the whole
	// string, so wording can be refined without test churn.
	for _, phrase := range []string{
		"documentation",
		"reference",
		"help",
		"docs()",
		`docs(topic=`,
		`section=`,
		"Prefer this over guessing parameter syntax",
	} {
		if !strings.Contains(tool.Description, phrase) {
			t.Errorf("docs Description missing key phrase %q\n--- description ---\n%s\n--- end ---",
				phrase, tool.Description)
		}
	}

	// Every topic name must be discoverable from the Description alone, so
	// an agent never needs a second round trip to learn they exist.
	for _, topic := range DocsIndex() {
		if !strings.Contains(tool.Description, topic.Name) {
			t.Errorf("docs Description does not name topic %q", topic.Name)
		}
	}
}

func TestDocsTool_IndexListsEveryTopic(t *testing.T) {
	cs := setupResourceTestSession(t)
	body := callDocsOK(t, cs, map[string]any{})

	topics := DocsIndex()
	if len(topics) != len(helpResources) {
		t.Fatalf("DocsIndex length = %d, want %d (one per help resource)", len(topics), len(helpResources))
	}

	for _, topic := range topics {
		if !strings.Contains(body, "**"+topic.Name+"**") {
			t.Errorf("index is missing topic %q", topic.Name)
		}
		if topic.Description == "" {
			t.Errorf("topic %q has an empty description", topic.Name)
		}
		if !strings.Contains(body, topic.Description) {
			t.Errorf("index is missing the description for topic %q", topic.Name)
		}
		if topic.EstTokens <= 0 {
			t.Errorf("topic %q has est_tokens = %d, want > 0", topic.Name, topic.EstTokens)
		}
		// Every help document has at least one H2, so every index entry
		// must carry a section list.
		if len(topic.Sections) == 0 {
			t.Errorf("topic %q has no H2 sections", topic.Name)
		}
		for _, sec := range topic.Sections {
			if !strings.Contains(body, sec) {
				t.Errorf("index is missing section %q of topic %q", sec, topic.Name)
			}
		}
	}

	// The heuristic must be labelled as such so an agent does not treat it
	// as an exact budget.
	if !strings.Contains(body, "chars/4 heuristic") {
		t.Error("index does not label est_tokens as a heuristic")
	}

	// The concept topics the milestone requires.
	for _, required := range []string{"getting-started", "examples", "template-syntax", "docs"} {
		if !strings.Contains(body, "**"+required+"**") {
			t.Errorf("index is missing required concept topic %q", required)
		}
	}
}

func TestDocsTool_IndexOmitsH3Sections(t *testing.T) {
	// The index carries H2 names only: an H2+H3 index measured larger than
	// simply reading the biggest document, which would defeat its purpose.
	// help_macro.md's "Encoder chain" is an H3 and must not appear.
	cs := setupResourceTestSession(t)
	body := callDocsOK(t, cs, map[string]any{})
	if strings.Contains(body, "Encoder chain") {
		t.Error("index leaked an H3 section name (Encoder chain); it should list H2 only")
	}
}

func TestDocsTool_FullDocument(t *testing.T) {
	cs := setupResourceTestSession(t)

	want, err := resourcesFS.ReadFile("resources/help_macro.md")
	if err != nil {
		t.Fatalf("read embedded help_macro.md: %v", err)
	}

	got := callDocsOK(t, cs, map[string]any{"topic": "macro"})
	if got != string(want) {
		t.Errorf("docs(topic=macro) is not byte-identical to the embedded document (got %d bytes, want %d)",
			len(got), len(want))
	}
}

// TestDocsTool_AcceptanceCriterion is the USK-1036 acceptance test: an agent
// that stumbles on the macro tool must be able to reach the §var§ template
// syntax through docs alone.
func TestDocsTool_AcceptanceCriterion(t *testing.T) {
	cs := setupResourceTestSession(t)

	full := callDocsOK(t, cs, map[string]any{"topic": "macro"})
	if !strings.Contains(full, "§name§") {
		t.Error("docs(topic=macro) does not reach the §name§ template syntax")
	}

	section := callDocsOK(t, cs, map[string]any{
		"topic":   "macro",
		"section": "Variable substitution syntax",
	})
	if !strings.Contains(section, "§name§") {
		t.Errorf("docs(topic=macro, section=...) does not reach the §name§ syntax:\n%s", section)
	}
	if !strings.HasPrefix(section, "## Variable substitution syntax") {
		t.Errorf("section does not start at its own heading line:\n%.80s", section)
	}
	// An H2 must bring its H3 children with it — the encoder chain and the
	// foreign-syntax warning are the parts an agent actually needs.
	for _, child := range []string{"### Encoder chain", "### False positives"} {
		if !strings.Contains(section, child) {
			t.Errorf("section is missing child heading %q", child)
		}
	}
	// ...and must stop at the next same-level heading. "## Variable
	// substitution syntax" is the last H2 in help_macro.md, so instead
	// assert the section is a strict, contiguous substring of the document.
	if !strings.Contains(full, strings.TrimRight(section, "\n")) {
		t.Error("section is not a contiguous substring of the full document")
	}
}

func TestDocsSection_Matching(t *testing.T) {
	cs := setupResourceTestSession(t)

	tests := []struct {
		name    string
		topic   string
		section string
		want    string
	}{
		{
			name:    "exact heading text",
			topic:   "macro",
			section: "Variable substitution syntax",
			want:    "## Variable substitution syntax",
		},
		{
			name:    "github slug",
			topic:   "macro",
			section: "variable-substitution-syntax",
			want:    "## Variable substitution syntax",
		},
		{
			name:    "case insensitive",
			topic:   "macro",
			section: "VARIABLE SUBSTITUTION SYNTAX",
			want:    "## Variable substitution syntax",
		},
		{
			name:    "surrounding whitespace trimmed",
			topic:   "macro",
			section: "  Variable substitution syntax  ",
			want:    "## Variable substitution syntax",
		},
		{
			name:    "h3 child is addressable on its own",
			topic:   "macro",
			section: "Encoder chain",
			want:    "### Encoder chain",
		},
		{
			name:    "h4 is addressable",
			topic:   "fuzz_http",
			section: "Macro hook scopes",
			want:    "#### Macro hook scopes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := callDocsOK(t, cs, map[string]any{"topic": tc.topic, "section": tc.section})
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("section body starts with %.60q, want prefix %q", got, tc.want)
			}
		})
	}
}

func TestDocsSection_StopsAtSameLevelHeading(t *testing.T) {
	// help_macro.md "## Actions" is followed by "## Usage Examples"; the
	// slice must include the H3 children of Actions but stop before the
	// next H2.
	body, err := DocsSection("macro", "Actions")
	if err != nil {
		t.Fatalf("DocsSection: %v", err)
	}
	if !strings.Contains(body, "### define_macro") {
		t.Error("section dropped its H3 child define_macro")
	}
	if strings.Contains(body, "## Usage Examples") {
		t.Error("section ran past the next H2 heading")
	}
}

func TestDocsSection_DuplicateHeadingReturnsFirstWithNote(t *testing.T) {
	// help_configure.md has "## Usage Examples" twice. Erroring on a
	// correctly-spelled section would block the agent, so the first match is
	// returned with a note.
	body, err := DocsSection("configure", "Usage Examples")
	if err != nil {
		t.Fatalf("DocsSection: %v", err)
	}
	if !strings.HasPrefix(body, "## Usage Examples") {
		t.Errorf("body does not start at the heading: %.60q", body)
	}
	if !strings.Contains(body, "sections in this topic share this heading; this is the first") {
		t.Errorf("duplicate-heading note missing:\n%s", body)
	}

	// The note must report the real count, and the returned slice must be
	// the FIRST occurrence.
	doc, err := DocsDocument("configure")
	if err != nil {
		t.Fatalf("DocsDocument: %v", err)
	}
	headings := scanDocsHeadings(strings.Split(doc, "\n"))
	n := 0
	for _, h := range headings {
		if h.level >= 2 && docsSectionMatches("Usage Examples", h.text) {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("fixture drift: help_configure.md now has %d 'Usage Examples' headings, want >= 2", n)
	}
	if !strings.Contains(body, "(note: "+strconv.Itoa(n)+" sections") {
		t.Errorf("note does not report the real duplicate count %d:\n%s", n, body)
	}

	firstIdx := strings.Index(doc, "## Usage Examples")
	stripped := strings.Split(body, "\n\n(note:")[0]
	if got := strings.Index(doc, stripped); got != firstIdx {
		t.Errorf("returned slice starts at offset %d, want the first occurrence at %d", got, firstIdx)
	}
}

func TestDocsTool_UnknownTopicListsAvailable(t *testing.T) {
	cs := setupResourceTestSession(t)
	res := callDocs(t, cs, map[string]any{"topic": "macroz"})
	if !res.IsError {
		t.Fatal("docs(topic=macroz) succeeded, want an error")
	}
	msg := textContent(res)
	if !strings.Contains(msg, `unknown docs topic "macroz"`) {
		t.Errorf("error does not name the bad topic: %s", msg)
	}
	for _, topic := range DocsIndex() {
		if !strings.Contains(msg, topic.Name) {
			t.Errorf("error does not list available topic %q: %s", topic.Name, msg)
		}
	}
}

func TestDocsTool_UnknownSectionListsOutline(t *testing.T) {
	cs := setupResourceTestSession(t)
	res := callDocs(t, cs, map[string]any{"topic": "macro", "section": "nope"})
	if !res.IsError {
		t.Fatal("docs(topic=macro, section=nope) succeeded, want an error")
	}
	msg := textContent(res)
	if !strings.Contains(msg, `unknown section "nope" in docs topic "macro"`) {
		t.Errorf("error does not name the bad section: %s", msg)
	}
	// The outline compensates for the H2-only index: it must be
	// level-prefixed and reach H3/H4.
	for _, want := range []string{"## Parameters", "## Actions", "### Encoder chain"} {
		if !strings.Contains(msg, want) {
			t.Errorf("outline missing %q:\n%s", want, msg)
		}
	}
}

func TestDocsBody_SectionWithoutTopic(t *testing.T) {
	_, err := docsBody("", "Parameters")
	if err == nil {
		t.Fatal("docsBody(\"\", \"Parameters\") succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "requires a topic") {
		t.Errorf("error does not explain the fix: %v", err)
	}
}

func TestDocsBody_EmptySectionReturnsWholeDocument(t *testing.T) {
	full, err := DocsDocument("proxy_stop")
	if err != nil {
		t.Fatalf("DocsDocument: %v", err)
	}
	for _, section := range []string{"", "   "} {
		got, err := docsBody("proxy_stop", section)
		if err != nil {
			t.Fatalf("docsBody(proxy_stop, %q): %v", section, err)
		}
		if got != full {
			t.Errorf("docsBody(proxy_stop, %q) did not return the whole document", section)
		}
	}
}

// TestDocsTool_ReturnsSingleTextContent pins the result shape. Returning a
// typed struct would make the go-sdk marshal the document into
// StructuredContent AND duplicate it into a TextContent block — shipping a
// 20 KB document twice, JSON-escaped.
func TestDocsTool_ReturnsSingleTextContent(t *testing.T) {
	cs := setupResourceTestSession(t)
	res := callDocs(t, cs, map[string]any{"topic": "proxy_stop"})
	if res.IsError {
		t.Fatalf("docs failed: %s", textContent(res))
	}
	if len(res.Content) != 1 {
		t.Fatalf("Content length = %d, want 1", len(res.Content))
	}
	if _, ok := res.Content[0].(*gomcp.TextContent); !ok {
		t.Fatalf("Content[0] type = %T, want *mcp.TextContent", res.Content[0])
	}
	if res.StructuredContent != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		t.Errorf("StructuredContent is set (%d bytes); the document would ship twice", len(raw))
	}
}

func TestDocsIndex_ReturnsIndependentCopies(t *testing.T) {
	first := DocsIndex()
	if len(first) == 0 || len(first[0].Sections) == 0 {
		t.Fatal("DocsIndex returned nothing to mutate")
	}
	original := first[0].Sections[0]
	first[0].Sections[0] = "MUTATED"

	second := DocsIndex()
	if second[0].Sections[0] != original {
		t.Errorf("mutating a returned Sections slice leaked into the registry: got %q, want %q",
			second[0].Sections[0], original)
	}
}

func TestScanDocsHeadings_FenceAware(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []docsHeading
	}{
		{
			name: "plain headings",
			doc:  "# Title\n\n## Alpha\ntext\n### Beta\n",
			want: []docsHeading{
				{level: 1, text: "Title", start: 0},
				{level: 2, text: "Alpha", start: 2},
				{level: 3, text: "Beta", start: 4},
			},
		},
		{
			name: "hash inside a backtick fence is not a heading",
			doc:  "## Alpha\n```bash\n# not a heading\n## also not\n```\n## Beta\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 0},
				{level: 2, text: "Beta", start: 5},
			},
		},
		{
			name: "hash inside a tilde fence is not a heading",
			doc:  "## Alpha\n~~~\n# nope\n~~~\n## Beta\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 0},
				{level: 2, text: "Beta", start: 4},
			},
		},
		{
			name: "shorter fence inside a longer one does not close it",
			doc:  "## Alpha\n````\n```\n# nope\n```\n````\n## Beta\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 0},
				{level: 2, text: "Beta", start: 6},
			},
		},
		{
			name: "unterminated fence swallows the rest",
			doc:  "## Alpha\n```\n## nope\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 0},
			},
		},
		{
			name: "no space after the hash run is not a heading",
			doc:  "#tag\n#!/bin/sh\n## Real\n",
			want: []docsHeading{
				{level: 2, text: "Real", start: 2},
			},
		},
		{
			name: "seven hashes exceed the ATX maximum",
			doc:  "####### too deep\n###### H6\n",
			want: []docsHeading{
				{level: 6, text: "H6", start: 1},
			},
		},
		{
			name: "closing hash run is trimmed",
			doc:  "## Alpha ##\n## C#\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 0},
				{level: 2, text: "C#", start: 1},
			},
		},
		{
			name: "empty heading is skipped",
			doc:  "##\n## Alpha\n",
			want: []docsHeading{
				{level: 2, text: "Alpha", start: 1},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scanDocsHeadings(strings.Split(tc.doc, "\n"))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d headings %+v, want %d %+v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("heading[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestExtractDocsSection_FenceAwareBoundary(t *testing.T) {
	// A "## " line inside a fenced block must not truncate the section that
	// contains it.
	doc := "# T\n\n## Alpha\nbefore\n```\n## fake\n```\nafter\n\n## Beta\nb\n"
	got, err := extractDocsSection("fixture", doc, "Alpha")
	if err != nil {
		t.Fatalf("extractDocsSection: %v", err)
	}
	for _, want := range []string{"before", "## fake", "after"} {
		if !strings.Contains(got, want) {
			t.Errorf("section is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "## Beta") {
		t.Errorf("section ran past the next real H2:\n%s", got)
	}
}

func TestExtractDocsSection_H1NotAddressable(t *testing.T) {
	doc := "# Title\n\n## Alpha\na\n"
	if _, err := extractDocsSection("fixture", doc, "Title"); err == nil {
		t.Fatal("H1 was addressable, want an error")
	}
}

func TestSlugifyDocsHeading(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Variable substitution syntax", "variable-substitution-syntax"},
		{"variable-substitution-syntax", "variable-substitution-syntax"},
		{"Usage Examples", "usage-examples"},
		{"action (string, required)", "action-string-required"},
		{"  Trim Me  ", "trim-me"},
		{"HTTP/2 & gRPC", "http2--grpc"},
		{"__reserved__", "__reserved__"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := slugifyDocsHeading(tc.in); got != tc.want {
				t.Errorf("slugifyDocsHeading(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDocsSectionMatches_EmptySelectorNeverMatches(t *testing.T) {
	if docsSectionMatches("", "Alpha") {
		t.Error("empty selector matched a heading")
	}
	if docsSectionMatches("   ", "Alpha") {
		t.Error("whitespace-only selector matched a heading")
	}
}

// TestTools_NoHelpURIInToolSurface asserts over tools/list — the exact bytes
// an MCP client receives — rather than over source text, so it covers
// Descriptions AND generated InputSchemas (a jsonschema struct tag carried
// one of these URIs) while inherently excluding the legitimate resource
// registrations in resources.go.
func TestTools_NoHelpURIInToolSurface(t *testing.T) {
	cs := setupResourceTestSession(t)

	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(result.Tools) == 0 {
		t.Fatal("tools/list returned no tools")
	}

	for _, tl := range result.Tools {
		if strings.Contains(tl.Description, "yorishiro://help/") {
			t.Errorf("tool %q Description still points at an unfetchable resource URI; "+
				"use `Full reference: call docs(topic=%q).` instead\n%s", tl.Name, tl.Name, tl.Description)
		}
		if tl.InputSchema == nil {
			continue
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal %q InputSchema: %v", tl.Name, err)
		}
		if strings.Contains(string(raw), "yorishiro://help/") {
			t.Errorf("tool %q InputSchema still points at an unfetchable resource URI:\n%s", tl.Name, raw)
		}
	}
}
