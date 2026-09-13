// Package mcp exposes this server's own documentation through the docs tool.
//
// # Why a tool and not just a resource
//
// The help documents in internal/mcp/resources/ have always been registered
// as MCP resources (yorishiro://help/<topic>). In practice that is a dead
// end: Claude Code and most other MCP hosts never fetch a resource unless a
// human explicitly selects it, so an agent that needs the reference has no
// in-band path to it. A real user reported an agent giving up on the macro
// tool's §var§ template syntax after several guesses, with correct
// documentation sitting one unreachable resource away (USK-1036).
//
// tools/list, by contrast, is always in the model's context. The docs tool is
// therefore an additional entrance to the same single source of truth — the
// embedded resources/*.md files reached via helpResources — not a second copy
// and not a replacement. registerResources() still registers every document
// as a resource for backward compatibility.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// docsTokenCharsPerToken is the divisor behind the est_tokens heuristic. It
// is a rough chars-per-token ratio for English markdown, not a tokenizer
// count — the index says so explicitly. Adding a real tokenizer would mean a
// new external dependency, and CLAUDE.md's approved-dependency list is
// closed.
const docsTokenCharsPerToken = 4

// DocsTopic is one entry of the docs tool's topic index.
//
// Exported so cmd/yorishiro-proxy can render the same index from the CLI
// (USK-1037) without duplicating the registry or re-parsing markdown.
type DocsTopic struct {
	// Name is the topic identifier, i.e. the value passed as docs(topic=...).
	// For per-tool topics it is exactly the MCP tool name.
	Name string
	// Description is the one-line summary, shared verbatim with the topic's
	// MCP resource registration so the two surfaces cannot drift.
	Description string
	// EstTokens is a len(doc)/4 heuristic for the cost of fetching the whole
	// document. It is an order-of-magnitude hint for choosing between a full
	// fetch and a section fetch, not a tokenizer count.
	EstTokens int
	// Sections lists the document's H2 heading texts in document order. Any
	// entry is a valid section= argument.
	Sections []string
}

// docsRegistry is the immutable, lazily-built view of helpResources used by
// every docs entry point. The underlying corpus is a compile-time embed.FS,
// so the registry is built once and only ever read afterwards.
type docsRegistry struct {
	// order lists topic names in helpResources order — the order the index
	// renders them in.
	order []string
	// topics maps topic name to its index entry.
	topics map[string]DocsTopic
	// files maps topic name to its path inside resourcesFS.
	files map[string]string
}

// docsRegistryOnce builds the registry on first use and caches it. Handlers
// are read-only from then on, so no further synchronisation is needed.
var docsRegistryOnce = sync.OnceValue(buildDocsRegistry)

// buildDocsRegistry derives the docs topic namespace from helpResources.
//
// Help resources only. The 17 schema_* resources are hand-written copies of
// JSON Schemas that tools/list already delivers in full as each tool's
// InputSchema, so surfacing them here would add index tokens and force a
// namespace disambiguator for exactly zero new information.
func buildDocsRegistry() *docsRegistry {
	reg := &docsRegistry{
		order:  make([]string, 0, len(helpResources)),
		topics: make(map[string]DocsTopic, len(helpResources)),
		files:  make(map[string]string, len(helpResources)),
	}
	for _, rd := range helpResources {
		if rd.topic == "" {
			continue
		}
		data, err := resourcesFS.ReadFile(rd.filename)
		if err != nil {
			// Unreachable in a built binary: resourcesFS is populated at
			// compile time and TestResourceDefinitions_AllFilesExist asserts
			// every registry entry resolves. Skipping rather than panicking
			// keeps a hypothetical mismatch to one missing topic instead of
			// taking the MCP server down at startup.
			slog.Error("docs registry: embedded help file missing",
				"topic", rd.topic, "filename", rd.filename, "error", err)
			continue
		}
		doc := string(data)
		reg.order = append(reg.order, rd.topic)
		reg.files[rd.topic] = rd.filename
		reg.topics[rd.topic] = DocsTopic{
			Name:        rd.topic,
			Description: rd.description,
			EstTokens:   len(doc) / docsTokenCharsPerToken,
			Sections:    docsH2Sections(doc),
		}
	}
	return reg
}

// DocsIndex returns every documentation topic in index order.
//
// The returned slice and each entry's Sections slice are copies, so callers
// may sort or filter them without disturbing the shared registry.
func DocsIndex() []DocsTopic {
	reg := docsRegistryOnce()
	out := make([]DocsTopic, 0, len(reg.order))
	for _, name := range reg.order {
		t := reg.topics[name]
		t.Sections = append([]string(nil), t.Sections...)
		out = append(out, t)
	}
	return out
}

// DocsDocument returns the full markdown document for a topic, byte-identical
// to the embedded file. An unknown topic yields an error naming every valid
// topic.
func DocsDocument(topic string) (string, error) {
	reg := docsRegistryOnce()
	filename, ok := reg.files[strings.TrimSpace(topic)]
	if !ok {
		return "", unknownDocsTopicError(topic)
	}
	data, err := resourcesFS.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("read embedded docs topic %q (%s): %w", topic, filename, err)
	}
	return string(data), nil
}

// DocsSection returns a single section of a topic's document, identified by
// its heading text or GitHub-style slug (case-insensitive). An empty section
// returns the whole document. An unknown section yields an error listing that
// topic's H2–H4 outline.
func DocsSection(topic, section string) (string, error) {
	doc, err := DocsDocument(topic)
	if err != nil {
		return "", err
	}
	section = strings.TrimSpace(section)
	if section == "" {
		return doc, nil
	}
	return extractDocsSection(strings.TrimSpace(topic), doc, section)
}

// unknownDocsTopicError builds the actionable "no such topic" error. Listing
// the valid values inline matches the house idiom used by query and macro.
func unknownDocsTopicError(topic string) error {
	return fmt.Errorf("unknown docs topic %q: available topics are %s",
		topic, strings.Join(docsRegistryOnce().order, ", "))
}

// docsIndexHeader prefixes the rendered index. It restates the call shapes so
// an agent that reached the index without reading the tool description still
// knows how to drill down, and it labels est_tokens as a heuristic.
const docsIndexHeader = `# yorishiro-proxy documentation index

Call docs(topic="<name>") for a full document, or docs(topic="<name>", section="<heading>")
to return a single section of a large one. section accepts either the heading text or its
slug — docs(topic="macro", section="Variable substitution syntax") and
docs(topic="macro", section="variable-substitution-syntax") are equivalent, and matching is
case-insensitive. Requesting a section also returns its sub-sections.

est_tokens is a chars/4 heuristic, not a tokenizer count.
`

// renderDocsIndex formats the topic index as markdown for the tool response.
func renderDocsIndex() string {
	var b strings.Builder
	b.WriteString(docsIndexHeader)
	for _, t := range DocsIndex() {
		fmt.Fprintf(&b, "\n- **%s** (~%d tok) — %s\n", t.Name, t.EstTokens, t.Description)
		if len(t.Sections) > 0 {
			fmt.Fprintf(&b, "  sections: %s\n", strings.Join(t.Sections, " | "))
		}
	}
	return b.String()
}

// docsInput is the typed input for the docs tool.
type docsInput struct {
	// Topic selects the document. Omit it to receive the topic index.
	Topic string `json:"topic,omitempty" jsonschema:"documentation topic to return; omit to receive the index of every topic. Every MCP tool name is a topic (proxy_start, query, macro, fuzz_http, ...), plus the concept topics getting-started, examples, template-syntax and docs"`

	// Section narrows a large document to one heading-anchored section.
	Section string `json:"section,omitempty" jsonschema:"return only this section of the topic instead of the whole document; accepts the heading text or its slug, case-insensitively (e.g. \"Variable substitution syntax\" or \"variable-substitution-syntax\"). Sub-sections of the match are included. Requires topic"`
}

// docsToolDescription is the docs tool's tools/list description.
//
// This string is a first-class artifact of USK-1036, not boilerplate: it is
// the only thing an agent sees before deciding whether documentation is
// reachable at all. It deliberately carries the words a confused agent greps
// for (documentation, reference, help, manual, docs), enumerates every topic
// name so no second call is needed to discover them, and ends with the
// instruction to prefer a lookup over guessing syntax — the exact failure
// this Issue exists to fix. It deliberately does NOT cite a
// yorishiro://help/... URI, because an unfetchable URI is the dead end being
// removed.
const docsToolDescription = "Self-service documentation, reference and help manual for this MCP server. " +
	"Call docs() with no arguments to list every topic with a one-line summary, an estimated token cost, and its section names. " +
	"Call docs(topic=\"<tool name>\") for that tool's full reference — every tool name is a topic " +
	"(proxy_start, proxy_stop, query, manage, macro, intercept, configure, security, " +
	"resend_http, resend_ws, resend_grpc, resend_raw, fuzz_http, fuzz_ws, fuzz_grpc, fuzz_raw, " +
	"plugin_introspect, grpc_schema), plus the concept topics getting-started, examples, template-syntax and docs. " +
	"Add section=\"<heading>\" to return one section of a large document instead of the whole thing; " +
	"the heading text or its slug both work, case-insensitively, and sub-sections come with the match. " +
	"An unknown topic or section returns the list of valid ones. " +
	"Prefer this over guessing parameter syntax — e.g. call docs(topic=\"macro\", section=\"Variable substitution syntax\") " +
	"before writing a macro template, and docs(topic=\"getting-started\") before the first capture."

// registerDocs registers the docs MCP tool.
func (s *Server) registerDocs() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "docs",
		Description: docsToolDescription,
	}, s.handleDocs)
}

// handleDocs returns the requested documentation as a single TextContent
// block.
//
// Result shape: the typed out return is deliberately nil and the Out type
// parameter resolves to any, which makes the go-sdk skip its
// StructuredContent branch entirely (mcp/server.go leaves elemZero nil when
// Out is any and no OutputSchema is set, and only populates
// StructuredContent for a non-nil out). Returning a struct instead would ship
// a 20 KB markdown document twice — once JSON-escaped into
// StructuredContent, once duplicated into a TextContent block by the SDK.
//
// No output size cap is applied. The corpus is compile-time-bounded and the
// largest document is under 20 KB (~5k est tokens), well below the project's
// own 256 KiB oversize advisory threshold; truncating a reference mid-
// sentence produces worse agent behaviour than the token cost. section= and
// the index's est_tokens are the mitigation.
//
// The Output SafetyFilter (internal/safety, invoked from safety_helper.go) is
// deliberately NOT applied here, and must not be added. CLAUDE.md MITM
// principle #7 scopes the Output Filter to recorded wire data on its way to
// the AI agent; these are static in-repo authored documents with no
// wire-controlled content. Applying it would actively corrupt them:
// help_security.md documents the PII presets using sample card numbers and
// e-mail addresses, which the credit-card and email presets would mask —
// redacting the very documentation that explains the masking.
func (s *Server) handleDocs(ctx context.Context, _ *gomcp.CallToolRequest, input docsInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "docs",
		"topic", input.Topic,
		"section", input.Section,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "docs",
			"topic", input.Topic,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	body, err := docsBody(input.Topic, input.Section)
	if err != nil {
		return nil, nil, err
	}
	return &gomcp.CallToolResult{
		Content: []gomcp.Content{&gomcp.TextContent{Text: body}},
	}, nil, nil
}

// docsBody resolves a (topic, section) pair to the text the tool returns.
// Split out from handleDocs so the routing rules are unit-testable without an
// MCP session.
func docsBody(topic, section string) (string, error) {
	topic = strings.TrimSpace(topic)
	section = strings.TrimSpace(section)

	switch {
	case topic == "" && section != "":
		// A section with no topic is unresolvable — there is no "current
		// document". Name the fix rather than silently returning the index.
		return "", fmt.Errorf("section %q requires a topic: call docs(topic=\"<name>\", section=%q); available topics are %s",
			section, section, strings.Join(docsRegistryOnce().order, ", "))
	case topic == "":
		return renderDocsIndex(), nil
	default:
		return DocsSection(topic, section)
	}
}
