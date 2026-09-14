package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/mcp"
)

// docsCLIIndexHeader prefixes the CLI topic index.
//
// It deliberately does NOT reuse internal/mcp's docsIndexHeader. That header
// tells the reader to `Call docs(topic="<name>")`, which is an MCP tool call
// an offline CLI user cannot make — printing it to someone who just ran
// `yorishiro-proxy docs` would hand them exactly the dead end M50 exists to
// remove. The header is the one part of the index that must differ per
// surface; the data below it (names, descriptions, est_tokens, section lists)
// all comes from mcp.DocsIndex(), the single registry, so it cannot drift.
const docsCLIIndexHeader = `# yorishiro-proxy documentation index

  yorishiro-proxy docs <topic>                     print a whole document
  yorishiro-proxy docs <topic> "<heading>"         print one section of it
  yorishiro-proxy docs <topic> --section "<slug>"  the same, as a flag

A section accepts the heading text or its GitHub-style slug, case-insensitively:
'yorishiro-proxy docs macro "Variable substitution syntax"' and
'yorishiro-proxy docs macro variable-substitution-syntax' are equivalent. A
section brings its sub-sections with it.

These documents are embedded in this binary. No server needs to be running.

est_tokens is a chars/4 heuristic, not a tokenizer count.
`

// runDocs handles the "docs" subcommand: it prints yorishiro-proxy's own
// documentation without contacting an MCP server.
//
// Offline operation is the whole point (USK-1037). `yorishiro-proxy client
// docs topic=X` already serves the same documents, but only against a running
// server — which is no help to an agent that is stuck precisely because it
// has not got the proxy running yet, nor to CLI-driven workflows such as the
// pentest-proxy skill. The corpus is a compile-time embed.FS, so this path
// opens no socket, reads no file and loads no config; like install and
// version it works offline.
//
// It deliberately takes no context.Context: there is nothing cancellable
// here. The writer is injected so tests can assert output directly, as
// runListServers does.
//
// Documents and sections are printed byte-identically via mcp.DocsDocument /
// mcp.DocsSection — no reflowing, no wrapping, no trailer. extractDocsSection
// returns a contiguous substring of the document rather than a
// reconstruction, and that property is worth preserving (CLAUDE.md principle
// #3). Only the index is rendered locally, because only its header is
// surface-specific.
//
// Topic and section validation is delegated to internal/mcp. A whitelist
// maintained here would recreate the clientToolList drift class that USK-751
// had to fix with a regression test.
//
// --format is deliberately absent. It exists on the client path only because
// a tool result arrives JSON-escaped inside a CallToolResult and needs an
// instruction not to print the envelope; this path never builds one, so there
// is nothing to un-escape. Output is plain markdown, unstyled and
// deterministic, because the primary consumer is an agent reading captured
// stdout where ANSI escapes are noise.
func runDocs(w io.Writer, args []string) error {
	// --help is handled before flag parsing and writes to w (stdout) with a
	// nil error, i.e. exit 0. install/upgrade let flag.ErrHelp escape to
	// main and exit 1; that is an accident of flag's defaults rather than a
	// decision, and a *documentation* command that exits non-zero when
	// probed with --help teaches an agent the command is unsupported —
	// self-defeating for the one subcommand whose job is discoverability.
	// Unifying the other subcommands is deferred to a separate Issue.
	for _, a := range args {
		if a == "--help" || a == "-help" || a == "-h" {
			printDocsUsage(w)
			return nil
		}
	}

	topic, positionalSection, flagArgs, err := splitDocsArgs(args)
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("docs", flag.ContinueOnError)
	var sectionFlag string
	fs.StringVar(&sectionFlag, "section", "",
		"print only this section of the topic (heading text or slug, case-insensitive)")
	fs.Usage = func() { printDocsUsage(fs.Output()) }
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	// Positionals may also trail the flags (`docs --section X macro`), so
	// fold whatever flag.Parse left over back into the positional list.
	topic, positionalSection, err = appendDocsPositionals(topic, positionalSection, fs.Args())
	if err != nil {
		return err
	}

	section := positionalSection
	switch {
	case sectionFlag != "" && positionalSection != "":
		return fmt.Errorf("section given twice: positional %q and --section %q; pass it once",
			positionalSection, sectionFlag)
	case sectionFlag != "":
		section = sectionFlag
	}

	body, err := docsCLIBody(topic, section)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, body)
	return nil
}

// docsCLIBody resolves a (topic, section) pair to the text the subcommand
// prints. Split out from runDocs so the routing rules are testable without
// going through flag parsing.
func docsCLIBody(topic, section string) (string, error) {
	topic = strings.TrimSpace(topic)
	section = strings.TrimSpace(section)

	switch {
	case topic == "" && section != "":
		// Mirrors internal/mcp's section-without-topic rule in CLI idiom:
		// there is no "current document" for a bare section to apply to.
		return "", fmt.Errorf("--section %q requires a topic: run 'yorishiro-proxy docs <topic> --section %q'; "+
			"run 'yorishiro-proxy docs' to list every topic", section, section)
	case topic == "":
		return renderDocsCLIIndex(), nil
	}

	body, err := mcp.DocsSection(topic, section)
	if err != nil {
		return "", docsTopicHint(topic, err)
	}
	return body, nil
}

// docsTopicHint appends a grammar hint when the topic looks like a key=value
// pair, i.e. the operator carried the `client docs topic=macro` spelling over
// to the subcommand. Rather than accepting both grammars, name the fix: the
// subcommand takes bare words, key=value belongs to `yorishiro-proxy client`.
func docsTopicHint(topic string, err error) error {
	key, value, ok := strings.Cut(topic, "=")
	if !ok || value == "" {
		return err
	}
	return fmt.Errorf("%w; did you mean 'yorishiro-proxy docs %s'? "+
		"(the %s=<value> form is for 'yorishiro-proxy client docs')", err, value, key)
}

// renderDocsCLIIndex formats the topic index for the CLI. The bullet shape
// matches the MCP index so the two read alike; the data is mcp.DocsIndex().
func renderDocsCLIIndex() string {
	var b strings.Builder
	b.WriteString(docsCLIIndexHeader)
	for _, t := range mcp.DocsIndex() {
		fmt.Fprintf(&b, "\n- **%s** (~%d tok) — %s\n", t.Name, t.EstTokens, t.Description)
		if len(t.Sections) > 0 {
			fmt.Fprintf(&b, "  sections: %s\n", strings.Join(t.Sections, " | "))
		}
	}
	return b.String()
}

// printDocsUsage writes the docs subcommand usage to w.
func printDocsUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: yorishiro-proxy docs [topic] [section] [flags]\n\n")
	fmt.Fprintf(w, "Print yorishiro-proxy's own documentation. Works offline: the documents are\n")
	fmt.Fprintf(w, "embedded in this binary, so no server needs to be running.\n\n")
	fmt.Fprintf(w, "Arguments:\n")
	fmt.Fprintf(w, "  topic     Document to print. Omit to list every topic.\n")
	fmt.Fprintf(w, "            Every MCP tool name is a topic (query, macro, fuzz_http, ...),\n")
	fmt.Fprintf(w, "            plus getting-started, examples, template-syntax and docs.\n")
	fmt.Fprintf(w, "  section   Print only this section instead of the whole document. Accepts\n")
	fmt.Fprintf(w, "            the heading text or its slug, case-insensitively; sub-sections\n")
	fmt.Fprintf(w, "            come with the match.\n\n")
	fmt.Fprintf(w, "Flags:\n")
	fmt.Fprintf(w, "  --section <heading>  Same as the second positional argument.\n\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  yorishiro-proxy docs                     # list every topic\n")
	fmt.Fprintf(w, "  yorishiro-proxy docs macro               # the whole macro reference\n")
	fmt.Fprintf(w, "  yorishiro-proxy docs macro \"Variable substitution syntax\"\n")
	fmt.Fprintf(w, "  yorishiro-proxy docs macro --section variable-substitution-syntax\n\n")
	fmt.Fprintf(w, "An unknown topic lists every valid topic; an unknown section prints that\n")
	fmt.Fprintf(w, "topic's heading outline. Both exit non-zero.\n")
}

// splitDocsArgs pulls the leading positional arguments off args and returns
// them plus the remainder for flag.Parse.
//
// The stripping is what makes `docs macro --section "X"` work at all: Go's
// flag package stops parsing at the first non-flag argument, so handing it
// the raw args would leave --section silently unread — the Issue's own
// headline example, broken with no error. install does the same thing with
// its target word (parseInstallTarget).
func splitDocsArgs(args []string) (topic, section string, flagArgs []string, err error) {
	var positionals []string
	for i, a := range args {
		// A bare "-" is not a flag; anything else starting with "-" is.
		if strings.HasPrefix(a, "-") && a != "-" {
			flagArgs = args[i:]
			break
		}
		positionals = append(positionals, a)
	}
	topic, section, err = appendDocsPositionals("", "", positionals)
	return topic, section, flagArgs, err
}

// appendDocsPositionals folds positional words into (topic, section) in that
// order, mirroring positionalArgMapping["docs"], and rejects a third.
func appendDocsPositionals(topic, section string, extra []string) (string, string, error) {
	for _, a := range extra {
		switch {
		case topic == "":
			topic = a
		case section == "":
			section = a
		default:
			return "", "", fmt.Errorf(
				"too many arguments: docs takes at most a topic and a section, got %q after topic %q and section %q; "+
					"quote a multi-word section, e.g. 'yorishiro-proxy docs %s %q'",
				a, topic, section, topic, section+" "+a)
		}
	}
	return topic, section, nil
}
