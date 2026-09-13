package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcp"
)

// runDocsOK drives runDocs and fails the test if it errors.
func runDocsOK(t *testing.T, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := runDocs(&buf, args); err != nil {
		t.Fatalf("runDocs(%q): %v", args, err)
	}
	return buf.String()
}

// runDocsErr drives runDocs expecting an error, and returns it.
func runDocsErr(t *testing.T, args ...string) error {
	t.Helper()
	var buf bytes.Buffer
	err := runDocs(&buf, args)
	if err == nil {
		t.Fatalf("runDocs(%q) succeeded, want an error; output:\n%s", args, buf.String())
	}
	return err
}

// TestSplitDocsArgs_Grammar pins the positional/flag split.
//
// This is the highest-risk part of the subcommand. Go's flag package stops
// parsing at the first non-flag argument, so `docs macro --section "X"` —
// the Issue's own headline example — would silently drop --section under the
// most natural implementation, with no error at all. The leading positionals
// must come off before flag.Parse sees the args.
func TestSplitDocsArgs_Grammar(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantTopic   string
		wantSection string
		wantFlags   []string
		wantErr     bool
	}{
		{name: "no args", args: nil},
		{name: "topic only", args: []string{"macro"}, wantTopic: "macro"},
		{
			name:        "topic and quoted section",
			args:        []string{"macro", "Variable substitution syntax"},
			wantTopic:   "macro",
			wantSection: "Variable substitution syntax",
		},
		{
			name:      "topic then double-dash section flag",
			args:      []string{"macro", "--section", "Variable substitution syntax"},
			wantTopic: "macro",
			wantFlags: []string{"--section", "Variable substitution syntax"},
		},
		{
			name:      "topic then single-dash section flag",
			args:      []string{"macro", "-section", "Variable substitution syntax"},
			wantTopic: "macro",
			wantFlags: []string{"-section", "Variable substitution syntax"},
		},
		{
			name:      "flag first, topic trails",
			args:      []string{"--section", "Notes", "macro"},
			wantFlags: []string{"--section", "Notes", "macro"},
		},
		{
			name:    "three positionals",
			args:    []string{"macro", "Variable", "substitution"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topic, section, flags, err := splitDocsArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("splitDocsArgs(%q) succeeded, want an error", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitDocsArgs(%q): %v", tt.args, err)
			}
			if topic != tt.wantTopic {
				t.Errorf("topic = %q, want %q", topic, tt.wantTopic)
			}
			if section != tt.wantSection {
				t.Errorf("section = %q, want %q", section, tt.wantSection)
			}
			if strings.Join(flags, "\x00") != strings.Join(tt.wantFlags, "\x00") {
				t.Errorf("flagArgs = %q, want %q", flags, tt.wantFlags)
			}
		})
	}
}

// TestRunDocs_Grammar drives the same grammar rows end-to-end, so a
// regression in the flag wiring (not just the splitter) is caught too.
func TestRunDocs_Grammar(t *testing.T) {
	wantSection, err := mcp.DocsSection("macro", "Variable substitution syntax")
	if err != nil {
		t.Fatalf("mcp.DocsSection: %v", err)
	}
	wantDoc, err := mcp.DocsDocument("macro")
	if err != nil {
		t.Fatalf("mcp.DocsDocument: %v", err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "topic only", args: []string{"macro"}, want: wantDoc},
		{
			name: "positional section",
			args: []string{"macro", "Variable substitution syntax"},
			want: wantSection,
		},
		{
			name: "double-dash section flag",
			args: []string{"macro", "--section", "Variable substitution syntax"},
			want: wantSection,
		},
		{
			name: "single-dash section flag",
			args: []string{"macro", "-section", "Variable substitution syntax"},
			want: wantSection,
		},
		{
			name: "section flag by slug",
			args: []string{"macro", "--section", "variable-substitution-syntax"},
			want: wantSection,
		},
		{
			name: "flag first, topic trails",
			args: []string{"--section", "Variable substitution syntax", "macro"},
			want: wantSection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runDocsOK(t, tt.args...)
			// runDocs adds exactly one trailing newline via Fprintln; the
			// document body itself must be byte-identical.
			if got != tt.want+"\n" {
				t.Errorf("runDocs(%q) body is not byte-identical to the mcp package output\n got %d bytes\nwant %d bytes",
					tt.args, len(got), len(tt.want)+1)
			}
		})
	}
}

// TestRunDocs_GrammarErrors covers the ambiguous and malformed arg shapes.
func TestRunDocs_GrammarErrors(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText string
	}{
		{
			name:     "section given twice",
			args:     []string{"macro", "Notes", "--section", "Parameters"},
			wantText: "section given twice",
		},
		{
			name:     "three positionals",
			args:     []string{"macro", "Variable", "substitution"},
			wantText: "too many arguments",
		},
		{
			name:     "section without topic",
			args:     []string{"--section", "Parameters"},
			wantText: "requires a topic",
		},
		{
			name:     "unknown topic",
			args:     []string{"no-such-topic"},
			wantText: "unknown docs topic",
		},
		{
			name:     "unknown section",
			args:     []string{"macro", "no-such-section"},
			wantText: "no-such-section",
		},
		{
			name:     "unknown flag",
			args:     []string{"macro", "--nope"},
			wantText: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDocsErr(t, tt.args...)
			if !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("error %q does not contain %q", err, tt.wantText)
			}
		})
	}
}

// TestRunDocs_ErrorsAreActionable asserts the two discovery errors carry the
// information needed to self-correct, rather than just reporting failure.
func TestRunDocs_ErrorsAreActionable(t *testing.T) {
	t.Run("unknown topic lists every topic", func(t *testing.T) {
		err := runDocsErr(t, "no-such-topic")
		topics := mcp.DocsIndex()
		if len(topics) == 0 {
			t.Fatal("mcp.DocsIndex() is empty; the assertions below would be vacuous")
		}
		for _, topic := range topics {
			if !strings.Contains(err.Error(), topic.Name) {
				t.Errorf("unknown-topic error does not name topic %q", topic.Name)
			}
		}
	})

	t.Run("unknown section prints the outline", func(t *testing.T) {
		err := runDocsErr(t, "macro", "no-such-section")
		for _, sec := range topicSections(t, "macro") {
			if !strings.Contains(err.Error(), sec) {
				t.Errorf("unknown-section error does not list section %q", sec)
			}
		}
	})
}

// TestRunDocs_KeyValueTopicHint covers the operator who carried the
// `client docs topic=macro` grammar over to the subcommand. Rather than
// accepting both grammars, the error names the fix.
func TestRunDocs_KeyValueTopicHint(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText []string
	}{
		{
			name:     "topic=value",
			args:     []string{"topic=macro"},
			wantText: []string{"unknown docs topic", "yorishiro-proxy docs macro", "yorishiro-proxy client docs"},
		},
		{
			name:     "arbitrary key=value",
			args:     []string{"name=macro"},
			wantText: []string{"yorishiro-proxy docs macro", "name=<value>"},
		},
		{
			// A bare unknown word must NOT get the key=value hint.
			name:     "no equals sign, no hint",
			args:     []string{"macroo"},
			wantText: []string{"unknown docs topic"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDocsErr(t, tt.args...)
			for _, want := range tt.wantText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if tt.name == "no equals sign, no hint" && strings.Contains(err.Error(), "did you mean") {
				t.Errorf("bare unknown topic should not get the key=value hint: %v", err)
			}
		})
	}
}

// TestRunDocs_IndexIsCLIIdiom is the counterpart to internal/mcp's index
// test. The CLI index must carry the same topic data and a CLI-spelled
// header: the MCP header instructs the reader to `Call docs(topic="X")`,
// which an offline CLI user cannot do, and printing it here would hand them
// the dead end this milestone exists to remove.
func TestRunDocs_IndexIsCLIIdiom(t *testing.T) {
	body := runDocsOK(t)

	topics := mcp.DocsIndex()
	if len(topics) == 0 {
		t.Fatal("mcp.DocsIndex() is empty; the assertions below would be vacuous")
	}
	for _, topic := range topics {
		if !strings.Contains(body, "**"+topic.Name+"**") {
			t.Errorf("index is missing topic %q", topic.Name)
		}
		if !strings.Contains(body, topic.Description) {
			t.Errorf("index is missing the description for topic %q", topic.Name)
		}
		for _, sec := range topic.Sections {
			if !strings.Contains(body, sec) {
				t.Errorf("index is missing section %q of topic %q", sec, topic.Name)
			}
		}
	}

	for _, want := range []string{
		"yorishiro-proxy docs <topic>",
		"No server needs to be running.",
		"est_tokens is a chars/4 heuristic",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("CLI index is missing %q", want)
		}
	}

	// The MCP-idiom header must not leak into CLI output.
	if strings.Contains(body, `Call docs(topic=`) {
		t.Error("CLI index carries the MCP-idiom header; an offline user cannot make that call")
	}
}

// TestRunDocs_HelpExitsZero pins the deliberate divergence from install /
// upgrade, which let flag.ErrHelp escape to main and exit 1. A documentation
// subcommand that exits non-zero when probed with --help teaches an agent
// the command is unsupported.
func TestRunDocs_HelpExitsZero(t *testing.T) {
	for _, flag := range []string{"-h", "-help", "--help"} {
		t.Run(flag, func(t *testing.T) {
			var buf bytes.Buffer
			if err := runDocs(&buf, []string{flag}); err != nil {
				t.Fatalf("runDocs(%q) returned %v, want nil (exit 0)", flag, err)
			}
			out := buf.String()
			for _, want := range []string{"Usage: yorishiro-proxy docs", "Works offline", "--section"} {
				if !strings.Contains(out, want) {
					t.Errorf("usage output missing %q:\n%s", want, out)
				}
			}
		})
	}

	// A help flag after a topic is still help, not a doc fetch.
	t.Run("after a topic", func(t *testing.T) {
		var buf bytes.Buffer
		if err := runDocs(&buf, []string{"macro", "--help"}); err != nil {
			t.Fatalf("runDocs(macro --help) returned %v, want nil", err)
		}
		if !strings.Contains(buf.String(), "Usage: yorishiro-proxy docs") {
			t.Error("help flag after a topic did not print usage")
		}
	})
}

// TestRunDocs_WorksOffline is the structural offline oracle that runs on
// every PR: no server, no env, no network, no fixtures, no HOME lookup — the
// corpus is a compile-time embed.FS. The exec'd-binary counterpart lives in
// binary_smoke_integration_test.go.
func TestRunDocs_WorksOffline(t *testing.T) {
	var buf bytes.Buffer
	if err := runDocs(&buf, []string{"macro"}); err != nil {
		t.Fatalf("runDocs(macro) with no server running: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("runDocs(macro) produced no output")
	}
}

// TestRunDocsCLI_AcceptanceCriterion is the USK-1037 acceptance test, the CLI
// counterpart of internal/mcp's TestDocsTool_AcceptanceCriterion: with no
// server running, an agent must be able to reach the §var§ template syntax
// through the docs subcommand alone.
func TestRunDocsCLI_AcceptanceCriterion(t *testing.T) {
	full := runDocsOK(t, "macro")
	if !strings.Contains(full, "§name§") {
		t.Error("'yorishiro-proxy docs macro' does not reach the §name§ template syntax")
	}

	for _, args := range [][]string{
		{"macro", "Variable substitution syntax"},
		{"macro", "--section", "Variable substitution syntax"},
		{"macro", "--section", "variable-substitution-syntax"},
	} {
		section := runDocsOK(t, args...)
		if !strings.Contains(section, "§name§") {
			t.Errorf("runDocs(%q) does not reach the §name§ syntax:\n%s", args, section)
		}
		if !strings.HasPrefix(section, "## Variable substitution syntax") {
			t.Errorf("runDocs(%q) does not start at its own heading line:\n%.80s", args, section)
		}
	}

	// The index must name the macro topic, so an agent starting from a bare
	// `yorishiro-proxy docs` can find its way there.
	if !strings.Contains(runDocsOK(t), "**macro**") {
		t.Error("the topic index does not name the macro topic")
	}
}

// TestClientToolHelp_PointsToDocsSubcommand is an invariant, not a unit test.
//
// Every `client <tool> --help` string must name the offline `yorishiro-proxy
// docs <tool>` path, because the CLI help is deliberately a summary and the
// full reference lives in the docs corpus. Every tool name is also a docs
// topic, so no entry is exempt. Without this, a partially-applied edit across
// the 19 entries passes silently.
func TestClientToolHelp_PointsToDocsSubcommand(t *testing.T) {
	if len(clientToolHelp) == 0 {
		t.Fatal("clientToolHelp is empty; the assertions below would be vacuous")
	}
	for name, help := range clientToolHelp {
		if want := "yorishiro-proxy docs " + name; !strings.Contains(help, want) {
			t.Errorf("clientToolHelp[%q] does not point at %q", name, want)
		}
		// The CLI help is CLI idiom; an MCP tool-call spelling here is a
		// dead end for an operator reading it at a shell prompt.
		if strings.Contains(help, `call docs(topic=`) {
			t.Errorf("clientToolHelp[%q] uses the MCP call idiom; use 'yorishiro-proxy docs %s'", name, name)
		}
	}
}

// TestClientToolHelp_EveryToolIsADocsTopic guards the assumption the pointer
// lines rest on: that `yorishiro-proxy docs <tool>` actually resolves for
// every tool the CLI advertises.
func TestClientToolHelp_EveryToolIsADocsTopic(t *testing.T) {
	topics := make(map[string]bool, len(mcp.DocsIndex()))
	for _, topic := range mcp.DocsIndex() {
		topics[topic.Name] = true
	}
	if len(topics) == 0 {
		t.Fatal("mcp.DocsIndex() is empty; the assertions below would be vacuous")
	}
	for _, name := range clientToolList {
		if !topics[name] {
			t.Errorf("tool %q has no docs topic, but its help points at 'yorishiro-proxy docs %s'", name, name)
		}
	}
}

// TestPrintClientUsage_NamesDocsSubcommand ensures an agent that reached
// `client --help` without a running server is told where documentation is.
func TestPrintClientUsage_NamesDocsSubcommand(t *testing.T) {
	var buf bytes.Buffer
	printClientUsage(&buf)
	for _, want := range []string{"yorishiro-proxy docs", "without a running server"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("client usage is missing %q", want)
		}
	}
}

// topicSections returns the H2 section names of a topic, failing the test if
// the topic is unknown.
func topicSections(t *testing.T, topic string) []string {
	t.Helper()
	for _, entry := range mcp.DocsIndex() {
		if entry.Name == topic {
			return entry.Sections
		}
	}
	t.Fatalf("topic %q not found in mcp.DocsIndex()", topic)
	return nil
}
