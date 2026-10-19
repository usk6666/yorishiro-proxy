package main

// skill_cli_examples_test.go — USK-1046.
//
// `.claude/skills/pentest-proxy/SKILL.md` is the playbook CLI-driven agents
// follow, and it had drifted until 19 of its 45 `yorishiro-proxy client`
// invocations were rejected by the server (dead tool names, a nonexistent
// `params.` wrapper on typed tools, made-up fuzz fields). Hand-written
// examples rot; this guard ties them to the live tool schemas.
//
// Every `yorishiro-proxy client ...` command found in fenced code blocks
// (at any indentation) and inline code spans of `.claude/skills/*/SKILL.md`,
// README.md and README-ja.md is run through the CLI's own argument path —
// the runClient dispatch, splitClientToolArgs, fetchToolSchema against the
// live tools/list, buildToolParams — and the resulting arguments are then
// validated by the go-sdk server-side InputSchema validator. Any CLI
// warning (unknown top-level parameter, dropped positional) is a failure,
// because the CLI only warns where the agent's intent is silently lost.
//
// The validator runs on a validation-only server that re-registers every
// tool from the real server's tools/list (same name, same InputSchema) with
// a no-op handler: identical schema validation, no side effects (fuzz /
// resend handlers would otherwise try to dial out), and unknown tools are
// still rejected. Handler-level checks (e.g. whether a fuzz position path
// exists in the recorded flow) are out of scope.
//
// Shell words are split by a deliberately small POSIX tokenizer that fails
// loudly on any construct it does not model ($, backticks, pipes, ;, &&,
// redirects, globs) rather than guessing.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// cliExample is one `yorishiro-proxy client` command found in a document.
type cliExample struct {
	Source  string   // document path as shown in test names
	Line    int      // 1-based line where the command starts
	EndLine int      // 1-based last physical line of the command (== Line for inline spans)
	Fenced  bool     // found in a fenced code block (vs an inline code span)
	Args    []string // shell words after "yorishiro-proxy client"
	Err     error    // the command could not be tokenized / is not a client command
}

func (ex cliExample) name() string { return fmt.Sprintf("%s:%d", ex.Source, ex.Line) }

const clientCommandMarker = "yorishiro-proxy client"

var inlineCodeSpan = regexp.MustCompile("`([^`]+)`")

// extractClientExamples returns every `yorishiro-proxy client` command in a
// Markdown document: logical lines (with `\`+newline continuations) inside
// fenced code blocks, and inline code spans outside them. A span or fenced
// line that mentions the command but cannot be tokenized, or that does not
// start with it, is returned with Err set so the caller reports it.
func extractClientExamples(source, text string) []cliExample {
	var out []cliExample
	lines := strings.Split(text, "\n")
	inFence := false
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if !inFence {
			out = append(out, extractInlineExamples(source, i+1, lines[i])...)
			continue
		}

		// Join backslash-continued physical lines into one logical command.
		// As in bash, only an unescaped `\` that is the very last byte of
		// the line continues it.
		start := i
		logical := lines[i]
		var joinErr error
		for {
			cur := lines[i]
			if endsWithContinuation(cur) {
				if i+1 >= len(lines) {
					break // the tokenizer reports the trailing backslash
				}
				i++
				logical += "\n" + lines[i]
				continue
			}
			// `\` followed only by blanks is an escaped space in bash, not
			// a continuation: the next line would run as its own command.
			if trimmed := strings.TrimRight(cur, " \t"); trimmed != cur && endsWithContinuation(trimmed) {
				joinErr = fmt.Errorf("line %d: `\\` followed by trailing whitespace is an escaped space in bash, not a line continuation", i+1)
			}
			break
		}
		if !strings.Contains(logical, clientCommandMarker) {
			continue
		}
		ex := parseClientCommand(source, start+1, true, logical)
		if joinErr != nil && ex.Err == nil {
			ex.Args, ex.Err = nil, joinErr
		}
		ex.EndLine = i + 1
		out = append(out, ex)
	}
	return out
}

// endsWithContinuation reports whether line ends in an unescaped backslash
// (an odd number of trailing backslashes).
func endsWithContinuation(line string) bool {
	n := 0
	for n < len(line) && line[len(line)-1-n] == '\\' {
		n++
	}
	return n%2 == 1
}

func extractInlineExamples(source string, line int, text string) []cliExample {
	var out []cliExample
	for _, m := range inlineCodeSpan.FindAllStringSubmatch(text, -1) {
		span := strings.TrimSpace(m[1])
		if !strings.Contains(span, clientCommandMarker) {
			continue
		}
		// A bare mention of the subcommand ("the `yorishiro-proxy client`
		// subcommand") is prose, not an example.
		if span == clientCommandMarker {
			continue
		}
		out = append(out, parseClientCommand(source, line, false, span))
	}
	return out
}

func parseClientCommand(source string, line int, fenced bool, cmd string) cliExample {
	ex := cliExample{Source: source, Line: line, EndLine: line, Fenced: fenced}
	words, err := shellWords(cmd)
	if err != nil {
		ex.Err = fmt.Errorf("tokenize %q: %w", cmd, err)
		return ex
	}
	if len(words) < 3 || words[0] != "yorishiro-proxy" || words[1] != "client" {
		ex.Err = fmt.Errorf("%q mentions %q but is not a plain `yorishiro-proxy client <command> ...` invocation", cmd, clientCommandMarker)
		return ex
	}
	ex.Args = words[2:]
	return ex
}

// shellWords splits a command line into words the way a POSIX shell would
// for the subset used in documentation: whitespace separation, single
// quotes, double quotes, backslash escapes, `\`+newline continuations and
// `#` comments. Anything whose meaning depends on the shell environment or
// on other commands (expansions, pipes, lists, redirects, globs,
// background jobs) is rejected with an error.
func shellWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
		}
		cur.Reset()
		inWord = false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing backslash")
			}
			i++
			if s[i] == '\n' { // line continuation
				continue
			}
			cur.WriteByte(s[i])
			inWord = true
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 1
			inWord = true
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				switch s[j] {
				case '$', '`':
					return nil, fmt.Errorf("unsupported shell construct %q inside double quotes", s[j])
				case '\\':
					if j+1 < len(s) && strings.IndexByte("$`\"\\\n", s[j+1]) >= 0 {
						j++
						if s[j] == '\n' {
							continue
						}
					}
				}
				cur.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, errors.New("unterminated double quote")
			}
			i = j
			inWord = true
		case c == '#' && !inWord:
			// A comment runs to end of line and swallows any trailing `\`,
			// so it ends the command. Anything after it (only reachable via
			// a joined continuation) would be a separate command in bash.
			if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
				if rest := strings.TrimSpace(s[i+nl:]); rest != "" {
					return nil, fmt.Errorf("comment ends the command, but %q follows it (a `\\` inside a comment is not a line continuation)", rest)
				}
			}
			i = len(s)
		case strings.IndexByte("$`|;&<>()*?[]{}~", c) >= 0:
			return nil, fmt.Errorf("unsupported shell construct %q", c)
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return words, nil
}

// newValidationSession boots the real MCP server, copies every tool from
// its tools/list (name, description, InputSchema) onto a validation-only
// server whose handlers do nothing, and returns a client session to the
// latter. CallTool on it applies the go-sdk server-side InputSchema
// validation exactly as the real server would, without side effects.
func newValidationSession(t *testing.T) (context.Context, *gomcp.ClientSession) {
	t.Helper()
	ctx, real := newInMemoryToolSession(t)

	list, err := real.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list on the real server: %v", err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("tools/list on the real server returned no tools")
	}

	srv := gomcp.NewServer(&gomcp.Implementation{Name: "usk1046-validator", Version: "test"}, nil)
	noop := func(context.Context, *gomcp.CallToolRequest, map[string]any) (*gomcp.CallToolResult, any, error) {
		return &gomcp.CallToolResult{}, nil, nil
	}
	for _, tool := range list.Tools {
		gomcp.AddTool(srv, &gomcp.Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema}, noop)
	}

	serverTransport, clientTransport := gomcp.NewInMemoryTransports()
	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = srv.Run(runCtx, serverTransport)
	}()
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1046-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("connect to validation server: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		cancel()
		<-runDone
	})
	return ctx, session
}

func isClientHelpFlag(a string) bool { return a == "--help" || a == "-help" || a == "-h" }

// checkClientExample reports why the words after `yorishiro-proxy client`
// would not be accepted, or nil. It mirrors runClient's dispatch: the
// client usage and list-servers need no server; `<tool> --help` needs a
// clientToolHelp entry; everything else is a tool call whose arguments go
// through the real CLI parameter path and the server's InputSchema.
func checkClientExample(ctx context.Context, session *gomcp.ClientSession, args []string) error {
	if len(args) == 0 {
		return errors.New("no command after `yorishiro-proxy client`")
	}
	first := args[0]
	if isClientHelpFlag(first) || first == "list-servers" {
		return nil
	}

	toolName, toolArgs := first, args[1:]
	for _, a := range toolArgs {
		if isClientHelpFlag(a) {
			if _, ok := clientToolHelp[toolName]; !ok {
				return fmt.Errorf("`%s --help`: no clientToolHelp entry for %q", toolName, toolName)
			}
			return nil
		}
	}

	_, paramArgs := splitClientToolArgs(toolArgs)
	schema := fetchToolSchema(ctx, session, toolName)
	if schema == nil {
		return fmt.Errorf("unknown tool %q (not in the server's tools/list)", toolName)
	}
	var warnings bytes.Buffer
	params, err := buildToolParams(toolName, paramArgs, schema, &warnings)
	if err != nil {
		return fmt.Errorf("CLI rejects the arguments: %w", err)
	}
	if warnings.Len() > 0 {
		return fmt.Errorf("CLI warns (the argument would be silently lost): %s", strings.TrimSpace(warnings.String()))
	}
	if _, err := session.CallTool(ctx, &gomcp.CallToolParams{Name: toolName, Arguments: params}); err != nil {
		return fmt.Errorf("server rejects the arguments %v: %w", params, err)
	}
	return nil
}

// guardedDocs returns the documents the guard covers, as (display name,
// path) pairs: every .claude/skills/*/SKILL.md, both READMEs, and the
// embedded MCP help resources (internal/mcp/resources/help_*.md, served by
// the docs tool and the offline `docs` subcommand).
func guardedDocs(t *testing.T) map[string]string {
	t.Helper()
	const root = "../.."
	skills, err := filepath.Glob(filepath.Join(root, ".claude", "skills", "*", "SKILL.md"))
	if err != nil {
		t.Fatalf("glob skills: %v", err)
	}
	helpDocs, err := filepath.Glob(filepath.Join(root, "internal", "mcp", "resources", "help_*.md"))
	if err != nil {
		t.Fatalf("glob help resources: %v", err)
	}
	if len(helpDocs) == 0 {
		t.Fatal("no internal/mcp/resources/help_*.md found")
	}
	paths := append(skills, helpDocs...)
	paths = append(paths, filepath.Join(root, "README.md"), filepath.Join(root, "README-ja.md"))
	docs := make(map[string]string, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("rel %s: %v", p, err)
		}
		docs[filepath.ToSlash(rel)] = p
	}
	if _, ok := docs[".claude/skills/pentest-proxy/SKILL.md"]; !ok {
		t.Fatalf("pentest-proxy/SKILL.md not found among %v", paths)
	}
	return docs
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestDocCLIExamples_AcceptedByLiveSchema (T1) is the guard: every
// `yorishiro-proxy client` example in the skills and READMEs must be
// accepted end-to-end. One subtest per file:line.
func TestDocCLIExamples_AcceptedByLiveSchema(t *testing.T) {
	ctx, session := newValidationSession(t)

	docs := guardedDocs(t)
	names := make([]string, 0, len(docs))
	for name := range docs {
		names = append(names, name)
	}
	sort.Strings(names)

	total := 0
	for _, name := range names {
		for _, ex := range extractClientExamples(name, readDoc(t, docs[name])) {
			total++
			t.Run(ex.name(), func(t *testing.T) {
				if ex.Err != nil {
					t.Fatal(ex.Err)
				}
				if err := checkClientExample(ctx, session, ex.Args); err != nil {
					t.Errorf("`yorishiro-proxy client %s`: %v", strings.Join(ex.Args, " "), err)
				}
			})
		}
	}
	if total == 0 {
		t.Fatal("no `yorishiro-proxy client` examples found in any guarded document")
	}
}

// pentestSkillMinExamples is the floor for the pentest-proxy skill: the
// guard must not pass by silently extracting nothing.
const pentestSkillMinExamples = 30

// TestDocCLIExamples_NotVacuous (T2) proves the extractor actually reaches
// the examples: the pentest skill yields at least the floor, every fenced
// physical line that starts a `yorishiro-proxy client` command is
// extracted, and each README yields at least one example.
func TestDocCLIExamples_NotVacuous(t *testing.T) {
	docs := guardedDocs(t)

	const skill = ".claude/skills/pentest-proxy/SKILL.md"
	text := readDoc(t, docs[skill])
	examples := extractClientExamples(skill, text)
	if len(examples) < pentestSkillMinExamples {
		t.Errorf("%s: extracted %d examples, want >= %d", skill, len(examples), pentestSkillMinExamples)
	}

	// Independent naive scan: fenced physical lines containing the marker.
	want := map[int]bool{}
	inFence := false
	for i, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence && strings.Contains(line, clientCommandMarker) {
			want[i+1] = true
		}
	}
	got := map[int]bool{}
	for _, ex := range examples {
		if ex.Fenced {
			got[ex.Line] = true
		}
	}
	for line := range want {
		if !got[line] {
			t.Errorf("%s:%d: fenced `yorishiro-proxy client` line was not extracted", skill, line)
		}
	}
	if len(want) == 0 {
		t.Errorf("%s: naive scan found no fenced examples", skill)
	}

	for _, readme := range []string{"README.md", "README-ja.md"} {
		if n := len(extractClientExamples(readme, readDoc(t, docs[readme]))); n == 0 {
			t.Errorf("%s: extracted no examples", readme)
		}
	}
}

// --- USK-1244: clientToolHelp ------------------------------------------
//
// `yorishiro-proxy client <tool> --help` prints clientToolHelp verbatim.
// It is plain text, not Markdown, and every line that mentions the client
// command is an example, so each help string is checked as if it were one
// fenced code block: fail-closed, every marker line becomes a command.

// extractHelpExamples returns every `yorishiro-proxy client` command in one
// clientToolHelp entry. Line numbers are 1-based within the help string.
func extractHelpExamples(tool, help string) []cliExample {
	source := "clientToolHelp[" + tool + "]"
	examples := extractClientExamples(source, "```\n"+help+"\n```")
	for i := range examples {
		// The synthetic opening fence shifts every line by one.
		examples[i].Line--
		examples[i].EndLine--
	}
	return examples
}

// helpExampleCoverage is the non-vacuity check for the help guard. It
// returns one finding per help entry that yields no example at all, or
// whose extracted example count differs from an independent naive count
// of lines mentioning the client command (a marker line the extractor
// dropped is a hole in the guard).
func helpExampleCoverage(help map[string]string) []string {
	return nil
}

// knownBrokenHelpExamples are help examples that are wrong for a reason
// tracked elsewhere. Each stays excluded only while it still fails: once
// it passes the guard, the exclusion is reported as stale.
var knownBrokenHelpExamples = []struct {
	tool, substr, issue string
}{
	// intercept has no params.override_body; the modify_and_forward
	// parameter surface is being reworked in USK-1153.
	{"intercept", "params.override_body=", "USK-1153"},
}

func knownBrokenHelpExample(tool string, args []string) string {
	joined := strings.Join(args, " ")
	for _, kb := range knownBrokenHelpExamples {
		if kb.tool == tool && strings.Contains(joined, kb.substr) {
			return kb.issue
		}
	}
	return ""
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestClientToolHelpExamples_AcceptedByLiveSchema is the help-text guard:
// every example printed by `yorishiro-proxy client <tool> --help` must be
// accepted end-to-end, exactly like the skill / README examples.
func TestClientToolHelpExamples_AcceptedByLiveSchema(t *testing.T) {
	ctx, session := newValidationSession(t)

	for _, tool := range sortedKeys(clientToolHelp) {
		for _, ex := range extractHelpExamples(tool, clientToolHelp[tool]) {
			t.Run(ex.name(), func(t *testing.T) {
				err := ex.Err
				if err == nil {
					err = checkClientExample(ctx, session, ex.Args)
				}
				if issue := knownBrokenHelpExample(tool, ex.Args); issue != "" {
					if err == nil {
						t.Errorf("stale exclusion: the example now passes; remove the %s entry from knownBrokenHelpExamples", issue)
						return
					}
					t.Skip("not yet implemented: " + issue)
				}
				switch {
				case ex.Err != nil:
					t.Error(ex.Err)
				case err != nil:
					t.Errorf("`yorishiro-proxy client %s`: %v", strings.Join(ex.Args, " "), err)
				}
			})
		}
	}
}

// TestHelpExampleCoverage pins the help guard's non-vacuity check with
// fixtures, then runs it over the live clientToolHelp map.
func TestHelpExampleCoverage(t *testing.T) {
	tests := []struct {
		name      string
		help      map[string]string
		wantFound bool
	}{
		{"entry without examples", map[string]string{"x": "x: does things.\n\nParameters:\n  a=<b>"}, true},
		{"marker line the extractor drops", map[string]string{"x": "Examples:\n```\n  yorishiro-proxy client query resource=flows"}, true},
		{"one example per entry", map[string]string{
			"query":  "Examples:\n  yorishiro-proxy client query resource=flows",
			"manage": "Examples:\n  yorishiro-proxy client manage action=delete_flows params.flow_id=X\n  yorishiro-proxy client manage action=delete_flows params.confirm=true",
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helpExampleCoverage(tt.help)
			if tt.wantFound && len(got) == 0 {
				t.Errorf("helpExampleCoverage(%q) found nothing, want a finding", tt.help)
			}
			if !tt.wantFound && len(got) != 0 {
				t.Errorf("helpExampleCoverage(%q) = %q, want no findings", tt.help, got)
			}
		})
	}

	t.Run("live clientToolHelp", func(t *testing.T) {
		if len(clientToolHelp) == 0 {
			t.Fatal("clientToolHelp is empty")
		}
		for _, f := range helpExampleCoverage(clientToolHelp) {
			t.Error(f)
		}
	})
}

// bareClientMention is the one prose form the extractor skips on purpose
// ("the `yorishiro-proxy client` subcommand"); the sweep allows exactly it.
const bareClientMention = "`" + clientCommandMarker + "`"

var (
	// splitMarkerHead / splitMarkerTail detect `yorishiro-proxy` ending a
	// line (optionally followed by a `\` continuation) with `client` as the
	// first word of the next line.
	splitMarkerHead = regexp.MustCompile(`yorishiro-proxy[ \t]*\\?[ \t]*$`)
	splitMarkerTail = regexp.MustCompile("^[ \t]*client([ \t`]|$)")
)

// uncoveredClientMentions is a fail-closed sweep, deliberately independent
// of the extractor's fence and span logic: it returns the 1-based lines
// that mention a `yorishiro-proxy client` command (including the form split
// across a line break) more often than extracted examples account for.
// A line inside a fenced example's range is covered; any other line needs
// one inline example per mention. Shapes the extractor does not model —
// indented code blocks, inline spans wrapping across lines, the split form
// — therefore surface here instead of being silently skipped.
func uncoveredClientMentions(text string, examples []cliExample) []int {
	inFencedRange := map[int]bool{}
	inlineAt := map[int]int{}
	for _, ex := range examples {
		if ex.Fenced {
			for l := ex.Line; l <= ex.EndLine; l++ {
				inFencedRange[l] = true
			}
		} else {
			inlineAt[ex.Line]++
		}
	}

	var out []int
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		mentions := strings.Count(strings.ReplaceAll(line, bareClientMention, ""), clientCommandMarker)
		if splitMarkerHead.MatchString(line) && i+1 < len(lines) && splitMarkerTail.MatchString(lines[i+1]) {
			mentions++
		}
		if mentions == 0 || inFencedRange[i+1] {
			continue
		}
		if inlineAt[i+1] < mentions {
			out = append(out, i+1)
		}
	}
	return out
}

// TestDocCLIExamples_NoUncoveredMentions (T2b) runs the fail-closed sweep
// over every guarded document: a mention the extractor did not turn into an
// example is a hole in the guard, reported as file:line.
func TestDocCLIExamples_NoUncoveredMentions(t *testing.T) {
	docs := guardedDocs(t)
	names := make([]string, 0, len(docs))
	for name := range docs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		text := readDoc(t, docs[name])
		for _, line := range uncoveredClientMentions(text, extractClientExamples(name, text)) {
			t.Errorf("%s:%d: mentions a `yorishiro-proxy client` command that the extractor did not pick up as an example (use a fenced block or a single-line inline code span)", name, line)
		}
	}
}

// TestUncoveredClientMentions pins the sweep with fixtures: each shape the
// extractor skips must be flagged, and extracted examples plus the bare
// subcommand mention must not be.
func TestUncoveredClientMentions(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []int
	}{
		{"indented code block", "Run:\n\n    yorishiro-proxy client query resource=flows\n", []int{3}},
		{"inline span wrapping lines", "Use `yorishiro-proxy client query\nresource=flows` here.", []int{1}},
		{"split across continuation in fence", "```bash\nyorishiro-proxy \\\n  client query resource=flows\n```", []int{2}},
		{"split inline span", "Use `yorishiro-proxy\nclient query resource=flows`.", []int{1}},
		{"second unquoted mention on a covered line", "`yorishiro-proxy client query flow A` or yorishiro-proxy client query flow B", []int{1}},
		{"plain prose", "the yorishiro-proxy client subcommand", []int{1}},

		{"bare subcommand mention", "All commands use the `yorishiro-proxy client` subcommand.", nil},
		{"inline example", "Run `yorishiro-proxy client query flow ID` first.", nil},
		{"two inline examples", "`yorishiro-proxy client query flow A` and `yorishiro-proxy client query flow B`", nil},
		{"fenced continuation", "```bash\nyorishiro-proxy client query \\\n  resource=flows\n```", nil},
		{"unrelated line ending in yorishiro-proxy", "npm i -g @usk6666/yorishiro-proxy\ncd yorishiro-proxy", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uncoveredClientMentions(tt.doc, extractClientExamples("fixture.md", tt.doc))
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("uncovered lines = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCheckClientExample_Controls (T3 + T4) pins the checker on both sides
// with invented fixtures (they test the checker, not the docs): each
// negative control is a real drift class that must be rejected, each
// positive control a real form that must be accepted.
func TestCheckClientExample_Controls(t *testing.T) {
	ctx, session := newValidationSession(t)

	tests := []struct {
		name    string
		doc     string
		wantErr string // "" = must be accepted
	}{
		// T3 negative controls.
		{"unknown top-level param", "`yorishiro-proxy client query resource=flows bogus=1`", `unknown parameter "bogus"`},
		{"unknown tool", "`yorishiro-proxy client resend action=resend`", `unknown tool "resend"`},
		{"unknown nested key", "`yorishiro-proxy client manage action=delete_flows params.attack_type=x`", "attack_type"},
		{"params object on typed tool", "`yorishiro-proxy client resend_http params.flow_id=X`", "server rejects"},
		{"stray positional", "`yorishiro-proxy client query flow ID ...`", "extra positional"},
		{"missing required positions", "`yorishiro-proxy client fuzz_http flow_id=X`", `missing required parameter "positions"`},
		{"malformed JSON", "`yorishiro-proxy client fuzz_http flow_id=X positions='[{'`", "positions"},
		{"typed placeholder", "`yorishiro-proxy client query resource=flows limit=N`", "limit"},
		{"help for unknown tool", "`yorishiro-proxy client resend --help`", "clientToolHelp"},
		{"unsupported shell construct", "`yorishiro-proxy client query resource=flows | jq .`", "unsupported shell construct"},
		{"not a plain invocation", "`YP_CLIENT_FORMAT=raw yorishiro-proxy client query resource=flows`", "not a plain"},
		// USK-1244: a gRPC RPC needs at least one DATA frame, so messages
		// is required even when flow_id supplies everything else.
		{"resend_grpc without messages", "`yorishiro-proxy client resend_grpc flow_id=X`", "messages"},
		{"fuzz_grpc without messages", "`yorishiro-proxy client fuzz_grpc flow_id=X positions='[{\"path\":\"method\",\"payloads\":[\"A\"]}]'`", "messages"},

		// T4 positive controls.
		{"comma array", "`yorishiro-proxy client configure tls_passthrough.add='a,b'`", ""},
		{"positional query", "`yorishiro-proxy client query flow ID`", ""},
		{"manage nested bool", "`yorishiro-proxy client manage action=delete_flows params.confirm=true`", ""},
		{"list-servers", "`yorishiro-proxy client list-servers`", ""},
		{"tool help", "`yorishiro-proxy client query --help`", ""},
		{"client help", "`yorishiro-proxy client -help`", ""},
		{"fuzz positions JSON", "```bash\nyorishiro-proxy client fuzz_http flow_id=X \\\n  positions='[{\"path\":\"raw_query\",\"payloads\":[\"test1\",\"test2\",\"test3\"]}]'\n```", ""},
		{"SQLi quote idiom", "```bash\nyorishiro-proxy client fuzz_http flow_id=X positions='[{\"path\":\"raw_query\",\"payloads\":[\"'\\'' OR '\\''1'\\''='\\''1\"]}]'\n```", ""},
		{"conn flag", "`yorishiro-proxy client query resource=status --format table`", ""},
		{"resend_grpc with messages", "`yorishiro-proxy client resend_grpc flow_id=X messages='[{\"payload\":\"hi\"}]'`", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			examples := extractClientExamples("fixture.md", tt.doc)
			if len(examples) != 1 {
				t.Fatalf("extracted %d examples from %q, want 1", len(examples), tt.doc)
			}
			err := examples[0].Err
			if err == nil {
				err = checkClientExample(ctx, session, examples[0].Args)
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("want accepted, got: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("want rejection containing %q, got accepted", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("rejection = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestExtractClientExamples_Continuation pins the extractor's `\`+newline
// joining to bash: only an unescaped backslash that is the very last byte
// of the line continues it. A backslash followed by trailing whitespace is
// an escaped space in bash (the next line runs as a separate command), and
// a comment swallows a trailing backslash; both must be reported, not
// silently joined.
func TestExtractClientExamples_Continuation(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantArgs []string // nil = want Err
	}{
		{"raw trailing backslash joins", "```bash\nyorishiro-proxy client query resource=flows \\\n  limit=5\n```", []string{"query", "resource=flows", "limit=5"}},
		{"escaped backslash does not join", "```bash\nyorishiro-proxy client query resource=flows a\\\\\nlimit=5\n```", []string{"query", "resource=flows", `a\`}},
		{"backslash then trailing space", "```bash\nyorishiro-proxy client query resource=flows \\ \n  limit=5\n```", nil},
		{"backslash then trailing tab", "```bash\nyorishiro-proxy client query resource=flows \\\t\n  limit=5\n```", nil},
		{"comment swallows continuation", "```bash\nyorishiro-proxy client query resource=flows # note \\\n  bogus=1\n```", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			examples := extractClientExamples("fixture.md", tt.doc)
			if len(examples) != 1 {
				t.Fatalf("extracted %d examples from %q, want 1", len(examples), tt.doc)
			}
			ex := examples[0]
			if tt.wantArgs == nil {
				if ex.Err == nil {
					t.Fatalf("want an error, got args %q", ex.Args)
				}
				return
			}
			if ex.Err != nil {
				t.Fatalf("unexpected error: %v", ex.Err)
			}
			if strings.Join(ex.Args, "\x00") != strings.Join(tt.wantArgs, "\x00") || len(ex.Args) != len(tt.wantArgs) {
				t.Errorf("args = %q, want %q", ex.Args, tt.wantArgs)
			}
		})
	}
}

// TestShellWords (T5) pins the tokenizer to shell semantics, and that it
// refuses constructs it does not model.
func TestShellWords(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "plain", in: "a b  c", want: []string{"a", "b", "c"}},
		{name: "single quotes", in: `k='a b,c'`, want: []string{"k=a b,c"}},
		{name: "double quotes", in: `k="a \"b\" \\ c"`, want: []string{`k=a "b" \ c`}},
		{name: "double quote keeps other backslash", in: `"a\nb"`, want: []string{`a\nb`}},
		{name: "backslash escape", in: `a\ b`, want: []string{"a b"}},
		{name: "quote idiom", in: `p='["'\'' OR 1"]'`, want: []string{`p=["' OR 1"]`}},
		{name: "continuation across indented lines", in: "cmd a=1 \\\n    b=2 \\\n  c=3", want: []string{"cmd", "a=1", "b=2", "c=3"}},
		{name: "comment", in: "cmd a # trailing", want: []string{"cmd", "a"}},
		{name: "comment then trailing blank line", in: "cmd a # trailing\n  ", want: []string{"cmd", "a"}},
		// In bash a comment swallows a trailing `\`, so the command ends at
		// the comment; content joined after it would run as a new command.
		{name: "comment swallows continuation", in: "cmd a # note \\\n  b=2", wantErr: true},
		{name: "hash inside word", in: "a#b", want: []string{"a#b"}},
		{name: "empty quoted word", in: "a ''", want: []string{"a", ""}},
		{name: "dollar", in: "a $HOME", wantErr: true},
		{name: "dollar in double quotes", in: `a "$HOME"`, wantErr: true},
		{name: "backtick", in: "a `id`", wantErr: true},
		{name: "pipe", in: "a | b", wantErr: true},
		{name: "semicolon", in: "a; b", wantErr: true},
		{name: "and list", in: "a && b", wantErr: true},
		{name: "redirect out", in: "a > f", wantErr: true},
		{name: "redirect in", in: "a < f", wantErr: true},
		{name: "background", in: "a &", wantErr: true},
		{name: "glob", in: "a *.har", wantErr: true},
		{name: "unterminated single", in: "a 'b", wantErr: true},
		{name: "unterminated double", in: `a "b`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := shellWords(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("shellWords(%q) = %q, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("shellWords(%q): %v", tt.in, err)
			}
			if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") || len(got) != len(tt.want) {
				t.Errorf("shellWords(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
