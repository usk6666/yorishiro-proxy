package envelope

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// wireURLGuardRule forbids one net/url idiom outside wirepath.go. USK-1139:
// Flow.URL (and the canonical scope/safety URLs built from wire paths) must
// be produced and consumed only through URLFromWirePath / WirePath /
// WireURLString / ParseWireURL, because url.URL{Path: wire}.String()
// re-escapes the wire bytes and url.Parse decodes or rejects them.
type wireURLGuardRule struct {
	name    string
	pattern *regexp.Regexp
	// dirs restricts the rule to these slash-separated prefixes under the
	// repository root (empty = everywhere scanned).
	dirs []string
	// allow lists substrings that mark a match as a legitimate non-wire use
	// (net/http request URLs, user-typed URLs, constant paths).
	allow []string
}

var wireURLGuardRules = []wireURLGuardRule{
	{
		name:    "URL.String() on a wire-path URL",
		pattern: regexp.MustCompile(`URL(\([^)]*\))?\.String\(\)`),
		allow: []string{
			// *http.Request URLs: net/http owns their encoding.
			"httpReq.URL.String()",
			"resp.Request.URL.String()",
		},
	},
	{
		name:    "url.Parse of a stored / wire URL",
		pattern: regexp.MustCompile(`url\.Parse\(`),
		dirs:    []string{"internal/flow/", "internal/pipeline/", "internal/mcp/"},
		allow: []string{
			// Operator-typed absolute URLs, not recorded wire paths.
			"url.Parse(step.OverrideURL)",
			"url.Parse(params.URL)",
		},
	},
	{
		name:    "url.URL literal built from a wire path",
		pattern: regexp.MustCompile(`url\.URL\{`),
		dirs:    []string{"internal/flow/", "internal/pipeline/", "internal/mcp/"},
		allow: []string{
			"&url.URL{}",
			// Constant reflection path; no wire bytes involved.
			"canonicalURL := &url.URL{",
		},
	},
	{
		name:    "decoded URL.Path read where the wire path is meant",
		pattern: regexp.MustCompile(`(URL|\bu)\.Path\b`),
		// USK-1139 review F-2: every package that consumes a recorded or
		// in-flight wire path, not just the original three.
		dirs: []string{
			"internal/mcp/", "internal/job/", "internal/connector/",
			"internal/flow/", "internal/pipeline/", "internal/session/",
			"internal/rules/", "internal/macro/",
		},
		allow: []string{
			// net/http server request in the Web UI handler.
			"r.URL.Path",
			// Constant reflection path.
			"canonicalURL.Path",
		},
	},
}

// TestWireURLGuard_NoDirectNetURLOnWirePaths is the grep-style guard from
// the USK-1139 test plan (row 13).
func TestWireURLGuard_NoDirectNetURLOnWirePaths(t *testing.T) {
	root := filepath.Join("..", "..")
	var violations []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "dist" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if rel == "internal/envelope/wirepath.go" {
				return nil
			}
			violations = append(violations, scanWireURLGuard(t, path, rel)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	for _, v := range violations {
		t.Error(v)
	}
}

func scanWireURLGuard(t *testing.T, path, rel string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, r := range wireURLGuardRules {
			if !ruleCoversPath(r, rel) || !r.pattern.MatchString(line) || lineAllowed(r, line) {
				continue
			}
			out = append(out, rel+":"+strconv.Itoa(lineNo)+": "+r.name+
				" — use envelope.URLFromWirePath / WirePath / WireURLString / ParseWireURL: "+strings.TrimSpace(line))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func ruleCoversPath(r wireURLGuardRule, rel string) bool {
	if len(r.dirs) == 0 {
		return true
	}
	for _, d := range r.dirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	return false
}

func lineAllowed(r wireURLGuardRule, line string) bool {
	for _, a := range r.allow {
		if strings.Contains(line, a) {
			return true
		}
	}
	return false
}
