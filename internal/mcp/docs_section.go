package mcp

import (
	"fmt"
	"strings"
	"unicode"
)

// docsOutlineMaxLevel bounds the heading depth listed on the unknown-section
// error path. The docs tool can address H2–H6, but listing every level of a
// large document (help_configure.md has 43 H2+H3 headings) would cost more
// tokens than simply reading the document. H2–H4 keeps the worst case around
// 150 tokens for a single topic. No help document uses H5 or H6 today.
const docsOutlineMaxLevel = 4

// docsHeading is one ATX markdown heading located inside a help document.
type docsHeading struct {
	// level is the heading depth: 1 for "# ", 2 for "## ", and so on.
	level int
	// text is the heading text with the leading "#" run, the optional
	// closing "#" run, and surrounding whitespace removed.
	text string
	// start is the 0-based index of the heading's line within the document.
	start int
}

// scanDocsHeadings returns every ATX heading in lines, in document order.
//
// The scanner is fence-aware: a line that looks like a heading but sits
// inside a fenced code block (``` or ~~~) is not a heading. Help documents
// are hand-maintained markdown that routinely embed shell transcripts, JSON
// and config snippets, so a naive "^#" scan would eventually promote a
// comment line into an addressable section — or, worse, truncate a real
// section at a "#" inside one of its own examples.
func scanDocsHeadings(lines []string) []docsHeading {
	var out []docsHeading

	// fenceChar/fenceLen track the currently open code fence. fenceChar == 0
	// means "not inside a fence". A fence closes only on a run of the same
	// character that is at least as long as the opening run, so a ```` ```` `
	// block may legally contain ``` lines.
	var fenceChar byte
	var fenceLen int

	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")

		if c, n := docsFenceMarker(trimmed); n > 0 {
			switch {
			case fenceChar == 0:
				fenceChar, fenceLen = c, n
			case c == fenceChar && n >= fenceLen:
				fenceChar, fenceLen = 0, 0
			}
			continue
		}
		if fenceChar != 0 {
			continue
		}

		level := 0
		for level < len(trimmed) && trimmed[level] == '#' {
			level++
		}
		if level == 0 || level > 6 {
			continue
		}
		rest := trimmed[level:]
		// CommonMark requires whitespace (or end of line) after the opening
		// "#" run; "#tag" and "#!/bin/sh" are body text, not headings.
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		text := trimDocsClosingHashes(strings.TrimSpace(rest))
		if text == "" {
			continue
		}
		out = append(out, docsHeading{level: level, text: text, start: i})
	}
	return out
}

// docsFenceMarker reports the fence character and run length when line opens
// or closes a fenced code block. It returns (0, 0) when line is not a fence.
// line is expected to already have its leading whitespace trimmed.
func docsFenceMarker(line string) (byte, int) {
	if len(line) < 3 {
		return 0, 0
	}
	c := line[0]
	if c != '`' && c != '~' {
		return 0, 0
	}
	n := 0
	for n < len(line) && line[n] == c {
		n++
	}
	if n < 3 {
		return 0, 0
	}
	return c, n
}

// trimDocsClosingHashes removes a CommonMark closing "#" run from a heading
// ("## Foo ##" → "Foo"). The run only counts as a closing sequence when it is
// preceded by whitespace or spans the whole string, so a heading like "C#"
// survives intact.
func trimDocsClosingHashes(text string) string {
	j := len(text)
	for j > 0 && text[j-1] == '#' {
		j--
	}
	if j == len(text) {
		return text
	}
	if j == 0 || text[j-1] == ' ' || text[j-1] == '\t' {
		return strings.TrimSpace(text[:j])
	}
	return text
}

// slugifyDocsHeading returns the GitHub-style anchor slug for a heading:
// lower-cased, punctuation dropped, spaces collapsed to hyphens. An agent
// that copied an anchor out of rendered markdown (or out of the docs index)
// can therefore pass either spelling.
func slugifyDocsHeading(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '\t':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// docsSectionMatches reports whether selector addresses heading. Matching is
// case-insensitive and whitespace-trimmed against the literal heading text,
// and additionally accepts the heading's slug form.
func docsSectionMatches(selector, heading string) bool {
	sel := strings.ToLower(strings.TrimSpace(selector))
	if sel == "" {
		return false
	}
	if sel == strings.ToLower(strings.TrimSpace(heading)) {
		return true
	}
	slug := slugifyDocsHeading(heading)
	return slug != "" && slugifyDocsHeading(selector) == slug
}

// docsH2Sections returns the H2 heading texts of doc, in document order.
// Only H2 is indexed: measured over the 22 help documents, an H2-only index
// costs ~1,200 tokens where an H2+H3 index costs ~4,220 — more than simply
// reading the largest document, which would defeat the point of the index.
// The finer outline is served on demand by the unknown-section error path.
func docsH2Sections(doc string) []string {
	headings := scanDocsHeadings(strings.Split(doc, "\n"))
	out := make([]string, 0, len(headings))
	for _, h := range headings {
		if h.level == 2 {
			out = append(out, h.text)
		}
	}
	return out
}

// extractDocsSection slices the section named by selector out of doc.
//
// The returned text starts at the matched heading's own line and runs to the
// next heading of the same or a shallower level, so requesting an H2 also
// returns its H3/H4 children. The slice is a contiguous substring of the
// embedded document — never a reconstruction — so the returned markdown is
// byte-identical to what docs(topic=...) would have returned for that span.
//
// H1 is not addressable: it is the document title, and docs(topic=...)
// already returns the whole document including it.
//
// When several headings share the same text (help_configure.md has "Usage
// Examples" twice), the first is returned with a trailing note. Erroring
// instead would block an agent that spelled a real section correctly.
func extractDocsSection(topic, doc, selector string) (string, error) {
	lines := strings.Split(doc, "\n")
	headings := scanDocsHeadings(lines)

	var matches []int
	for i, h := range headings {
		if h.level < 2 {
			continue
		}
		if docsSectionMatches(selector, h.text) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("unknown section %q in docs topic %q: available sections are:\n%s",
			selector, topic, strings.Join(docsOutline(headings), "\n"))
	}

	first := matches[0]
	h := headings[first]
	end := len(lines)
	for _, next := range headings[first+1:] {
		if next.level <= h.level {
			end = next.start
			break
		}
	}

	body := strings.TrimRight(strings.Join(lines[h.start:end], "\n"), "\n")
	if len(matches) > 1 {
		body += fmt.Sprintf("\n\n(note: %d sections in this topic share this heading; this is the first)", len(matches))
	}
	return body, nil
}

// docsOutline renders the level-prefixed H2–H4 outline used by the
// unknown-section error message. Each entry is spelled exactly as it must be
// passed back in section=..., so the error is directly actionable.
func docsOutline(headings []docsHeading) []string {
	out := make([]string, 0, len(headings))
	for _, h := range headings {
		if h.level < 2 || h.level > docsOutlineMaxLevel {
			continue
		}
		out = append(out, "  "+strings.Repeat("#", h.level)+" "+h.text)
	}
	if len(out) == 0 {
		return []string{"  (this topic has no addressable sections; call docs(topic=...) without section)"}
	}
	return out
}
