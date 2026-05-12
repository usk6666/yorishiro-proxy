package macro

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanForResiduals_Patterns(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantEmpty bool
		wantHas   []string // substrings that must appear in the message
	}{
		// Positives — three supported foreign syntaxes.
		{
			name:    "handlebars positive",
			input:   "Bearer {{session_uuid}}",
			wantHas: []string{"{{session_uuid}}"},
		},
		{
			name:    "dollar positive",
			input:   `{"id":${user_id}}`,
			wantHas: []string{"${user_id}"},
		},
		{
			name:    "percent positive",
			input:   "DOMAIN\\%username%",
			wantHas: []string{"%username%"},
		},
		{
			name:    "underscore identifier accepted",
			input:   "X-{{_priv}}-Y",
			wantHas: []string{"{{_priv}}"},
		},
		{
			name:    "multiple distinct in one input",
			input:   "a={{x}} b=${y} c=%z%",
			wantHas: []string{"{{x}}", "${y}", "%z%"},
		},

		// Negatives — must not trigger.
		{
			name:      "empty input",
			input:     "",
			wantEmpty: true,
		},
		{
			name:      "no templates",
			input:     "https://example.com/api/users?id=42",
			wantEmpty: true,
		},
		{
			name:      "percent-encoding %20 ignored",
			input:     "https://example.com/path%20with%20spaces",
			wantEmpty: true,
		},
		{
			name:      "percent-encoded byte %ff ignored",
			input:     "binary %ff data",
			wantEmpty: true,
		},
		{
			name:      "css interpolation with non-identifier interior ignored",
			input:     "{{ foo.bar }}",
			wantEmpty: true,
		},
		{
			name:      "framework directive with leading-dash ignored",
			input:     "{{- spaced -}}",
			wantEmpty: true,
		},
		{
			name:      "arithmetic-style expression ignored",
			input:     "${1+2}",
			wantEmpty: true,
		},
		{
			name:      "identifier starting with digit ignored",
			input:     "{{1abc}}",
			wantEmpty: true,
		},
		{
			name:      "empty interior ignored",
			input:     "{{}}",
			wantEmpty: true,
		},
		{
			name:      "section sign supported syntax ignored by foreign detector",
			input:     "Bearer §session_uuid§",
			wantEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForResiduals(tc.input)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("scanForResiduals(%q) = %q, want empty", tc.input, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("scanForResiduals(%q) = empty, want non-empty", tc.input)
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("scanForResiduals(%q) = %q, missing %q", tc.input, got, want)
				}
			}
		})
	}
}

func TestScanForResiduals_DedupesMatches(t *testing.T) {
	got := scanForResiduals("{{x}} {{x}} {{x}}")
	if got == "" {
		t.Fatalf("expected non-empty result")
	}
	if strings.Count(got, "{{x}}") != 1 {
		t.Errorf("expected exactly one {{x}} sample (dedup), got %q", got)
	}
}

func TestScanForResiduals_TruncatesAtSampleCap(t *testing.T) {
	// 7 distinct identifier-shaped matches; cap is 5.
	input := "{{a}} {{b}} {{c}} {{d}} {{e}} {{f}} {{g}}"
	got := scanForResiduals(input)
	if got == "" {
		t.Fatalf("expected non-empty result")
	}
	if !strings.Contains(got, "...(2 more)") {
		t.Errorf("expected truncation marker '...(2 more)', got %q", got)
	}
}

func TestDetectUnresolvedTemplates_NilReturnsNil(t *testing.T) {
	if got := DetectUnresolvedTemplates(nil); got != nil {
		t.Errorf("DetectUnresolvedTemplates(nil) = %v, want nil", got)
	}
}

func TestDetectUnresolvedTemplates_CleanRequest(t *testing.T) {
	req := &SendRequest{
		Method:  "GET",
		URL:     "https://example.com/api/users",
		Headers: map[string][]string{"Authorization": {"Bearer abc123"}},
		Body:    []byte(`{"id":42}`),
	}
	if got := DetectUnresolvedTemplates(req); len(got) != 0 {
		t.Errorf("DetectUnresolvedTemplates(clean) = %v, want empty", got)
	}
}

func TestDetectUnresolvedTemplates_URLDetected(t *testing.T) {
	req := &SendRequest{
		URL: "https://example.com/api/users/{{user_id}}",
	}
	got := DetectUnresolvedTemplates(req)
	if len(got) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "url: ") {
		t.Errorf("expected url: prefix, got %q", got[0])
	}
	if !strings.Contains(got[0], "{{user_id}}") {
		t.Errorf("expected {{user_id}} in warning, got %q", got[0])
	}
}

func TestDetectUnresolvedTemplates_HeaderValueDetected(t *testing.T) {
	req := &SendRequest{
		URL: "https://example.com",
		Headers: map[string][]string{
			"X-Session-UUID": {"{{session_uuid}}"},
			"Authorization":  {"Bearer real-token"},
		},
	}
	got := DetectUnresolvedTemplates(req)
	if len(got) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "header:X-Session-UUID: ") {
		t.Errorf("expected header:X-Session-UUID prefix, got %q", got[0])
	}
}

func TestDetectUnresolvedTemplates_HeaderNameNotScanned(t *testing.T) {
	// Header NAME contains {{foo}} but value is clean — must not trigger.
	req := &SendRequest{
		URL: "https://example.com",
		Headers: map[string][]string{
			"X-{{header_name}}": {"plain-value"},
		},
	}
	if got := DetectUnresolvedTemplates(req); len(got) != 0 {
		t.Errorf("header name should not be scanned; got %v", got)
	}
}

func TestDetectUnresolvedTemplates_BodyDetected(t *testing.T) {
	req := &SendRequest{
		URL:  "https://example.com",
		Body: []byte(`{"token":"${session}"}`),
	}
	got := DetectUnresolvedTemplates(req)
	if len(got) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "body: ") {
		t.Errorf("expected body: prefix, got %q", got[0])
	}
	if !strings.Contains(got[0], "${session}") {
		t.Errorf("expected ${session} in warning, got %q", got[0])
	}
}

func TestDetectUnresolvedTemplates_BodyScanBounded(t *testing.T) {
	// Place an offending token strictly outside MaxUnresolvedScanBytes.
	prefix := bytes.Repeat([]byte("a"), MaxUnresolvedScanBytes)
	body := append(prefix, []byte("{{too_far}}")...)
	req := &SendRequest{URL: "https://example.com", Body: body}
	if got := DetectUnresolvedTemplates(req); len(got) != 0 {
		t.Errorf("body beyond MaxUnresolvedScanBytes should not be scanned; got %v", got)
	}

	// Sanity: a token at the very start IS detected.
	body2 := append([]byte("{{close}}"), bytes.Repeat([]byte("z"), 100)...)
	req2 := &SendRequest{URL: "https://example.com", Body: body2}
	if got := DetectUnresolvedTemplates(req2); len(got) != 1 {
		t.Errorf("body within window must be scanned; got %v", got)
	}
}

func TestDetectUnresolvedTemplates_AllLocationsScanned(t *testing.T) {
	req := &SendRequest{
		URL: "https://example.com/{{u}}",
		Headers: map[string][]string{
			"X-A": {"%a%"},
			"X-B": {"plain"},
		},
		Body: []byte("${b}"),
	}
	got := DetectUnresolvedTemplates(req)
	if len(got) != 3 {
		t.Fatalf("expected 3 warnings (url + header + body), got %d: %v", len(got), got)
	}
	prefixes := []string{"url: ", "header:X-A: ", "body: "}
	for i, p := range prefixes {
		if !strings.HasPrefix(got[i], p) {
			t.Errorf("warning[%d] = %q, want prefix %q", i, got[i], p)
		}
	}
}

func TestDetectUnresolvedTemplates_PercentEncodingNotFalsePositive(t *testing.T) {
	req := &SendRequest{
		URL:     "https://example.com/path?q=hello%20world%21",
		Headers: map[string][]string{"Cookie": {"sid=%20"}},
		Body:    []byte("encoded=%2F%2Fpath"),
	}
	if got := DetectUnresolvedTemplates(req); len(got) != 0 {
		t.Errorf("percent-encoded bytes should not trigger; got %v", got)
	}
}

func TestDetectUnresolvedTemplates_SectionSignNotFlagged(t *testing.T) {
	// §var§ is the SUPPORTED syntax — it survives ExpandTemplate as a literal
	// if the var is unknown, and the detector must not flag it.
	req := &SendRequest{
		URL:     "https://example.com/§unknown§",
		Headers: map[string][]string{"X-A": {"§missing§"}},
		Body:    []byte("body=§nope§"),
	}
	if got := DetectUnresolvedTemplates(req); len(got) != 0 {
		t.Errorf("§...§ tokens are out of scope for this detector; got %v", got)
	}
}
