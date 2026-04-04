package payload

import (
	"strings"
	"testing"
)

func TestRangeGenerator(t *testing.T) {
	tests := []struct {
		name    string
		gen     RangeGenerator
		want    []string
		wantErr string
	}{
		{
			name: "simple ascending",
			gen:  RangeGenerator{Start: 1, End: 5, Step: 1},
			want: []string{"1", "2", "3", "4", "5"},
		},
		{
			name: "ascending with step 2",
			gen:  RangeGenerator{Start: 0, End: 10, Step: 2},
			want: []string{"0", "2", "4", "6", "8", "10"},
		},
		{
			name: "descending",
			gen:  RangeGenerator{Start: 5, End: 1, Step: -1},
			want: []string{"5", "4", "3", "2", "1"},
		},
		{
			name: "descending with step -2",
			gen:  RangeGenerator{Start: 10, End: 0, Step: -2},
			want: []string{"10", "8", "6", "4", "2", "0"},
		},
		{
			name: "single value",
			gen:  RangeGenerator{Start: 5, End: 5, Step: 1},
			want: []string{"5"},
		},
		{
			name: "negative range",
			gen:  RangeGenerator{Start: -3, End: 3, Step: 1},
			want: []string{"-3", "-2", "-1", "0", "1", "2", "3"},
		},
		{
			name:    "zero step",
			gen:     RangeGenerator{Start: 1, End: 5, Step: 0},
			wantErr: "step cannot be zero",
		},
		{
			name: "empty range ascending step descending values",
			gen:  RangeGenerator{Start: 5, End: 1, Step: 1},
			want: nil,
		},
		{
			name: "empty range descending step ascending values",
			gen:  RangeGenerator{Start: 1, End: 5, Step: -1},
			want: nil,
		},
		{
			name:    "exceeds max payload count",
			gen:     RangeGenerator{Start: 0, End: maxPayloadCount + 1, Step: 1},
			wantErr: "exceeding maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.gen.Generate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strSliceEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCharsetGenerator(t *testing.T) {
	tests := []struct {
		name    string
		gen     CharsetGenerator
		want    []string
		wantLen int
		wantErr string
	}{
		{
			name: "binary length 2",
			gen:  CharsetGenerator{Charset: "01", Length: 2},
			want: []string{"00", "01", "10", "11"},
		},
		{
			name: "ab length 1",
			gen:  CharsetGenerator{Charset: "ab", Length: 1},
			want: []string{"a", "b"},
		},
		{
			name:    "abc length 3",
			gen:     CharsetGenerator{Charset: "abc", Length: 3},
			wantLen: 27, // 3^3
		},
		{
			name:    "empty charset",
			gen:     CharsetGenerator{Charset: "", Length: 2},
			wantErr: "charset cannot be empty",
		},
		{
			name:    "zero length",
			gen:     CharsetGenerator{Charset: "ab", Length: 0},
			wantErr: "length must be positive",
		},
		{
			name:    "negative length",
			gen:     CharsetGenerator{Charset: "ab", Length: -1},
			wantErr: "length must be positive",
		},
		{
			name:    "exceeds limit",
			gen:     CharsetGenerator{Charset: "abcdefghijklmnopqrstuvwxyz", Length: 10},
			wantErr: "more than",
		},
		{
			name: "unicode charset",
			gen:  CharsetGenerator{Charset: "\u3042\u3044", Length: 2},
			want: []string{"\u3042\u3042", "\u3042\u3044", "\u3044\u3042", "\u3044\u3044"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.gen.Generate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want != nil {
				if !strSliceEqual(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			}
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Errorf("got %d payloads, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestCharsetGeneratorOverflowDetection(t *testing.T) {
	// A charset of 100 characters with length 10 would produce 100^10 = 10^20 payloads,
	// which overflows int64. The overflow check should catch this before it happens.
	gen := CharsetGenerator{
		Charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~ab",
		Length:  10,
	}
	_, err := gen.Generate()
	if err == nil {
		t.Fatal("expected error for overflow-inducing charset/length combination, got nil")
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Errorf("expected overflow error, got: %v", err)
	}
}

func TestCharsetGeneratorNoDuplicates(t *testing.T) {
	gen := CharsetGenerator{Charset: "abc", Length: 3}
	got, err := gen.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]struct{})
	for _, s := range got {
		if _, ok := seen[s]; ok {
			t.Errorf("duplicate payload: %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestCaseVariationGenerator(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantSubset []string
		wantNil    bool
	}{
		{
			name:       "simple word",
			input:      "admin",
			wantSubset: []string{"admin", "ADMIN", "Admin"},
		},
		{
			name:       "mixed case",
			input:      "Admin",
			wantSubset: []string{"Admin", "admin", "ADMIN", "aDMIN"},
		},
		{
			name:    "empty input",
			input:   "",
			wantNil: true,
		},
		{
			name:       "single char",
			input:      "a",
			wantSubset: []string{"a", "A"},
		},
		{
			name:       "no letters",
			input:      "123",
			wantSubset: []string{"123"},
		},
		{
			name:       "mixed with numbers",
			input:      "a1b",
			wantSubset: []string{"a1b", "A1B", "A1b", "a1B"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := CaseVariationGenerator{Input: tt.input}
			got, err := gen.Generate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			gotSet := make(map[string]struct{})
			for _, s := range got {
				gotSet[s] = struct{}{}
			}
			for _, want := range tt.wantSubset {
				if _, ok := gotSet[want]; !ok {
					t.Errorf("missing expected variation %q in %v", want, got)
				}
			}
			// Check no duplicates.
			if len(gotSet) != len(got) {
				t.Errorf("got %d payloads but only %d unique", len(got), len(gotSet))
			}
		})
	}
}

func TestCaseVariationGeneratorLongInput(t *testing.T) {
	// Input with more than maxCaseBitVariations alpha characters should still work
	// but produce only fixed variations (no bit-flip explosion).
	input := "abcdefghijklmnopqrstuvwxyz"
	gen := CaseVariationGenerator{Input: input}
	got, err := gen.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have at least the fixed variations.
	if len(got) < 3 {
		t.Errorf("expected at least 3 variations, got %d", len(got))
	}
	// Should not explode to 2^26 variations.
	if len(got) > 100 {
		t.Errorf("expected limited variations for long input, got %d", len(got))
	}
}

func TestNullByteInjectionGenerator(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		minLen  int
	}{
		{
			name:   "simple string",
			input:  "admin",
			minLen: 4, // at least: \x00+input, input+\x00, %00+input, input+%00
		},
		{
			name:   "single char",
			input:  "a",
			minLen: 4, // prepend/append for both null byte variants
		},
		{
			name:    "empty input",
			input:   "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NullByteInjectionGenerator{Input: tt.input}
			got, err := gen.Generate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) < tt.minLen {
				t.Errorf("expected at least %d payloads, got %d: %v", tt.minLen, len(got), got)
			}
			// Check no duplicates.
			seen := make(map[string]struct{})
			for _, s := range got {
				if _, ok := seen[s]; ok {
					t.Errorf("duplicate payload: %q", s)
				}
				seen[s] = struct{}{}
			}
		})
	}
}

func TestNullByteInjectionContainsNullByte(t *testing.T) {
	gen := NullByteInjectionGenerator{Input: "test"}
	got, err := gen.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasRawNull := false
	hasURLNull := false
	for _, s := range got {
		if strings.Contains(s, "\x00") {
			hasRawNull = true
		}
		if strings.Contains(s, "%00") {
			hasURLNull = true
		}
	}
	if !hasRawNull {
		t.Error("no payloads contain raw null byte")
	}
	if !hasURLNull {
		t.Error("no payloads contain URL-encoded null byte")
	}
}

func TestNullByteInjectionExceedsLimit(t *testing.T) {
	// An input with enough characters to exceed maxPayloadCount should return an error.
	// estimatedCount = 2 * (len(runes) + 1), so we need len(runes) > maxPayloadCount/2.
	longInput := strings.Repeat("a", maxPayloadCount/2+1)
	gen := NullByteInjectionGenerator{Input: longInput}
	_, err := gen.Generate()
	if err == nil {
		t.Fatal("expected error for exceeding maxPayloadCount, got nil")
	}
	if !strings.Contains(err.Error(), "exceeding maximum") {
		t.Errorf("expected error about exceeding maximum, got: %v", err)
	}
}

func TestPipeline(t *testing.T) {
	gen := &RangeGenerator{Start: 1, End: 3, Step: 1}

	t.Run("no encode", func(t *testing.T) {
		p := NewPipeline(gen, nil)
		got, err := p.Generate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"1", "2", "3"}
		if !strSliceEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("with encode", func(t *testing.T) {
		p := NewPipeline(gen, func(s string) (string, error) {
			return "[" + s + "]", nil
		})
		got, err := p.Generate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"[1]", "[2]", "[3]"}
		if !strSliceEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("encode error", func(t *testing.T) {
		p := NewPipeline(gen, func(s string) (string, error) {
			if s == "2" {
				return "", errBoom
			}
			return s, nil
		})
		_, err := p.Generate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

var errBoom = &testError{msg: "boom"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestPipelineWithCodecIntegration(t *testing.T) {
	// Demonstrates that Pipeline can use encoding.Registry.Encode as the EncodeFunc.
	// This is a unit test that uses a mock encode function simulating codec behavior.
	gen := &RangeGenerator{Start: 1, End: 3, Step: 1}
	mockBase64 := func(s string) (string, error) {
		// Simulated base64 encoding for test (not real base64).
		return "b64(" + s + ")", nil
	}
	p := NewPipeline(gen, mockBase64)
	got, err := p.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"b64(1)", "b64(2)", "b64(3)"}
	if !strSliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEstimateCount(t *testing.T) {
	tests := []struct {
		name       string
		start, end int
		step       int
		want       int
	}{
		{"ascending", 1, 10, 1, 10},
		{"ascending step 3", 1, 10, 3, 4},
		{"descending", 10, 1, -1, 10},
		{"descending step -3", 10, 1, -3, 4},
		{"single", 5, 5, 1, 1},
		{"empty ascending", 5, 1, 1, 0},
		{"empty descending", 1, 5, -1, 0},
		{"zero step", 1, 5, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := estimateCount(tt.start, tt.end, tt.step)
			if got != tt.want {
				t.Errorf("estimateCount(%d, %d, %d) = %d, want %d", tt.start, tt.end, tt.step, got, tt.want)
			}
		})
	}
}

func strSliceEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
