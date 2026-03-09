package payload

import (
	"testing"
)

func TestReverse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "olleh"},
		{"empty", "", ""},
		{"single", "a", "a"},
		{"palindrome", "aba", "aba"},
		{"unicode", "\u3042\u3044\u3046", "\u3046\u3044\u3042"},
		{"with spaces", "a b c", "c b a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Reverse(tt.input)
			if got != tt.want {
				t.Errorf("Reverse(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRepeat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{"repeat 3", "ab", 3, "ababab"},
		{"repeat 1", "ab", 1, "ab"},
		{"repeat 0", "ab", 0, ""},
		{"repeat negative", "ab", -1, ""},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Repeat(tt.input, tt.n)
			if got != tt.want {
				t.Errorf("Repeat(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{"truncate shorter", "hello", 3, "hel"},
		{"truncate equal", "hello", 5, "hello"},
		{"truncate longer", "hello", 10, "hello"},
		{"truncate zero", "hello", 0, ""},
		{"truncate negative", "hello", -1, ""},
		{"empty string", "", 5, ""},
		{"unicode", "\u3042\u3044\u3046\u3048\u304a", 3, "\u3042\u3044\u3046"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.input, tt.n)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
			}
		})
	}
}

func TestPrefix(t *testing.T) {
	fn := Prefix(">>")
	got := fn("hello")
	want := ">>hello"
	if got != want {
		t.Errorf("Prefix(\">>\")(\"hello\") = %q, want %q", got, want)
	}

	// Empty prefix.
	fn = Prefix("")
	got = fn("hello")
	if got != "hello" {
		t.Errorf("Prefix(\"\")(\"hello\") = %q, want \"hello\"", got)
	}
}

func TestSuffix(t *testing.T) {
	fn := Suffix("<<")
	got := fn("hello")
	want := "hello<<"
	if got != want {
		t.Errorf("Suffix(\"<<\")(\"hello\") = %q, want %q", got, want)
	}

	// Empty suffix.
	fn = Suffix("")
	got = fn("hello")
	if got != "hello" {
		t.Errorf("Suffix(\"\")(\"hello\") = %q, want \"hello\"", got)
	}
}

func TestApplyTransforms(t *testing.T) {
	payloads := []string{"hello", "world"}

	t.Run("no transforms", func(t *testing.T) {
		got := ApplyTransforms(payloads)
		if !strSliceEqual(got, payloads) {
			t.Errorf("got %v, want %v", got, payloads)
		}
	})

	t.Run("single transform", func(t *testing.T) {
		got := ApplyTransforms(payloads, Prefix("["))
		want := []string{"[hello", "[world"}
		if !strSliceEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("chained transforms", func(t *testing.T) {
		got := ApplyTransforms(payloads, Prefix("["), Suffix("]"))
		want := []string{"[hello]", "[world]"}
		if !strSliceEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("empty payloads", func(t *testing.T) {
		got := ApplyTransforms(nil, Prefix("["))
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})
}

func TestTransformPipeline(t *testing.T) {
	gen := &RangeGenerator{Start: 1, End: 3, Step: 1}
	tp := &TransformPipeline{
		Generator:  gen,
		Transforms: []Transform{Prefix("<"), Suffix(">")},
	}
	got, err := tp.Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"<1>", "<2>", "<3>"}
	if !strSliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTransformPipelineGeneratorError(t *testing.T) {
	gen := &RangeGenerator{Start: 1, End: 5, Step: 0} // zero step = error
	tp := &TransformPipeline{
		Generator:  gen,
		Transforms: []Transform{Prefix("<")},
	}
	_, err := tp.Generate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
