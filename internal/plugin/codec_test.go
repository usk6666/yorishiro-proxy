package plugin

import (
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

func TestCodecModule_IndividualEncode(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "base64 encode",
			script: `result = codec.base64("hello")`,
			want:   "aGVsbG8=",
		},
		{
			name:   "hex encode",
			script: `result = codec.hex("abc")`,
			want:   "616263",
		},
		{
			name:   "url_encode_query",
			script: `result = codec.url_encode_query("hello world")`,
			want:   "hello+world",
		},
		{
			name:   "md5 encode",
			script: `result = codec.md5("hello")`,
			want:   "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name:   "upper encode",
			script: `result = codec.upper("hello")`,
			want:   "HELLO",
		},
		{
			name:   "lower encode",
			script: `result = codec.lower("HELLO")`,
			want:   "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predeclared := starlark.StringDict{
				"codec": newCodecModule(),
			}
			thread := &starlark.Thread{Name: "test"}
			globals, err := starlark.ExecFileOptions(
				&syntax.FileOptions{},
				thread, "test.star", tt.script, predeclared,
			)
			if err != nil {
				t.Fatalf("exec error: %v", err)
			}
			got, ok := globals["result"]
			if !ok {
				t.Fatal("result not found in globals")
			}
			gotStr, ok := starlark.AsString(got)
			if !ok {
				t.Fatalf("result is not a string: %v", got)
			}
			if gotStr != tt.want {
				t.Errorf("got %q, want %q", gotStr, tt.want)
			}
		})
	}
}

func TestCodecModule_IndividualDecode(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "base64 decode",
			script: `result = codec.base64_decode("aGVsbG8=")`,
			want:   "hello",
		},
		{
			name:   "hex decode",
			script: `result = codec.hex_decode("616263")`,
			want:   "abc",
		},
		{
			name:   "url_encode_query decode",
			script: `result = codec.url_encode_query_decode("hello+world")`,
			want:   "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predeclared := starlark.StringDict{
				"codec": newCodecModule(),
			}
			thread := &starlark.Thread{Name: "test"}
			globals, err := starlark.ExecFileOptions(
				&syntax.FileOptions{},
				thread, "test.star", tt.script, predeclared,
			)
			if err != nil {
				t.Fatalf("exec error: %v", err)
			}
			got, ok := globals["result"]
			if !ok {
				t.Fatal("result not found in globals")
			}
			gotStr, ok := starlark.AsString(got)
			if !ok {
				t.Fatalf("result is not a string: %v", got)
			}
			if gotStr != tt.want {
				t.Errorf("got %q, want %q", gotStr, tt.want)
			}
		})
	}
}

func TestCodecModule_IrreversibleDecodeError(t *testing.T) {
	irreversible := []string{"md5", "sha256", "lower", "upper"}
	for _, name := range irreversible {
		t.Run(name+"_decode error", func(t *testing.T) {
			script := `result = codec.` + name + `_decode("anything")`
			predeclared := starlark.StringDict{
				"codec": newCodecModule(),
			}
			thread := &starlark.Thread{Name: "test"}
			_, err := starlark.ExecFileOptions(
				&syntax.FileOptions{},
				thread, "test.star", script, predeclared,
			)
			if err == nil {
				t.Error("expected error for irreversible decode")
			}
		})
	}
}

func TestCodecModule_ChainEncode(t *testing.T) {
	script := `result = codec.encode("hello world", ["url_encode_query", "base64"])`
	predeclared := starlark.StringDict{
		"codec": newCodecModule(),
	}
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread, "test.star", script, predeclared,
	)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	got, _ := starlark.AsString(globals["result"])
	want := "aGVsbG8rd29ybGQ="
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCodecModule_ChainDecode(t *testing.T) {
	script := `result = codec.decode("aGVsbG8rd29ybGQ=", ["url_encode_query", "base64"])`
	predeclared := starlark.StringDict{
		"codec": newCodecModule(),
	}
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread, "test.star", script, predeclared,
	)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	got, _ := starlark.AsString(globals["result"])
	want := "hello world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCodecModule_List(t *testing.T) {
	script := `result = codec.list()`
	predeclared := starlark.StringDict{
		"codec": newCodecModule(),
	}
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread, "test.star", script, predeclared,
	)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	list, ok := globals["result"].(*starlark.List)
	if !ok {
		t.Fatalf("result is not a list: %T", globals["result"])
	}
	if list.Len() != 14 {
		t.Errorf("list length = %d, want 14", list.Len())
	}
}

func TestCodecModule_EncodeErrorUnknownCodec(t *testing.T) {
	script := `result = codec.encode("hello", ["nonexistent"])`
	predeclared := starlark.StringDict{
		"codec": newCodecModule(),
	}
	thread := &starlark.Thread{Name: "test"}
	_, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread, "test.star", script, predeclared,
	)
	if err == nil {
		t.Error("expected error for unknown codec in chain")
	}
}
