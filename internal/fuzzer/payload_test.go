package fuzzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPayloadSet_Validate(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name    string
		ps      PayloadSet
		wantErr bool
	}{
		{
			name: "valid wordlist",
			ps:   PayloadSet{Type: "wordlist", Values: []string{"a", "b"}},
		},
		{
			name:    "wordlist empty values",
			ps:      PayloadSet{Type: "wordlist", Values: []string{}},
			wantErr: true,
		},
		{
			name:    "wordlist exceeds max payload count",
			ps:      PayloadSet{Type: "wordlist", Values: make([]string, maxPayloadCount+1)},
			wantErr: true,
		},
		{
			name: "wordlist at max payload count",
			ps:   PayloadSet{Type: "wordlist", Values: make([]string, maxPayloadCount)},
		},
		{
			name: "valid file",
			ps:   PayloadSet{Type: "file", Path: "passwords.txt"},
		},
		{
			name:    "file empty path",
			ps:      PayloadSet{Type: "file"},
			wantErr: true,
		},
		{
			name:    "file absolute path",
			ps:      PayloadSet{Type: "file", Path: "/etc/passwd"},
			wantErr: true,
		},
		{
			name: "valid range",
			ps:   PayloadSet{Type: "range", Start: intPtr(0), End: intPtr(10)},
		},
		{
			name:    "range missing start",
			ps:      PayloadSet{Type: "range", End: intPtr(10)},
			wantErr: true,
		},
		{
			name:    "range missing end",
			ps:      PayloadSet{Type: "range", Start: intPtr(0)},
			wantErr: true,
		},
		{
			name: "valid sequence",
			ps:   PayloadSet{Type: "sequence", Start: intPtr(1), End: intPtr(5), Format: "user%03d"},
		},
		{
			name:    "sequence missing format",
			ps:      PayloadSet{Type: "sequence", Start: intPtr(1), End: intPtr(5)},
			wantErr: true,
		},
		{
			name:    "sequence missing start",
			ps:      PayloadSet{Type: "sequence", End: intPtr(5), Format: "u%d"},
			wantErr: true,
		},
		{
			name:    "invalid type",
			ps:      PayloadSet{Type: "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ps.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPayloadSet_GenerateWordlist(t *testing.T) {
	ps := PayloadSet{
		Type:   "wordlist",
		Values: []string{"alpha", "beta", "gamma"},
	}
	got, err := ps.Generate("")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d payloads, want 3", len(got))
	}
	for i, want := range []string{"alpha", "beta", "gamma"} {
		if got[i] != want {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestPayloadSet_GenerateRange(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name    string
		ps      PayloadSet
		want    []string
		wantErr bool
	}{
		{
			name: "ascending range default step",
			ps:   PayloadSet{Type: "range", Start: intPtr(1), End: intPtr(5)},
			want: []string{"1", "2", "3", "4", "5"},
		},
		{
			name: "ascending range with step 2",
			ps:   PayloadSet{Type: "range", Start: intPtr(0), End: intPtr(6), Step: intPtr(2)},
			want: []string{"0", "2", "4", "6"},
		},
		{
			name: "descending range",
			ps:   PayloadSet{Type: "range", Start: intPtr(5), End: intPtr(1), Step: intPtr(-1)},
			want: []string{"5", "4", "3", "2", "1"},
		},
		{
			name:    "zero step",
			ps:      PayloadSet{Type: "range", Start: intPtr(0), End: intPtr(5), Step: intPtr(0)},
			wantErr: true,
		},
		{
			name: "single value range",
			ps:   PayloadSet{Type: "range", Start: intPtr(3), End: intPtr(3)},
			want: []string{"3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ps.Generate("")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d payloads, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPayloadSet_GenerateSequence(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	ps := PayloadSet{
		Type:   "sequence",
		Start:  intPtr(1),
		End:    intPtr(3),
		Format: "user%03d",
	}
	got, err := ps.Generate("")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	want := []string{"user001", "user002", "user003"}
	if len(got) != len(want) {
		t.Fatalf("got %d payloads, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPayloadSet_GenerateFile(t *testing.T) {
	baseDir := t.TempDir()
	content := "payload1\npayload2\npayload3\n"
	if err := os.WriteFile(filepath.Join(baseDir, "test.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ps := PayloadSet{
		Type: "file",
		Path: "test.txt",
	}
	got, err := ps.Generate(baseDir)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	want := []string{"payload1", "payload2", "payload3"}
	if len(got) != len(want) {
		t.Fatalf("got %d payloads, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPayloadSet_GenerateFile_EmptyLines(t *testing.T) {
	baseDir := t.TempDir()
	content := "payload1\n\npayload2\n\n"
	if err := os.WriteFile(filepath.Join(baseDir, "test.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ps := PayloadSet{
		Type: "file",
		Path: "test.txt",
	}
	got, err := ps.Generate(baseDir)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// Empty lines should be skipped.
	if len(got) != 2 {
		t.Errorf("got %d payloads, want 2 (empty lines should be skipped)", len(got))
	}
}

func TestPayloadSet_GenerateFile_ExceedsMaxLines(t *testing.T) {
	baseDir := t.TempDir()

	// Create a file with maxPayloadCount+1 non-empty lines.
	f, err := os.Create(filepath.Join(baseDir, "huge.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxPayloadCount; i++ {
		if _, err := f.WriteString("x\n"); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	f.Close()

	ps := PayloadSet{
		Type: "file",
		Path: "huge.txt",
	}
	_, err = ps.Generate(baseDir)
	if err == nil {
		t.Fatal("Generate() expected error for file exceeding max line count, got nil")
	}
}

func TestResolveWordlistPath_Security(t *testing.T) {
	baseDir := t.TempDir()

	// Create a valid file.
	validFile := filepath.Join(baseDir, "valid.txt")
	if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		relPath string
		wantErr bool
	}{
		{
			name:    "valid relative path",
			relPath: "valid.txt",
		},
		{
			name:    "absolute path rejected",
			relPath: "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal with ..",
			relPath: "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "empty path",
			relPath: "",
			wantErr: true,
		},
		{
			name:    "nonexistent file",
			relPath: "nonexistent.txt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveWordlistPath(baseDir, tt.relPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveWordlistPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveWordlistPath_Subdirectory(t *testing.T) {
	baseDir := t.TempDir()
	subDir := filepath.Join(baseDir, "sqli")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(subDir, "error-based.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveWordlistPath(baseDir, "sqli/error-based.txt")
	if err != nil {
		t.Fatalf("resolveWordlistPath() error = %v", err)
	}
	if resolved != filePath {
		t.Errorf("resolved = %q, want %q", resolved, filePath)
	}
}
