package mcp

import (
	"encoding/base64"
	"testing"
)

func TestValidateRawPatch(t *testing.T) {
	offset0 := 0
	offset5 := 5
	offsetNeg := -1

	tests := []struct {
		name    string
		patch   RawPatch
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid offset patch",
			patch:   RawPatch{Offset: &offset0, DataBase64: base64.StdEncoding.EncodeToString([]byte("abc"))},
			wantErr: false,
		},
		{
			name:    "valid binary find/replace",
			patch:   RawPatch{FindBase64: base64.StdEncoding.EncodeToString([]byte("old")), ReplaceBase64: base64.StdEncoding.EncodeToString([]byte("new"))},
			wantErr: false,
		},
		{
			name:    "valid text find/replace",
			patch:   RawPatch{FindText: "old", ReplaceText: "new"},
			wantErr: false,
		},
		{
			name:    "valid binary find with empty replace (delete)",
			patch:   RawPatch{FindBase64: base64.StdEncoding.EncodeToString([]byte("old"))},
			wantErr: false,
		},
		{
			name:    "valid text find with empty replace (delete)",
			patch:   RawPatch{FindText: "old"},
			wantErr: false,
		},
		{
			name:    "no mode specified",
			patch:   RawPatch{},
			wantErr: true,
			errMsg:  "must specify one of",
		},
		{
			name: "multiple modes: offset + text",
			patch: RawPatch{
				Offset:     &offset0,
				DataBase64: base64.StdEncoding.EncodeToString([]byte("data")),
				FindText:   "text",
			},
			wantErr: true,
			errMsg:  "exactly one mode",
		},
		{
			name: "multiple modes: binary + text",
			patch: RawPatch{
				FindBase64: base64.StdEncoding.EncodeToString([]byte("old")),
				FindText:   "text",
			},
			wantErr: true,
			errMsg:  "exactly one mode",
		},
		{
			name:    "offset without data_base64",
			patch:   RawPatch{Offset: &offset5},
			wantErr: true,
			errMsg:  "data_base64 is required",
		},
		{
			name:    "data_base64 without offset",
			patch:   RawPatch{DataBase64: base64.StdEncoding.EncodeToString([]byte("data"))},
			wantErr: true,
			errMsg:  "offset is required",
		},
		{
			name:    "negative offset",
			patch:   RawPatch{Offset: &offsetNeg, DataBase64: base64.StdEncoding.EncodeToString([]byte("data"))},
			wantErr: true,
			errMsg:  "offset must be >= 0",
		},
		{
			name:    "replace_base64 without find_base64",
			patch:   RawPatch{ReplaceBase64: base64.StdEncoding.EncodeToString([]byte("new"))},
			wantErr: true,
			errMsg:  "find_base64 is required",
		},
		{
			name:    "replace_text without find_text",
			patch:   RawPatch{ReplaceText: "new"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRawPatch(tt.patch)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRawPatch() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" {
				if got := err.Error(); !contains(got, tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", got, tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestApplyRawPatches_OffsetPatch(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		offset  int
		b64Data string
		want    []byte
		wantErr bool
	}{
		{
			name:    "overwrite at beginning",
			data:    []byte("Hello, World!"),
			offset:  0,
			b64Data: base64.StdEncoding.EncodeToString([]byte("XXXXX")),
			want:    []byte("XXXXX, World!"),
		},
		{
			name:    "overwrite in middle",
			data:    []byte("Hello, World!"),
			offset:  7,
			b64Data: base64.StdEncoding.EncodeToString([]byte("Earth")),
			want:    []byte("Hello, Earth!"),
		},
		{
			name:    "overwrite extending beyond data",
			data:    []byte("Hello"),
			offset:  3,
			b64Data: base64.StdEncoding.EncodeToString([]byte("LOOONG")),
			want:    []byte("HelLOOONG"),
		},
		{
			name:    "overwrite at exact end",
			data:    []byte("Hello"),
			offset:  5,
			b64Data: base64.StdEncoding.EncodeToString([]byte("!")),
			want:    []byte("Hello!"),
		},
		{
			name:    "offset beyond data length",
			data:    []byte("Hello"),
			offset:  10,
			b64Data: base64.StdEncoding.EncodeToString([]byte("!")),
			wantErr: true,
		},
		{
			name:    "invalid base64",
			data:    []byte("Hello"),
			offset:  0,
			b64Data: "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "empty base64 data",
			data:    []byte("Hello"),
			offset:  0,
			b64Data: "",
			wantErr: true, // empty data_base64 caught by validateRawPatch
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := tt.offset
			patch := RawPatch{Offset: &offset, DataBase64: tt.b64Data}

			// Skip empty data_base64 test (handled by validateRawPatch)
			if tt.b64Data == "" {
				return
			}

			got, err := applyRawPatches(tt.data, []RawPatch{patch})
			if (err != nil) != tt.wantErr {
				t.Errorf("applyRawPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && string(got) != string(tt.want) {
				t.Errorf("applyRawPatches() = %q, want %q", string(got), string(tt.want))
			}
		})
	}
}

func TestApplyRawPatches_BinaryFindReplace(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		find    []byte
		replace []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "simple binary replace",
			data:    []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			find:    []byte{0x01, 0x02},
			replace: []byte{0xAA, 0xBB},
			want:    []byte{0x00, 0xAA, 0xBB, 0x03, 0x04},
		},
		{
			name:    "binary replace with different size (shorter)",
			data:    []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			find:    []byte{0x01, 0x02, 0x03},
			replace: []byte{0xFF},
			want:    []byte{0x00, 0xFF, 0x04},
		},
		{
			name:    "binary replace with different size (longer)",
			data:    []byte{0x00, 0x01, 0x02},
			find:    []byte{0x01},
			replace: []byte{0xAA, 0xBB, 0xCC},
			want:    []byte{0x00, 0xAA, 0xBB, 0xCC, 0x02},
		},
		{
			name:    "binary delete (empty replace)",
			data:    []byte{0x00, 0x01, 0x02, 0x03},
			find:    []byte{0x01, 0x02},
			replace: nil,
			want:    []byte{0x00, 0x03},
		},
		{
			name:    "multiple occurrences replaced",
			data:    []byte("aXbXc"),
			find:    []byte("X"),
			replace: []byte("YY"),
			want:    []byte("aYYbYYc"),
		},
		{
			name:    "pattern not found (no change)",
			data:    []byte{0x00, 0x01, 0x02},
			find:    []byte{0xFF},
			replace: []byte{0xAA},
			want:    []byte{0x00, 0x01, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findB64 := base64.StdEncoding.EncodeToString(tt.find)
			var replaceB64 string
			if tt.replace != nil {
				replaceB64 = base64.StdEncoding.EncodeToString(tt.replace)
			}
			patch := RawPatch{FindBase64: findB64, ReplaceBase64: replaceB64}
			got, err := applyRawPatches(tt.data, []RawPatch{patch})
			if (err != nil) != tt.wantErr {
				t.Errorf("applyRawPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && string(got) != string(tt.want) {
				t.Errorf("applyRawPatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyRawPatches_TextFindReplace(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		find    string
		replace string
		want    []byte
	}{
		{
			name:    "simple text replace",
			data:    []byte("Hello, World!"),
			find:    "World",
			replace: "Earth",
			want:    []byte("Hello, Earth!"),
		},
		{
			name:    "text delete (empty replace)",
			data:    []byte("Hello, World!"),
			find:    ", World",
			replace: "",
			want:    []byte("Hello!"),
		},
		{
			name:    "multiple text occurrences",
			data:    []byte("foo bar foo baz foo"),
			find:    "foo",
			replace: "qux",
			want:    []byte("qux bar qux baz qux"),
		},
		{
			name:    "pattern not found (no change)",
			data:    []byte("Hello"),
			find:    "xyz",
			replace: "abc",
			want:    []byte("Hello"),
		},
		{
			name:    "HTTP header value replacement",
			data:    []byte("GET /api HTTP/1.1\r\nHost: old.example.com\r\nAuthorization: Bearer old-token\r\n\r\n"),
			find:    "old-token",
			replace: "new-token",
			want:    []byte("GET /api HTTP/1.1\r\nHost: old.example.com\r\nAuthorization: Bearer new-token\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := RawPatch{FindText: tt.find, ReplaceText: tt.replace}
			got, err := applyRawPatches(tt.data, []RawPatch{patch})
			if err != nil {
				t.Fatalf("applyRawPatches() error = %v", err)
			}
			if string(got) != string(tt.want) {
				t.Errorf("applyRawPatches() = %q, want %q", string(got), string(tt.want))
			}
		})
	}
}

func TestApplyRawPatches_MultiplePatches(t *testing.T) {
	data := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n")
	offset := 4

	patches := []RawPatch{
		// 1. Change path via offset: "/api" starts at offset 4
		{Offset: &offset, DataBase64: base64.StdEncoding.EncodeToString([]byte("/new"))},
		// 2. Text find/replace the host
		{FindText: "example.com", ReplaceText: "target.com"},
		// 3. Text find/replace the cookie
		{FindText: "session=abc123", ReplaceText: "session=xyz789"},
	}

	got, err := applyRawPatches(data, patches)
	if err != nil {
		t.Fatalf("applyRawPatches() error = %v", err)
	}

	want := "GET /new HTTP/1.1\r\nHost: target.com\r\nCookie: session=xyz789\r\n\r\n"
	if string(got) != want {
		t.Errorf("applyRawPatches() = %q, want %q", string(got), want)
	}
}

func TestApplyRawPatches_InvalidBase64(t *testing.T) {
	t.Run("invalid find_base64", func(t *testing.T) {
		patch := RawPatch{FindBase64: "not-valid!!!"}
		_, err := applyRawPatches([]byte("data"), []RawPatch{patch})
		if err == nil {
			t.Error("expected error for invalid find_base64")
		}
	})

	t.Run("invalid replace_base64", func(t *testing.T) {
		patch := RawPatch{
			FindBase64:    base64.StdEncoding.EncodeToString([]byte("find")),
			ReplaceBase64: "not-valid!!!",
		}
		_, err := applyRawPatches([]byte("data"), []RawPatch{patch})
		if err == nil {
			t.Error("expected error for invalid replace_base64")
		}
	})

	t.Run("invalid data_base64", func(t *testing.T) {
		offset := 0
		patch := RawPatch{Offset: &offset, DataBase64: "not-valid!!!"}
		_, err := applyRawPatches([]byte("data"), []RawPatch{patch})
		if err == nil {
			t.Error("expected error for invalid data_base64")
		}
	})
}

func TestApplyRawPatches_EmptyFindBase64(t *testing.T) {
	// find_base64 that decodes to empty bytes should fail
	patch := RawPatch{FindBase64: base64.StdEncoding.EncodeToString([]byte{})}
	_, err := applyRawPatches([]byte("data"), []RawPatch{patch})
	if err == nil {
		t.Error("expected error for empty find_base64 decoded value")
	}
}

func TestApplyRawPatches_DoesNotMutateOriginal(t *testing.T) {
	original := []byte("Hello, World!")
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)

	offset := 0
	patches := []RawPatch{
		{Offset: &offset, DataBase64: base64.StdEncoding.EncodeToString([]byte("XXXXX"))},
	}

	_, err := applyRawPatches(original, patches)
	if err != nil {
		t.Fatalf("applyRawPatches() error = %v", err)
	}

	// Original slice should be unchanged.
	if string(original) != string(originalCopy) {
		t.Errorf("original data was mutated: got %q, want %q", string(original), string(originalCopy))
	}
}

func TestBuildResendRawBytes(t *testing.T) {
	originalRaw := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	t.Run("no mutations returns original", func(t *testing.T) {
		got, count, err := buildResendRawBytes(originalRaw, resendParams{})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if count != 0 {
			t.Errorf("patch count = %d, want 0", count)
		}
		if string(got) != string(originalRaw) {
			t.Errorf("got %q, want %q", string(got), string(originalRaw))
		}
	})

	t.Run("override_raw_base64 replaces entirely", func(t *testing.T) {
		replacement := []byte("POST /new HTTP/1.1\r\nHost: new.com\r\n\r\n")
		b64 := base64.StdEncoding.EncodeToString(replacement)
		got, count, err := buildResendRawBytes(originalRaw, resendParams{OverrideRawBase64: b64})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if count != 0 {
			t.Errorf("patch count = %d, want 0", count)
		}
		if string(got) != string(replacement) {
			t.Errorf("got %q, want %q", string(got), string(replacement))
		}
	})

	t.Run("override_raw_base64 takes priority over patches", func(t *testing.T) {
		replacement := []byte("REPLACED")
		b64 := base64.StdEncoding.EncodeToString(replacement)
		got, count, err := buildResendRawBytes(originalRaw, resendParams{
			OverrideRawBase64: b64,
			Patches:           []RawPatch{{FindText: "example.com", ReplaceText: "target.com"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if count != 0 {
			t.Errorf("patch count = %d, want 0", count)
		}
		if string(got) != "REPLACED" {
			t.Errorf("got %q, want REPLACED", string(got))
		}
	})

	t.Run("patches applied to original", func(t *testing.T) {
		got, count, err := buildResendRawBytes(originalRaw, resendParams{
			Patches: []RawPatch{{FindText: "example.com", ReplaceText: "target.com"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if count != 1 {
			t.Errorf("patch count = %d, want 1", count)
		}
		want := "GET /test HTTP/1.1\r\nHost: target.com\r\n\r\n"
		if string(got) != want {
			t.Errorf("got %q, want %q", string(got), want)
		}
	})

	t.Run("invalid override_raw_base64", func(t *testing.T) {
		_, _, err := buildResendRawBytes(originalRaw, resendParams{OverrideRawBase64: "not-valid!!!"})
		if err == nil {
			t.Error("expected error for invalid override_raw_base64")
		}
	})

	t.Run("empty override_raw_base64 treated as not set", func(t *testing.T) {
		// base64("") == "", which is treated as "field not set" -> returns original bytes
		b64 := base64.StdEncoding.EncodeToString([]byte{})
		got, count, err := buildResendRawBytes(originalRaw, resendParams{OverrideRawBase64: b64})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if count != 0 {
			t.Errorf("patch count = %d, want 0", count)
		}
		if string(got) != string(originalRaw) {
			t.Errorf("got %q, want %q", string(got), string(originalRaw))
		}
	})
}
