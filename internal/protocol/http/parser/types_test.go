package parser

import (
	"testing"
)

func TestRawHeaders_Get(t *testing.T) {
	tests := []struct {
		name    string
		headers RawHeaders
		key     string
		want    string
	}{
		{
			name:    "exact match",
			headers: RawHeaders{{Name: "Content-Type", Value: "text/html"}},
			key:     "Content-Type",
			want:    "text/html",
		},
		{
			name:    "case insensitive",
			headers: RawHeaders{{Name: "Content-Type", Value: "text/html"}},
			key:     "content-type",
			want:    "text/html",
		},
		{
			name:    "not found",
			headers: RawHeaders{{Name: "Content-Type", Value: "text/html"}},
			key:     "Accept",
			want:    "",
		},
		{
			name:    "returns first match",
			headers: RawHeaders{{Name: "X-Foo", Value: "first"}, {Name: "X-Foo", Value: "second"}},
			key:     "X-Foo",
			want:    "first",
		},
		{
			name:    "nil headers",
			headers: nil,
			key:     "X-Foo",
			want:    "",
		},
		{
			name:    "empty headers",
			headers: RawHeaders{},
			key:     "X-Foo",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.headers.Get(tt.key)
			if got != tt.want {
				t.Errorf("Get(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestRawHeaders_Values(t *testing.T) {
	headers := RawHeaders{
		{Name: "Set-Cookie", Value: "a=1"},
		{Name: "Content-Type", Value: "text/html"},
		{Name: "set-cookie", Value: "b=2"},
	}

	vals := headers.Values("Set-Cookie")
	if len(vals) != 2 {
		t.Fatalf("Values() returned %d values, want 2", len(vals))
	}
	if vals[0] != "a=1" || vals[1] != "b=2" {
		t.Errorf("Values() = %v, want [a=1 b=2]", vals)
	}

	empty := headers.Values("X-Missing")
	if len(empty) != 0 {
		t.Errorf("Values() for missing header = %v, want nil", empty)
	}
}

func TestRawHeaders_Set(t *testing.T) {
	t.Run("update existing", func(t *testing.T) {
		h := RawHeaders{{Name: "Content-Type", Value: "text/html"}}
		h.Set("content-type", "application/json")
		if h[0].Value != "application/json" {
			t.Errorf("Set() did not update value: got %q", h[0].Value)
		}
		// Original case should be preserved.
		if h[0].Name != "Content-Type" {
			t.Errorf("Set() changed name case: got %q", h[0].Name)
		}
	})

	t.Run("append new", func(t *testing.T) {
		h := RawHeaders{{Name: "Content-Type", Value: "text/html"}}
		h.Set("X-Custom", "value")
		if len(h) != 2 {
			t.Fatalf("Set() did not append: len=%d", len(h))
		}
		if h[1].Name != "X-Custom" || h[1].Value != "value" {
			t.Errorf("Set() appended incorrect header: %+v", h[1])
		}
	})
}

func TestRawHeaders_Del(t *testing.T) {
	t.Run("delete existing", func(t *testing.T) {
		h := RawHeaders{
			{Name: "Content-Type", Value: "text/html"},
			{Name: "X-Foo", Value: "bar"},
			{Name: "x-foo", Value: "baz"},
		}
		h.Del("X-Foo")
		if len(h) != 1 {
			t.Fatalf("Del() len=%d, want 1", len(h))
		}
		if h[0].Name != "Content-Type" {
			t.Errorf("Del() removed wrong header: %+v", h[0])
		}
	})

	t.Run("delete nonexistent", func(t *testing.T) {
		h := RawHeaders{{Name: "Content-Type", Value: "text/html"}}
		h.Del("X-Missing")
		if len(h) != 1 {
			t.Errorf("Del() changed len for missing header: %d", len(h))
		}
	})
}

func TestRawHeaders_Clone(t *testing.T) {
	t.Run("deep copy", func(t *testing.T) {
		orig := RawHeaders{
			{Name: "Content-Type", Value: "text/html"},
			{Name: "X-Foo", Value: "bar"},
		}
		clone := orig.Clone()
		clone[0].Value = "modified"

		if orig[0].Value != "text/html" {
			t.Error("Clone() did not create a deep copy")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		var h RawHeaders
		clone := h.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})
}
