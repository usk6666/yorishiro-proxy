package httputil

import (
	gohttp "net/http"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

func TestHTTPHeaderToRawHeaders_NilInput(t *testing.T) {
	got := HTTPHeaderToRawHeaders(nil)
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestHTTPHeaderToRawHeaders_EmptyInput(t *testing.T) {
	got := HTTPHeaderToRawHeaders(gohttp.Header{})
	if got != nil {
		t.Fatalf("expected nil for empty header, got %v", got)
	}
}

func TestHTTPHeaderToRawHeaders_MultiValue(t *testing.T) {
	h := gohttp.Header{
		"Accept": {"text/html", "application/json"},
	}
	got := HTTPHeaderToRawHeaders(h)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	values := map[string]bool{}
	for _, rh := range got {
		if rh.Name != "Accept" {
			t.Errorf("expected name Accept, got %q", rh.Name)
		}
		values[rh.Value] = true
	}
	if !values["text/html"] || !values["application/json"] {
		t.Errorf("expected both values present, got %v", got)
	}
}

func TestHTTPHeaderToRawHeaders_CasingPreserved(t *testing.T) {
	h := gohttp.Header{
		"Content-Type": {"text/plain"},
		"X-Custom":     {"val"},
	}
	got := HTTPHeaderToRawHeaders(h)
	names := map[string]bool{}
	for _, rh := range got {
		names[rh.Name] = true
	}
	if !names["Content-Type"] {
		t.Error("expected Content-Type to preserve casing")
	}
	if !names["X-Custom"] {
		t.Error("expected X-Custom to preserve casing")
	}
}

func TestRawHeadersToHTTPHeader_NilInput(t *testing.T) {
	got := RawHeadersToHTTPHeader(nil)
	if got == nil {
		t.Fatal("expected non-nil empty header map for nil RawHeaders, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(got))
	}
}

func TestRawHeadersToHTTPHeader_EmptyInput(t *testing.T) {
	got := RawHeadersToHTTPHeader(parser.RawHeaders{})
	if got == nil {
		t.Fatal("expected non-nil empty header map for empty RawHeaders")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(got))
	}
}

func TestRawHeadersToHTTPHeader_MultiValue(t *testing.T) {
	rh := parser.RawHeaders{
		{Name: "Accept", Value: "text/html"},
		{Name: "Accept", Value: "application/json"},
	}
	got := RawHeadersToHTTPHeader(rh)
	vals := got.Values("Accept")
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}
}

func TestRawHeadersToHTTPHeader_Normalization(t *testing.T) {
	// net/http.Header.Add canonicalizes the key, so "content-type" becomes "Content-Type".
	rh := parser.RawHeaders{
		{Name: "content-type", Value: "text/plain"},
	}
	got := RawHeadersToHTTPHeader(rh)
	if got.Get("Content-Type") != "text/plain" {
		t.Errorf("expected canonical lookup to work, got %q", got.Get("Content-Type"))
	}
}

func TestRoundTrip_HTTPHeader_RawHeaders_HTTPHeader(t *testing.T) {
	original := gohttp.Header{
		"Content-Type":  {"text/html"},
		"Cache-Control": {"no-cache", "no-store"},
		"X-Custom":      {"value1"},
	}

	rh := HTTPHeaderToRawHeaders(original)
	roundTripped := RawHeadersToHTTPHeader(rh)

	for name, vals := range original {
		got := roundTripped.Values(name)
		if len(got) != len(vals) {
			t.Errorf("header %q: expected %d values, got %d", name, len(vals), len(got))
			continue
		}
		valSet := map[string]int{}
		for _, v := range vals {
			valSet[v]++
		}
		for _, v := range got {
			valSet[v]--
		}
		for v, count := range valSet {
			if count != 0 {
				t.Errorf("header %q: value %q count mismatch: %d", name, v, count)
			}
		}
	}
}

func TestRoundTrip_RawHeaders_HTTPHeader_RawHeaders(t *testing.T) {
	original := parser.RawHeaders{
		{Name: "Content-Type", Value: "text/html"},
		{Name: "Accept", Value: "text/plain"},
		{Name: "Accept", Value: "application/json"},
	}

	h := RawHeadersToHTTPHeader(original)
	roundTripped := HTTPHeaderToRawHeaders(h)

	if len(roundTripped) != len(original) {
		t.Fatalf("expected %d entries, got %d", len(original), len(roundTripped))
	}

	// Build frequency maps to compare content (order may differ due to map iteration).
	freq := map[string]int{}
	for _, rh := range original {
		freq[rh.Name+"\x00"+rh.Value]++
	}
	for _, rh := range roundTripped {
		freq[rh.Name+"\x00"+rh.Value]--
	}
	for key, count := range freq {
		if count != 0 {
			t.Errorf("mismatch for %q: %d", key, count)
		}
	}
}

func TestHTTPHeaderToRawHeaders_OrderConsistency(t *testing.T) {
	// Verify that each call produces the same set of entries (content, not order).
	h := gohttp.Header{
		"A": {"1"},
		"B": {"2"},
		"C": {"3"},
	}
	first := HTTPHeaderToRawHeaders(h)
	second := HTTPHeaderToRawHeaders(h)

	if len(first) != len(second) {
		t.Fatalf("length mismatch: %d vs %d", len(first), len(second))
	}

	freq := map[string]int{}
	for _, rh := range first {
		freq[rh.Name+"\x00"+rh.Value]++
	}
	for _, rh := range second {
		freq[rh.Name+"\x00"+rh.Value]--
	}
	for key, count := range freq {
		if count != 0 {
			t.Errorf("inconsistency for %q: %d", key, count)
		}
	}
}
