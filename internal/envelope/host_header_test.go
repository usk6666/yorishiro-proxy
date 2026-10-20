package envelope

import (
	"reflect"
	"testing"
)

func TestHostHeaderValues(t *testing.T) {
	tests := []struct {
		name    string
		headers []KeyValue
		want    []string
	}{
		{"none", []KeyValue{{Name: "Accept", Value: "*/*"}}, nil},
		{"single", []KeyValue{{Name: "Host", Value: "a.example"}}, []string{"a.example"}},
		{
			"every casing, wire order, duplicates kept",
			[]KeyValue{
				{Name: "Host", Value: "a.example"},
				{Name: "X-Host", Value: "ignored"},
				{Name: "host", Value: "b.example"},
				{Name: "HOST", Value: "a.example"},
			},
			[]string{"a.example", "b.example", "a.example"},
		},
		{"OWS trimmed", []KeyValue{{Name: "Host", Value: " \tb.example:80 \t"}}, []string{"b.example:80"}},
		{"comma not split", []KeyValue{{Name: "Host", Value: "a.example, b.example"}}, []string{"a.example, b.example"}},
		{"empty value kept", []KeyValue{{Name: "Host", Value: ""}}, []string{""}},
		{
			"trailing SP / HTAB before the colon still names Host",
			[]KeyValue{{Name: "Host ", Value: "a"}, {Name: "host\t", Value: "b"}, {Name: "Host \t ", Value: "c"}},
			[]string{"a", "b", "c"},
		},
		{"leading whitespace is not trimmed from the name", []KeyValue{{Name: " Host", Value: "a"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := append([]KeyValue(nil), tt.headers...)
			got := HostHeaderValues(tt.headers)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HostHeaderValues = %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(before, tt.headers) {
				t.Errorf("headers mutated: %v -> %v", before, tt.headers)
			}
		})
	}
}
