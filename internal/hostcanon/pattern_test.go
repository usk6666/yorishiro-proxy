package hostcanon

import "testing"

func TestDialEquivalentPatternKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"LocalHost.", "localhost"},
		{"[::1]", "::1"},
		{"0:0::1", "::1"},
		{"::ffff:10.0.0.5", "10.0.0.5"},
		{"*.Example.COM.", "*.example.com"},
		{"*.", "*."},
		{"127.1", "127.1"},
		{"0X7F.0.0.1", "0x7f.0.0.1"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := DialEquivalentPatternKey(tt.in); got != tt.want {
			t.Errorf("DialEquivalentPatternKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDialEquivalentLookupKeys(t *testing.T) {
	tests := []struct{ in, exact, wildcard string }{
		{"API.Example.COM.", "api.example.com", "*.example.com"},
		{"a.b.example.com", "a.b.example.com", "*.b.example.com"},
		{"localhost.", "localhost", ""},
		{"[::ffff:127.0.0.1]", "127.0.0.1", "*.0.0.1"},
		{"::1", "::1", ""},
		{"127.0.0.1.", "127.0.0.1.", "*.0.0.1."},
		{"", "", ""},
	}
	for _, tt := range tests {
		exact, wildcard := DialEquivalentLookupKeys(tt.in)
		if exact != tt.exact || wildcard != tt.wildcard {
			t.Errorf("DialEquivalentLookupKeys(%q) = (%q, %q), want (%q, %q)", tt.in, exact, wildcard, tt.exact, tt.wildcard)
		}
	}
}
