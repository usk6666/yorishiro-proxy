package macro

import "testing"

func TestIsReservedKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"__iteration", true},
		{"__nonce", true},
		{"__", true},
		{"_iteration", false},
		{"iteration", false},
		{"", false},
		{"foo__bar", false},
	}
	for _, c := range cases {
		if got := IsReservedKey(c.key); got != c.want {
			t.Errorf("IsReservedKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}
