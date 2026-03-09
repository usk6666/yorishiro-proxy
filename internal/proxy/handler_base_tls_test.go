package proxy

import (
	"testing"
)

func TestHandlerBase_TLSFingerprint_Default(t *testing.T) {
	b := &HandlerBase{}
	if got := b.TLSFingerprint(); got != "" {
		t.Errorf("TLSFingerprint() = %q, want empty string (default)", got)
	}
}

func TestHandlerBase_SetTLSFingerprint(t *testing.T) {
	profiles := []string{"chrome", "firefox", "safari", "edge", "random", "none"}
	b := &HandlerBase{}

	for _, p := range profiles {
		b.SetTLSFingerprint(p)
		if got := b.TLSFingerprint(); got != p {
			t.Errorf("TLSFingerprint() = %q after Set(%q), want %q", got, p, p)
		}
	}
}

func TestHandlerBase_SetTLSFingerprint_Overwrite(t *testing.T) {
	b := &HandlerBase{}
	b.SetTLSFingerprint("chrome")
	b.SetTLSFingerprint("firefox")
	if got := b.TLSFingerprint(); got != "firefox" {
		t.Errorf("TLSFingerprint() = %q, want firefox", got)
	}
}
