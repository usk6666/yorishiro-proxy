package envelope

import "testing"

func TestTLSHandshakeMessage_Protocol(t *testing.T) {
	m := &TLSHandshakeMessage{}
	if got := m.Protocol(); got != ProtocolTLSHandshake {
		t.Errorf("Protocol() = %q, want %q", got, ProtocolTLSHandshake)
	}
}

func TestTLSHandshakeMessage_CloneMessage(t *testing.T) {
	original := &TLSHandshakeMessage{
		SNI:                   "example.com",
		LocalAddr:             "127.0.0.1:8080",
		RemoteAddr:            "192.0.2.5:54321",
		UpstreamAddr:          "93.184.216.34:443",
		BytesClientToUpstream: 1024,
		BytesUpstreamToClient: 4096,
		Outcome:               TLSHandshakeOutcomeTunneled,
		ErrorReason:           "",
	}

	cloneMsg := original.CloneMessage()
	if cloneMsg == nil {
		t.Fatal("CloneMessage returned nil")
	}
	clone, ok := cloneMsg.(*TLSHandshakeMessage)
	if !ok {
		t.Fatalf("CloneMessage returned %T, want *TLSHandshakeMessage", cloneMsg)
	}
	if clone == original {
		t.Error("CloneMessage returned identity pointer; expected a deep copy")
	}
	if *clone != *original {
		t.Errorf("CloneMessage values differ:\n got:  %+v\nwant: %+v", *clone, *original)
	}

	// Mutating the clone must not affect the original.
	clone.SNI = "other.example"
	clone.BytesClientToUpstream = 999
	if original.SNI == clone.SNI {
		t.Errorf("clone share fields with original after mutation: %+v", original)
	}
	if original.BytesClientToUpstream == clone.BytesClientToUpstream {
		t.Errorf("clone share fields with original after mutation: %+v", original)
	}
}

func TestTLSHandshakeMessage_CloneMessage_Nil(t *testing.T) {
	var m *TLSHandshakeMessage
	if got := m.CloneMessage(); got != nil {
		t.Errorf("nil receiver CloneMessage = %v, want nil", got)
	}
}

func TestTLSHandshakeOutcomeConstants(t *testing.T) {
	if TLSHandshakeOutcomeTunneled != "tunneled" {
		t.Errorf("TLSHandshakeOutcomeTunneled = %q, want %q", TLSHandshakeOutcomeTunneled, "tunneled")
	}
	if TLSHandshakeOutcomeFailed != "failed" {
		t.Errorf("TLSHandshakeOutcomeFailed = %q, want %q", TLSHandshakeOutcomeFailed, "failed")
	}
}
