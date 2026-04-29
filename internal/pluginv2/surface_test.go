package pluginv2

import "testing"

// expectedEntries is the RFC §9.3 17-entry surface, encoded so that any
// drift between surface.go and the spec fails this test loudly.
var expectedEntries = []struct {
	Protocol string
	Event    string
	Phases   PhaseSupport
	Actions  ActionMask
}{
	{ProtoHTTP, EventOnRequest, PhaseSupportPrePost, ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
	{ProtoHTTP, EventOnResponse, PhaseSupportPrePost, ActionMaskContinue | ActionMaskRespond},

	{ProtoWS, EventOnUpgrade, PhaseSupportPrePost, ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
	{ProtoWS, EventOnMessage, PhaseSupportPrePost, ActionMaskContinue},
	{ProtoWS, EventOnClose, PhaseSupportNone, ActionMaskContinue},

	{ProtoGRPC, EventOnStart, PhaseSupportPrePost, ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
	{ProtoGRPC, EventOnData, PhaseSupportPrePost, ActionMaskContinue},
	{ProtoGRPC, EventOnEnd, PhaseSupportNone, ActionMaskContinue},

	{ProtoGRPCWeb, EventOnStart, PhaseSupportPrePost, ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
	{ProtoGRPCWeb, EventOnData, PhaseSupportPrePost, ActionMaskContinue},
	{ProtoGRPCWeb, EventOnEnd, PhaseSupportNone, ActionMaskContinue},

	{ProtoSSE, EventOnEvent, PhaseSupportPrePost, ActionMaskContinue},
	{ProtoRaw, EventOnChunk, PhaseSupportPrePost, ActionMaskContinue},

	{ProtoTLS, EventOnHandshake, PhaseSupportNone, ActionMaskContinue},
	{ProtoConnection, EventOnConnect, PhaseSupportNone, ActionMaskContinue | ActionMaskDrop},
	{ProtoConnection, EventOnDisconnect, PhaseSupportNone, ActionMaskContinue},
	{ProtoSOCKS5, EventOnConnect, PhaseSupportNone, ActionMaskContinue | ActionMaskDrop},
}

func TestSurface_AllSeventeenEntriesPresent(t *testing.T) {
	if got := len(expectedEntries); got != 17 {
		t.Fatalf("expectedEntries length = %d, want 17", got)
	}
	if got := len(SurfaceEntries()); got != 17 {
		t.Errorf("SurfaceEntries length = %d, want 17", got)
	}
	for _, want := range expectedEntries {
		spec, ok := LookupEntry(want.Protocol, want.Event)
		if !ok {
			t.Errorf("(%q, %q) missing from surface", want.Protocol, want.Event)
			continue
		}
		if spec.Phases != want.Phases {
			t.Errorf("(%q, %q) phase support = %d, want %d", want.Protocol, want.Event, spec.Phases, want.Phases)
		}
		if spec.Actions != want.Actions {
			t.Errorf("(%q, %q) action mask = %b, want %b", want.Protocol, want.Event, spec.Actions, want.Actions)
		}
	}
}

func TestSurface_LookupUnknownProtocolReturnsFalse(t *testing.T) {
	if _, ok := LookupEntry("htttp", EventOnRequest); ok {
		t.Error("typo protocol should not match")
	}
}

func TestSurface_LookupUnknownEventReturnsFalse(t *testing.T) {
	if _, ok := LookupEntry(ProtoHTTP, "on_chunk"); ok {
		t.Error("event from another protocol should not match")
	}
}

func TestSurface_LifecycleEntriesAcceptOnlyContinueOrDrop(t *testing.T) {
	for _, e := range expectedEntries {
		if e.Phases != PhaseSupportNone {
			continue
		}
		if !e.Actions.Has(ActionContinue) {
			t.Errorf("(%q, %q) lifecycle entry must allow CONTINUE", e.Protocol, e.Event)
		}
		if e.Actions.Has(ActionRespond) {
			t.Errorf("(%q, %q) lifecycle entry must not allow RESPOND", e.Protocol, e.Event)
		}
	}
}

func TestSurface_TransactionStartEntriesPermitDrop(t *testing.T) {
	starts := map[string]map[string]bool{
		ProtoHTTP:       {EventOnRequest: true},
		ProtoWS:         {EventOnUpgrade: true},
		ProtoGRPC:       {EventOnStart: true},
		ProtoGRPCWeb:    {EventOnStart: true},
		ProtoConnection: {EventOnConnect: true},
		ProtoSOCKS5:     {EventOnConnect: true},
	}
	for proto, evs := range starts {
		for ev := range evs {
			spec, ok := LookupEntry(proto, ev)
			if !ok {
				t.Fatalf("(%q, %q) missing from surface", proto, ev)
			}
			if !spec.Actions.Has(ActionDrop) {
				t.Errorf("(%q, %q) transaction-start should allow DROP", proto, ev)
			}
		}
	}
}

func TestSurface_HTTPOnResponseDoesNotAllowDrop(t *testing.T) {
	spec, ok := LookupEntry(ProtoHTTP, EventOnResponse)
	if !ok {
		t.Fatal("(http, on_response) missing")
	}
	if spec.Actions.Has(ActionDrop) {
		t.Error("(http, on_response) must not allow DROP — would hang client")
	}
	if !spec.Actions.Has(ActionRespond) {
		t.Error("(http, on_response) must allow RESPOND-replace")
	}
}
