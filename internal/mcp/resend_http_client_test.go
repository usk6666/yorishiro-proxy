package mcp

import (
	"net/http"
	"testing"
)

func TestResendHTTPClient_ForceAttemptHTTP2(t *testing.T) {
	s := &Server{deps: &deps{}}

	doer := s.resendHTTPClient(resendParams{})
	client, ok := doer.(*http.Client)
	if !ok {
		t.Fatalf("expected *http.Client, got %T", doer)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must be true to support HTTP/2 over TLS resend")
	}
}

func TestResendHTTPClient_ReplayDoerOverride(t *testing.T) {
	mock := &mockHTTPDoer{}
	s := &Server{deps: &deps{replayDoer: mock}}

	doer := s.resendHTTPClient(resendParams{})
	if doer != mock {
		t.Error("expected replayDoer to be returned when set")
	}
}

type mockHTTPDoer struct{}

func (m *mockHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	return nil, nil
}
