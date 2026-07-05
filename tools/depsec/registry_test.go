package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGoModuleEscape(t *testing.T) {
	cases := map[string]string{
		"github.com/foo/bar":         "github.com/foo/bar",
		"github.com/Azure/azure-sdk": "github.com/!azure/azure-sdk",
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"golang.org/x/net":           "golang.org/x/net",
	}
	for in, want := range cases {
		if got := goModuleEscape(in); got != want {
			t.Errorf("goModuleEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHTTPClock_Go(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/github.com/!burnt!sushi/toml/@v/v1.4.0.info" {
			t.Errorf("unexpected go proxy path %q", r.URL.Path)
		}
		w.Write([]byte(`{"Version":"v1.4.0","Time":"2026-05-10T08:00:00Z"}`))
	}))
	defer srv.Close()

	c := &httpClock{hc: srv.Client(), goBase: srv.URL}
	got, err := c.releasedAt(context.Background(), "go", "github.com/BurntSushi/toml", "v1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestHTTPClock_NpmUnsupported(t *testing.T) {
	c := &httpClock{hc: http.DefaultClient, goBase: "http://unused"}
	if _, err := c.releasedAt(context.Background(), "npm", "left-pad", "1.0.0"); err == nil {
		t.Error("npm lookup should be unsupported (gated by pnpm/.npmrc)")
	}
}

func TestHTTPClock_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c := &httpClock{hc: srv.Client(), goBase: srv.URL}
	if _, err := c.releasedAt(context.Background(), "go", "m", "v1.0.0"); err == nil {
		t.Error("expected error on 404")
	}
}
