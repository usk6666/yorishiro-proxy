package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchAlerts(t *testing.T) {
	page1 := `[
      {"number":1,"state":"open","html_url":"https://gh/adv/1",
       "dependency":{"package":{"ecosystem":"Go","name":"github.com/foo/bar"},"manifest_path":"go.mod"},
       "security_vulnerability":{"severity":"high","first_patched_version":{"identifier":"v1.2.3"}},
       "security_advisory":{"ghsa_id":"GHSA-aaaa","cve_id":"CVE-1"}},
      {"number":2,"state":"dismissed",
       "dependency":{"package":{"ecosystem":"npm","name":"left-pad"}},
       "security_vulnerability":{"severity":"low","first_patched_version":{"identifier":"1.3.0"}},
       "security_advisory":{"ghsa_id":"GHSA-bbbb"}}
    ]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tkn" {
			t.Errorf("auth header = %q", got)
		}
		if got := r.URL.Query().Get("state"); got != "open" {
			t.Errorf("state filter = %q", got)
		}
		w.Write([]byte(page1))
	}))
	defer srv.Close()

	alerts, err := fetchAlerts(context.Background(), srv.URL, "o", "r", "tkn")
	if err != nil {
		t.Fatal(err)
	}
	// Dismissed alert is dropped; ecosystem is lowercased.
	if len(alerts) != 1 {
		t.Fatalf("want 1 open alert, got %d: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Ecosystem != "go" || a.Name != "github.com/foo/bar" || a.FirstPatched != "v1.2.3" || a.GHSA != "GHSA-aaaa" {
		t.Errorf("alert mapping wrong: %+v", a)
	}
}

func TestFetchAlerts_CursorPagination(t *testing.T) {
	// The Dependabot API paginates by cursor (Link header), never ?page=N.
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "" {
			t.Errorf("must not use ?page= pagination; got %q", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("after") {
		case "":
			// First page advertises a next cursor.
			w.Header().Set("Link", `<`+srvURL+`/repos/o/r/dependabot/alerts?state=open&per_page=100&after=CUR>; rel="next"`)
			w.Write([]byte(`[{"number":1,"state":"open","dependency":{"package":{"ecosystem":"go","name":"m1"}},"security_vulnerability":{"first_patched_version":{"identifier":"v1"}}}]`))
		case "CUR":
			// Last page: no Link header.
			w.Write([]byte(`[{"number":2,"state":"open","dependency":{"package":{"ecosystem":"npm","name":"m2"}},"security_vulnerability":{"first_patched_version":{"identifier":"2.0.0"}}}]`))
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("after"))
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	alerts, err := fetchAlerts(context.Background(), srv.URL, "o", "r", "tkn")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("want 2 alerts across 2 pages, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Name != "m1" || alerts[1].Name != "m2" {
		t.Errorf("pagination aggregation wrong: %+v", alerts)
	}
}

func TestParseNextLink(t *testing.T) {
	cases := map[string]string{
		``: "",
		`<https://api.github.com/x?after=A>; rel="next"`:                                                  "https://api.github.com/x?after=A",
		`<https://api.github.com/x?before=B>; rel="prev", <https://api.github.com/x?after=A>; rel="next"`: "https://api.github.com/x?after=A",
		`<https://api.github.com/x?before=B>; rel="prev"`:                                                 "",
	}
	for in, want := range cases {
		if got := parseNextLink(in); got != want {
			t.Errorf("parseNextLink(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFetchAlerts_ForbiddenIsExplicit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Resource not accessible"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := fetchAlerts(context.Background(), srv.URL, "o", "r", "tkn")
	if err == nil {
		t.Fatal("want error on 403")
	}
	if !strings.Contains(err.Error(), "Dependabot alerts: read") {
		t.Errorf("403 error should hint at the missing permission, got: %v", err)
	}
}

func TestLoadNpmDirect(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "package.json")
	os.WriteFile(p, []byte(`{"dependencies":{"react":"^18"},"devDependencies":{"vite":"^5"}}`), 0o644)

	set, err := loadNpmDirect(p)
	if err != nil {
		t.Fatal(err)
	}
	if !set["react"] || !set["vite"] {
		t.Errorf("direct set missing entries: %v", set)
	}
	if set["left-pad"] {
		t.Errorf("unexpected transitive entry classified as direct")
	}
}
