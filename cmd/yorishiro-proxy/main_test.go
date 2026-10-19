package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

// TestRouteCommand_Branches is USK-1047 T1: every top-level argv shape the
// callers produce (setup.BuildMCPEntry's `server -stdio-mcp -log-file`,
// setup.VerifyMCPServer's bare invocation, the Usage examples' flag-first
// `-db <name>`, npm/parent/bin/cli.js pass-through) lands on the right
// subcommand with its arguments intact.
func TestRouteCommand_Branches(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantName string
		wantRest []string
	}{
		{"no args starts the server", nil, "server", nil},
		{"empty slice starts the server", []string{}, "server", []string{}},
		{"server subcommand", []string{"server", "-stdio-mcp", "-log-file", "/tmp/x.log"}, "server", []string{"-stdio-mcp", "-log-file", "/tmp/x.log"}},
		{"bare server", []string{"server"}, "server", []string{}},
		{"flag-first bool goes to the server whole", []string{"-stdio-mcp"}, "server", []string{"-stdio-mcp"}},
		{"flag-first value goes to the server whole", []string{"-db", "proj"}, "server", []string{"-db", "proj"}},
		{"flag-first help", []string{"-h"}, "server", []string{"-h"}},
		{"double-dash help", []string{"--help"}, "server", []string{"--help"}},
		{"lone dash goes to the server", []string{"-"}, "server", []string{"-"}},
		{"lone double dash goes to the server", []string{"--"}, "server", []string{"--"}},
		{"client", []string{"client", "query", "resource=flows"}, "client", []string{"query", "resource=flows"}},
		{"docs", []string{"docs", "macro"}, "docs", []string{"macro"}},
		{"install", []string{"install", "mcp"}, "install", []string{"mcp"}},
		{"upgrade", []string{"upgrade"}, "upgrade", []string{}},
		{"version", []string{"version"}, "version", []string{}},
		{"help", []string{"help"}, "help", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotRest, err := routeCommand(tt.args)
			if err != nil {
				t.Fatalf("routeCommand(%q) error = %v, want nil", tt.args, err)
			}
			if gotName != tt.wantName {
				t.Errorf("routeCommand(%q) name = %q, want %q", tt.args, gotName, tt.wantName)
			}
			if !reflect.DeepEqual(gotRest, tt.wantRest) {
				t.Errorf("routeCommand(%q) rest = %q, want %q", tt.args, gotRest, tt.wantRest)
			}
		})
	}
}

// TestRouteCommand_UnknownSubcommandIsAnError is USK-1047 T1 (error rows):
// a bare first word that is not a subcommand must not boot the server; the
// error names the word and every valid subcommand.
func TestRouteCommand_UnknownSubcommandIsAnError(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		word     string
		wantHint bool
	}{
		{"typo of server", []string{"serevr"}, "serevr", false},
		{"typo with flags after it", []string{"serevr", "-stdio-mcp"}, "serevr", false},
		{"client tool name without client", []string{"query", "resource=flows"}, "query", true},
		{"another client tool name", []string{"resend_http"}, "resend_http", true},
		{"empty string", []string{""}, "", false},
		{"capitalised subcommand", []string{"Server"}, "Server", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, rest, err := routeCommand(tt.args)
			if err == nil {
				t.Fatalf("routeCommand(%q) = (%q, %q, nil), want an unknown-subcommand error", tt.args, name, rest)
			}
			msg := err.Error()
			if want := `unknown subcommand "` + tt.word + `"`; !strings.Contains(msg, want) {
				t.Errorf("error %q does not contain %q", msg, want)
			}
			routeAssertListsSubcommands(t, msg)
			hint := "did you mean 'yorishiro-proxy client " + tt.word + "'"
			if got := strings.Contains(msg, hint); got != tt.wantHint {
				t.Errorf("error %q: contains client hint = %v, want %v", msg, got, tt.wantHint)
			}
		})
	}
}

// TestRouteCommand_HelpTakesNoArguments: `help <x>` must not silently drop
// <x> — the same silent-ignore class this Issue removes.
func TestRouteCommand_HelpTakesNoArguments(t *testing.T) {
	_, _, err := routeCommand([]string{"help", "client"})
	if err == nil {
		t.Fatal("routeCommand([help client]) error = nil, want an error")
	}
	if !strings.Contains(err.Error(), `"client"`) {
		t.Errorf("error %q does not name the stray argument", err)
	}
}

// TestRouteCommand_SubcommandTableRoutes is USK-1047 T2: the subcommand
// table is the single source of names — every entry routes to itself.
func TestRouteCommand_SubcommandTableRoutes(t *testing.T) {
	if len(subcommandNames) == 0 {
		t.Fatal("subcommandNames is empty")
	}
	for _, sub := range subcommandNames {
		name, _, err := routeCommand([]string{sub})
		if err != nil || name != sub {
			t.Errorf("routeCommand([%q]) = (%q, %v), want (%q, nil)", sub, name, err, sub)
		}
	}
}

// TestPrintServerUsage_ListsEverySubcommand is USK-1047 T5: the -h banner
// documents every name in the subcommand table, including help.
func TestPrintServerUsage_ListsEverySubcommand(t *testing.T) {
	var buf bytes.Buffer
	printServerUsage(&buf, flag.NewFlagSet("usage", flag.ContinueOnError))
	out := buf.String()
	i := strings.Index(out, "Subcommands:")
	if i < 0 {
		t.Fatalf("usage has no Subcommands section:\n%s", out)
	}
	section, _, _ := strings.Cut(out[i:], "\n\n")
	for _, sub := range subcommandNames {
		if !strings.Contains(section, "\n  "+sub+" ") {
			t.Errorf("usage Subcommands section is missing %q:\n%s", sub, section)
		}
	}
}

// routeAssertListsSubcommands fails t unless msg names every subcommand.
func routeAssertListsSubcommands(t *testing.T, msg string) {
	t.Helper()
	for _, sub := range subcommandNames {
		if !strings.Contains(msg, sub) {
			t.Errorf("error %q does not list subcommand %q", msg, sub)
		}
	}
}

// TestRunServer_HelpPrintsUsage drives the real server-mode usage path:
// runServer installs the banner, mcpserver.Run registers every flag and
// fs.Parse handles -h before any boot side effect. The usage must carry
// the banner, every registered server flag, and that flag's YP_ env var.
func TestRunServer_HelpPrintsUsage(t *testing.T) {
	fs := flag.NewFlagSet("yorishiro-proxy", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	err := runServer(context.Background(), fs, []string{"-h"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("runServer(-h) = %v, want flag.ErrHelp", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Usage: yorishiro-proxy [subcommand] [flags]",
		"Server flags:",
		"All flags accept a YP_ prefixed environment variable as fallback.",
		"Examples:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q", want)
		}
	}

	if len(mcpserver.EnvVarMap) == 0 {
		t.Fatal("mcpserver.EnvVarMap is empty")
	}
	for name, env := range mcpserver.EnvVarMap {
		if fs.Lookup(name) == nil {
			t.Errorf("flag -%s (in EnvVarMap) is not registered by the server path", name)
			continue
		}
		if !strings.Contains(out, "  -"+name) {
			t.Errorf("usage output does not list flag -%s", name)
		}
		if !strings.Contains(out, "(env: "+env+")") {
			t.Errorf("usage output does not advertise %s for flag -%s", env, name)
		}
	}
	if t.Failed() {
		t.Logf("usage output:\n%s", out)
	}
}
