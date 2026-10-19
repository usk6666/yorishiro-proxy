package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

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
