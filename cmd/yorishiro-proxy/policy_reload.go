package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

// sighupPolicyReload is the mcpserver.RunOptions.PolicyReload hook: SIGHUP
// re-reads the Policy Layer source and replaces the running policy
// (USK-1115). It is the operator's privileged path — sending a signal
// requires being the process owner (or root), which the AI agent reaching
// the MCP server is not.
//
// mcpserver.Run calls the hook only when a policy source
// (-target-policy-file or -config) is configured, so without one SIGHUP is
// never registered and keeps Go's default (terminate the process).
//
// Unix only: syscall.SIGHUP compiles on Windows but is never delivered
// there, so the reload trigger simply never fires.
func sighupPolicyReload() mcpserver.PolicyReloadTrigger {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	// Buffer of 1: signals that arrive while a reload is pending coalesce
	// into a single request.
	trig := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigCh:
				select {
				case trig <- struct{}{}:
				default:
				}
			}
		}
	}()

	var once sync.Once
	return mcpserver.PolicyReloadTrigger{
		Name: "SIGHUP",
		C:    trig,
		Stop: func() {
			once.Do(func() {
				signal.Stop(sigCh)
				close(done)
			})
		},
	}
}
