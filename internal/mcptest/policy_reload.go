package mcptest

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcpserver"
)

// policyReloadDriver is the harness side of mcpserver.RunOptions.PolicyReload
// (USK-1115). The binary wires that hook to SIGHUP; the harness wires it to a
// channel so a test can request a reload and wait for its outcome without
// sending a signal to the test process.
type policyReloadDriver struct {
	trigger   chan struct{}
	results   chan error
	installed atomic.Bool
	mu        sync.Mutex // serializes ReloadPolicy callers
}

func newPolicyReloadDriver() *policyReloadDriver {
	return &policyReloadDriver{
		trigger: make(chan struct{}, 1),
		results: make(chan error, 1),
	}
}

// install is the RunOptions.PolicyReload hook. mcpserver.Run calls it only
// when a policy source is configured.
func (d *policyReloadDriver) install() mcpserver.PolicyReloadTrigger {
	d.installed.Store(true)
	return mcpserver.PolicyReloadTrigger{Name: "mcptest", C: d.trigger}
}

// report is the RunOptions.OnPolicyReload hook. Non-blocking so a test that
// never calls ReloadPolicy cannot stall the server's reload goroutine.
func (d *policyReloadDriver) report(err error) {
	select {
	case d.results <- err:
	default:
	}
}

// ReloadPolicy requests one Policy Layer reload through the same path SIGHUP
// drives in the production binary and returns the reload's result (nil = the
// policy source was re-read and installed). It t.Fatal's when the server
// installed no reload trigger — i.e. it was booted without
// -target-policy-file / -config — or when the reload does not finish within
// 10s.
func (h *Harness) ReloadPolicy(t *testing.T) error {
	t.Helper()
	d := h.policyReload
	if d == nil || !d.installed.Load() {
		t.Fatal("mcptest: server installed no policy reload trigger (boot it with -target-policy-file or -config)")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Drop a stale result (e.g. from a reload a previous caller abandoned).
	select {
	case <-d.results:
	default:
	}

	select {
	case d.trigger <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("mcptest: policy reload trigger not consumed within 10s")
	}
	select {
	case err := <-d.results:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("mcptest: policy reload did not finish within 10s")
	}
	return nil // unreachable; t.Fatal above
}
