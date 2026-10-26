package mcpserver

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// USK-1389: a -config file with a null host_tls entry used to pass
// validation and then panic in InitHostTLSRegistry at startup. Boot must
// refuse it at config load with an error naming the entry.
func TestLoadConfigs_NullHostTLSEntryRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFileAtomic(t, path, `{"host_tls":{"x":null}}`)

	res, err := LoadConfigs(path, "")
	if err == nil {
		t.Fatalf("LoadConfigs accepted a null host_tls entry (InitHostTLSRegistry %s)", initHostTLSOutcome(res.ProxyCfg))
	}
	if !strings.Contains(err.Error(), `host_tls["x"]`) {
		t.Errorf("LoadConfigs error = %q, want it to name host_tls[\"x\"]", err)
	}
}

// initHostTLSOutcome runs the boot consumer of host_tls and reports whether
// it panicked, so a failure shows the crash the gate prevents.
func initHostTLSOutcome(proxyCfg *config.ProxyConfig) (outcome string) {
	defer func() {
		if r := recover(); r != nil {
			outcome = fmt.Sprintf("panicked: %v", r)
		}
	}()
	_, err := InitHostTLSRegistry(&config.Config{}, proxyCfg, discardLogger())
	return fmt.Sprintf("returned err=%v", err)
}

// USK-1389: a SIGHUP reload of a -config file that gains a null host_tls
// entry is rejected exactly as boot would reject it, and the previous
// Policy Layer keeps working.
func TestPolicyReload_ConfigFileNullHostTLSEntryKeepsOld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFileAtomic(t, path, `{"target_scope_policy":{"allows":[{"hostname":"old.test"}]}}`)
	e := bootEngines(t, path, "")
	want := e.state()

	writeFileAtomic(t, path, `{"target_scope_policy":{"allows":[{"hostname":"new.test"}]},"host_tls":{"x":null}}`)
	err := e.reloader(PolicySource{ConfigFile: path}, discardLogger()).Reload("test")
	if err == nil {
		t.Fatal("Reload accepted a config file with a null host_tls entry, want an error")
	}
	if !strings.Contains(err.Error(), `host_tls["x"]`) {
		t.Errorf("Reload error = %q, want it to name host_tls[\"x\"]", err)
	}
	if got := e.state(); !reflect.DeepEqual(got, want) {
		t.Errorf("Policy Layer changed by a rejected reload:\n got  %+v\n want %+v", got, want)
	}
	if ok, _ := e.scope.CheckTarget("https", "old.test", 443, "/"); !ok {
		t.Error("old.test blocked after a rejected reload; the previous policy must keep working")
	}
}
