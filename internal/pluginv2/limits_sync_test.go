package pluginv2_test

// Sync test for the (raw, on_chunk) chunk-size cap.
//
// internal/pluginv2 cannot import internal/config (config imports pluginv2
// for PluginConfig, so the reverse import would form a cycle). The cap
// constant is therefore mirrored locally in dispatch.go as
// maxTCPPluginChunkSize. This test belongs to the external pluginv2_test
// package precisely so it can import both packages and assert they agree
// — preventing silent drift if someone later edits config.MaxTCPPluginChunkSize
// without updating the mirror.

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// TestTCPPluginChunkCap_MirrorsConfig fails fast if the local mirror in
// dispatch.go drifts from config.MaxTCPPluginChunkSize.
func TestTCPPluginChunkCap_MirrorsConfig(t *testing.T) {
	got := pluginv2.TCPPluginChunkSizeForTest()
	if int64(got) != config.MaxTCPPluginChunkSize {
		t.Fatalf("pluginv2 mirror %d != config.MaxTCPPluginChunkSize %d — update one to match the other",
			got, config.MaxTCPPluginChunkSize)
	}
}
