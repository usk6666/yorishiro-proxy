package pluginv2

// Test-only exports. The file name `export_test.go` is the standard Go
// idiom for surfacing internal symbols to external (`pluginv2_test`)
// test packages without polluting the production API.

// TCPPluginChunkSizeForTest exposes maxTCPPluginChunkSize so the sync
// test in limits_sync_test.go can compare it against
// config.MaxTCPPluginChunkSize. Not part of the production API.
func TCPPluginChunkSizeForTest() int { return maxTCPPluginChunkSize }
