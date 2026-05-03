// Package fuzzer provides position-application primitives for fuzz attacks:
// payload-position iterators (Iterator, FuzzCase) and request-data mutation
// (Position, RequestData, ApplyPosition). Consumed by the typed fuzz MCP
// tools via internal/job/fuzz_http_source.go. The async legacy fuzzer engine
// (Engine, Runner, JobRegistry, OverloadMonitor) was removed in USK-694
// alongside the legacy fuzz MCP tool (USK-693).
package fuzzer
