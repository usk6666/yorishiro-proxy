package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/bodydecode"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// defaultRequestTimeoutMs is the default request timeout in milliseconds
// used when no protocol handler is registered.
const defaultRequestTimeoutMs = 60000

// oversizeAdvisoryThreshold is the per-message body byte length at which
// the flow / messages handlers attach an Advisory hint suggesting that the
// caller pass include_bodies=false or body_max_bytes=N to stay under the
// MCP per-tool token cap. 256 KiB is conservative — observed MCP rejection
// is around 2.8 MB and a single message body that large would risk pushing
// any multi-message response over the cap.
const oversizeAdvisoryThreshold = 256 * 1024

// oversizeAdvisoryMessage is the one-line hint string emitted in result.Advisory
// when an unbounded response carries at least one body above
// oversizeAdvisoryThreshold. The caller can suppress the advisory by passing
// either size-bounding param explicitly.
const oversizeAdvisoryMessage = "response contains a body larger than 256 KiB; pass include_bodies=false or body_max_bytes=N to stay under the MCP token limit"

// wireLevelAdvisory carries a structured hint surfaced on query
// responses when the default semantic wire_level filter (USK-921) hid
// wire-level overlay rows (h2-frame / grpc-lpm-frame / h1-chunk /
// grpcweb-base64) from the AI-facing response. Emitted only when the
// caller did NOT explicitly opt in via filter.wire_level, AND at least
// one overlay row exists for the queried stream(s). The advisory is
// purely informational — the wire copy of the overlay rows is
// unchanged on disk and re-fetchable via filter.wire_level=all (or any
// specific overlay value).
//
// Schema: pointer + omitempty so the field omits from JSON entirely on
// default-shaped queries (zero overlay rows OR explicit opt-in). When
// present, Hidden maps wire_level → count for every overlay value that
// had at least one suppressed row.
//
// Sibling of the existing Advisory string — additive change so existing
// AI-agent consumers parsing the oversize hint are unaffected (USK-931
// Q1 resolution).
type wireLevelAdvisory struct {
	// Filter is the resolved wire_level filter applied to this query.
	// Always "semantic (default)" today since the advisory is gated on
	// the caller having NOT opted in — kept as a string field so a
	// future change (e.g., advisory under a non-default-but-still-
	// hiding filter) can populate the canonical value.
	Filter string `json:"wire_level_filter" jsonschema:"the resolved wire_level filter applied to this query (\"semantic (default)\" when the advisory fires)"`
	// Hidden maps wire_level value → count of suppressed rows.
	// Zero-count entries are omitted so the map only carries the
	// overlays that actually contributed to the AI-visible projection
	// loss (USK-931 Q2 resolution: DB-side GROUP BY via
	// CountFlowsByWireLevel avoids loading payloads).
	Hidden map[string]int `json:"hidden_overlay_rows,omitempty" jsonschema:"per-wire_level count of rows suppressed by the semantic-default filter"`
	// Hint is the operator-facing one-liner describing the opt-in
	// mechanism. Constant string — the same value for every emit.
	Hint string `json:"hint" jsonschema:"one-line guidance for opting in to overlay rows"`
}

// wireLevelAdvisoryHint is the constant operator-facing hint string
// embedded in wireLevelAdvisory.Hint. Lists every canonical overlay
// value and the universal "all" sentinel so the AI agent can compose
// a fully-typed opt-in request from a single response field.
const wireLevelAdvisoryHint = "Pass filter.wire_level=\"h2-frame\" / \"grpc-lpm-frame\" / \"h1-chunk\" / \"grpcweb-base64\" / \"all\" to inspect raw-frame diagnostics."

// wireLevelAdvisoryDefaultLabel is the value set on
// wireLevelAdvisory.Filter when the advisory fires. Kept as a constant
// so the rendered shape is identical across all three query handlers.
const wireLevelAdvisoryDefaultLabel = "semantic (default)"

// buildWireLevelAdvisory composes a *wireLevelAdvisory from the
// per-wire_level suppressed-row counts. Returns nil when:
//
//   - filter is non-nil AND filter.WireLevel is non-empty (caller opted
//     in via filter.wire_level={overlay | all}); the advisory only
//     fires for default-shaped queries.
//   - hidden is empty (no overlay rows exist for the queried streams).
//
// Caller passes the raw map from Store.CountFlowsByWireLevel after
// subtracting the semantic bucket. Zero entries in the map are dropped.
func buildWireLevelAdvisory(filter *queryFilter, hidden map[string]int) *wireLevelAdvisory {
	if filter != nil && filter.WireLevel != "" {
		return nil
	}
	pruned := map[string]int{}
	for k, v := range hidden {
		if v > 0 {
			pruned[k] = v
		}
	}
	if len(pruned) == 0 {
		return nil
	}
	return &wireLevelAdvisory{
		Filter: wireLevelAdvisoryDefaultLabel,
		Hidden: pruned,
		Hint:   wireLevelAdvisoryHint,
	}
}

// collectHiddenOverlayCounts queries the wire_level breakdown for a
// single stream and returns the count of overlay rows (every wire_level
// other than semantic). Direction inside opts narrows the count to a
// single side; an empty Direction counts both. The semantic bucket is
// dropped from the returned map. Returns nil on the underlying SQL
// error path.
func (s *Server) collectHiddenOverlayCounts(ctx context.Context, streamID string, opts flow.FlowListOptions) (map[string]int, error) {
	if s.flowStore.store == nil {
		return nil, nil
	}
	breakdown, err := s.flowStore.store.CountFlowsByWireLevel(ctx, streamID, opts)
	if err != nil {
		return nil, fmt.Errorf("count flows by wire_level: %w", err)
	}
	if len(breakdown) == 0 {
		return nil, nil
	}
	hidden := make(map[string]int, len(breakdown))
	for wl, n := range breakdown {
		if wl == flow.WireLevelSemantic {
			continue
		}
		hidden[wl] = n
	}
	return hidden, nil
}

// queryInput is the typed input for the query tool.
type queryInput struct {
	// Resource specifies what to query: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results.
	Resource string `json:"resource" jsonschema:"resource to query: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results"`

	// ID is required for flow and messages resources.
	// For flow: the flow ID. For messages: the flow_id.
	ID string `json:"id,omitempty" jsonschema:"flow ID (required for flow and messages resources)"`

	// FuzzID is required for the fuzz_results resource (fuzz job ID).
	FuzzID string `json:"fuzz_id,omitempty" jsonschema:"fuzz job ID (required for fuzz_results resource)"`

	// Filter is used with the flows and fuzz resources for filtering results.
	Filter *queryFilter `json:"filter,omitempty" jsonschema:"filter options for flows and fuzz resources"`

	// Fields controls which fields are returned in the response.
	// If empty, all fields are returned.
	Fields []string `json:"fields,omitempty" jsonschema:"list of field names to include in the response"`

	// SortBy specifies the field to sort results by (used by flows and fuzz_results).
	SortBy string `json:"sort_by,omitempty" jsonschema:"field name to sort results by"`

	// Limit is the maximum number of items to return (default 50, max 1000).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of items to return (default 50, max 1000)"`

	// Offset is the number of items to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"number of items to skip for pagination (must be >= 0)"`

	// DecodeBodies controls whether the flow / messages handlers decode HTTP
	// Content-Encoding (gzip / deflate / br / zstd) bodies into additive
	// `*_body_decoded` fields for AI-agent readability. Default is true. Set
	// to false to skip decompression when fidelity-only inspection is desired.
	// The original wire-form body is always returned in `*_body` regardless
	// of this flag (CLAUDE.md MITM principle #1).
	DecodeBodies *bool `json:"decode_bodies,omitempty" jsonschema:"decode HTTP Content-Encoding bodies (gzip/deflate/br/zstd) into *_body_decoded fields (default true)"`

	// IncludeBodies suppresses body fields on the flow / messages responses
	// when set to false. Defaults to true. Mirrors manage.export_flows.include_bodies.
	// When false, all *_body / *_body_encoding / *_body_decoded* fields and the
	// raw_request / raw_response base64 dumps are cleared on the response; the
	// per-message body_truncated_by_query flag (and the side companions on
	// queryFlowResult) is set so callers can tell metadata-only responses apart
	// from genuinely empty bodies. Headers, metadata, status, method, URL, and
	// the record-time body_truncated flag are preserved.
	IncludeBodies *bool `json:"include_bodies,omitempty" jsonschema:"include message bodies in flow/messages responses (default true). When false, body fields are suppressed; metadata, headers, and body_truncated remain. Mirrors manage.export_flows.include_bodies."`

	// BodyMaxBytes caps each message body (and decoded body, independently)
	// to at most this many bytes. 0 disables the cap (default). Truncation is
	// applied to the body byte slice before base64 encoding so the response
	// never base64-mid-quadruple-splits. When applied, body_truncated_by_query
	// is set on the entry and body_original_size / body_decoded_original_size
	// report the pre-truncation byte length on the side that was truncated.
	BodyMaxBytes int `json:"body_max_bytes,omitempty" jsonschema:"truncate per-message body and body_decoded to at most this many bytes (0 = no cap, default). When applied, body_truncated_by_query is set and body_original_size / body_decoded_original_size report the pre-truncation lengths."`
}

// queryFilter contains filter options for the flows and fuzz resources.
type queryFilter struct {
	// Protocol filters flows by canonical Message-type family. Accepted values:
	// http, ws, grpc, grpc-web, sse, raw, tls-handshake. Each family expands
	// across all wire spellings recorded for it (e.g. protocol=http matches
	// HTTP/1.x, HTTPS, HTTP/2 and their SOCKS5+ variants). To find all TLS flows
	// regardless of HTTP version, use scheme=https instead.
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter — canonical Message-type family: http, ws, grpc, grpc-web, sse, raw, tls-handshake. Each family expands across all wire spellings. Use scheme=https to find all TLS flows regardless of HTTP version."`
	// Scheme filters flows by Stream.Scheme — the wire-observed handshake
	// transport ("http", "https", "tcp"). Per USK-848, WebSocket Streams keep
	// the handshake transport (http or https); they do NOT record "ws"/"wss".
	// To isolate WebSocket flows: use filter.protocol="ws" (any transport) or
	// combine protocol="ws" with scheme="https" for WS-over-TLS only.
	Scheme string `json:"scheme,omitempty" jsonschema:"Stream.Scheme filter — wire-observed handshake transport (http, https, tcp). For WebSocket flows use protocol=\"ws\"; combine with scheme=\"https\" for WS-over-TLS only."`
	// HTTPVersion filters flows that have at least one Flow row with
	// the matching http_version value (USK-788/USK-792). Canonical
	// lowercased values: "http/1.0", "http/1.1", "h2", "h2c". Mirrors
	// the manage tool's filter.http_version axis. Use a pointer so
	// callers may explicitly pass "" to match pre-USK-788 rows; omit
	// the key entirely to disable the predicate.
	HTTPVersion *string `json:"http_version,omitempty" jsonschema:"http_version filter (http/1.0, http/1.1, h2, h2c). Empty-string explicit value matches pre-USK-788 rows."`
	// Method filters flows by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters flows by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters flows/fuzz_results by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
	// BlockedBy filters flows by blocked_by value (e.g. "target_scope", "intercept_drop", "rate_limit").
	BlockedBy string `json:"blocked_by,omitempty" jsonschema:"blocked_by filter (e.g. target_scope, intercept_drop, rate_limit)"`
	// Origin filters streams by how they came into existence (USK-786):
	// "proxy" for live MITM-recorded traffic, "resend" for streams created by the
	// resend_* MCP tools, "fuzz" reserved for fuzz campaigns. Empty disables the filter.
	Origin string `json:"origin,omitempty" jsonschema:"stream origin filter (proxy, resend, fuzz)"`
	// State filters flows by lifecycle state ("active", "complete", or "error").
	State string `json:"state,omitempty" jsonschema:"flow lifecycle state filter (active, complete, error)"`
	// Direction filters messages by direction ("send" or "receive").
	Direction string `json:"direction,omitempty" jsonschema:"message direction filter (send or receive)"`
	// WireLevel filters messages by wire_level discriminator (USK-921).
	// The flow store records both canonical L7 "semantic" envelopes and
	// per-protocol wire-level overlay envelopes (h2-frame, h1-chunk,
	// grpc-lpm-frame, grpcweb-base64) for diagnostic L4 visibility. To
	// keep the default L7 view free of overlay clutter the MCP query path
	// hard-defaults this filter to "semantic" — set "all" to receive
	// every wire_level, or one of the overlay values to isolate a single
	// diagnostic view. Empty / unset → "semantic". Applies to the flows,
	// flow, and messages resources (overlay rows are excluded from
	// message_count and message_preview by default).
	WireLevel string `json:"wire_level,omitempty" jsonschema:"wire_level filter (USK-921). semantic (default) returns only canonical L7 envelopes; h2-frame / h1-chunk / grpc-lpm-frame / grpcweb-base64 isolate a single diagnostic overlay; all returns every wire_level. Applies to flows / flow / messages resources."`
	// ConnID filters flows by connection ID (exact match).
	ConnID string `json:"conn_id,omitempty" jsonschema:"connection ID filter for flows (exact match)"`
	// Host filters flows by host (matches server_addr or URL host).
	Host string `json:"host,omitempty" jsonschema:"host filter for flows (matches server_addr or URL host, e.g. example.com)"`
	// BodyContains filters fuzz_results by response body substring.
	BodyContains string `json:"body_contains,omitempty" jsonschema:"response body substring filter (fuzz_results)"`
	// OutliersOnly filters fuzz_results to return only outlier results.
	OutliersOnly bool `json:"outliers_only,omitempty" jsonschema:"return only outlier fuzz results (by status_code, body_length, or timing)"`
	// Status filters fuzz_jobs by status (e.g. "running", "completed").
	Status string `json:"status,omitempty" jsonschema:"fuzz job status filter (e.g. running, completed)"`
	// Tag filters fuzz_jobs by tag (exact match).
	Tag string `json:"tag,omitempty" jsonschema:"fuzz job tag filter (exact match)"`
}

// availableResources lists all valid resource names for error messages.
var availableResources = []string{"flows", "flow", "messages", "status", "config", "ca_cert", "intercept_queue", "macros", "macro", "fuzz_jobs", "fuzz_results"}

// validFilterProtocols lists accepted values for filter.protocol. The
// query tool accepts canonical Envelope.Protocol values only; the legacy
// spellings ("HTTP/1.x", "HTTPS", "HTTP/2", "WebSocket", "gRPC", "gRPC-Web",
// "TCP", "SOCKS5+*") that lived through the parallel-coexistence window
// were retired in USK-705 (RFC-001 N9 design review Q8).
var validFilterProtocols = []string{
	"http", "ws", "grpc", "grpc-web", "sse", "raw", "tls-handshake",
}

// validFilterSchemes lists valid values for filter.scheme. Per USK-848 +
// RFC-001 §3, Stream.Scheme records the wire-observed handshake transport
// only: "http", "https", or "tcp". Application-level URL schemes such as
// "ws"/"wss" are NOT valid Stream.Scheme values — WebSocket Streams retain
// the handshake transport ("http" / "https") across the WS Protocol retag.
// USK-864 hard-rejects "ws"/"wss" filter values via validateSchemeFilter,
// which surfaces the remediation hint from rejectedSchemeHints pointing
// callers at the correct combined filter.
var validFilterSchemes = []string{"https", "http", "tcp"}

// rejectedSchemeHints lists scheme values that USK-864 hard-rejects with
// a remediation hint. Keys are the rejected value as supplied by the
// caller; values are the trailing remediation clause appended to the
// validateEnum error so the caller knows which combined filter to use
// instead.
var rejectedSchemeHints = map[string]string{
	"ws":  `use protocol="ws" for WebSocket flows (Stream.Scheme records the handshake transport, not the application protocol)`,
	"wss": `use protocol="ws" combined with scheme="https" for WS-over-TLS flows (Stream.Scheme records the handshake transport, not the application protocol)`,
}

// validateSchemeFilter wraps validateEnum to surface the USK-864
// remediation hint for the application-protocol values that callers
// commonly mistake for valid Stream.Scheme values. For non-rejected
// invalid values it falls through to the standard validateEnum error.
func validateSchemeFilter(value string) error {
	if value == "" {
		return nil
	}
	if hint, ok := rejectedSchemeHints[value]; ok {
		return fmt.Errorf("invalid scheme %q: %s", value, hint)
	}
	return validateEnum("scheme", value, validFilterSchemes)
}

// validFilterHTTPVersions lists valid values for filter.http_version.
// Mirrors the canonical lowercased values stamped on Flow.HTTPVersion
// by USK-788. The empty string is a separately-meaningful sentinel
// (pre-USK-788 rows) and is accepted by the filter when sent as an
// explicit empty value, but it is not enumerated here because
// validateEnum treats "" as "filter not applied".
var validFilterHTTPVersions = []string{"http/1.0", "http/1.1", "h2", "h2c"}

// validFilterStates lists valid values for filter.state.
var validFilterStates = []string{"active", "complete", "error"}

// validFilterBlockedBy lists valid values for filter.blocked_by.
var validFilterBlockedBy = []string{"target_scope", "intercept_drop", "rate_limit", "safety_filter", "budget"}

// validFilterOrigins lists valid values for filter.origin (USK-786).
// Mirrors flow.Origin constants; "fuzz" is reserved for forward compatibility.
var validFilterOrigins = []string{"proxy", "resend", "fuzz"}

// validFilterFuzzJobStatuses lists valid values for filter.status (fuzz_jobs).
var validFilterFuzzJobStatuses = []string{"running", "paused", "completed", "cancelled", "error"}

// wireLevelFilterAll is the opt-in sentinel disabling the wire_level
// default; passing "all" surfaces every wire_level (semantic + every
// overlay) to the caller. Distinct from the empty / unset value which
// the MCP query path normalises to flow.WireLevelSemantic.
const wireLevelFilterAll = "all"

// validFilterWireLevels lists accepted values for filter.wire_level (USK-921).
// The MCP query path (flows / flow / messages) hard-defaults to
// flow.WireLevelSemantic when the field is empty / unset; "all" disables
// the predicate. The overlay values are reused verbatim from the
// flow.WireLevel* canonical set so a new producer surfaces here at the
// same time it surfaces at the SQL boundary.
var validFilterWireLevels = []string{
	flow.WireLevelSemantic,
	flow.WireLevelH2Frame,
	flow.WireLevelHTTP1Chunk,
	flow.WireLevelGRPCLPMFrame,
	flow.WireLevelGRPCWebBase64,
	wireLevelFilterAll,
}

// nonSemanticWireLevel reports the wire_level discriminator suitable for
// inclusion in the JSON response — i.e. surfacing every value except the
// default flow.WireLevelSemantic (the latter is implied by the absence of
// the field on a default-filtered response). The empty string passes
// through unchanged so pre-schemaV14 rows stay invisible.
func nonSemanticWireLevel(wl string) string {
	if wl == flow.WireLevelSemantic {
		return ""
	}
	return wl
}

// resolveWireLevelFilter validates and translates filter.wire_level into
// the value passed to flow.FlowListOptions.WireLevel. Empty / unset →
// flow.WireLevelSemantic so the MCP L7 view never includes overlay rows
// without explicit opt-in (USK-921). "all" disables the predicate (empty
// string returned). Any other accepted value passes through verbatim.
// Unknown values surface a validateEnum error with the canonical list.
func resolveWireLevelFilter(filter *queryFilter) (string, error) {
	value := ""
	if filter != nil {
		value = filter.WireLevel
	}
	if value == "" {
		return flow.WireLevelSemantic, nil
	}
	if err := validateEnum("wire_level", value, validFilterWireLevels); err != nil {
		return "", err
	}
	if value == wireLevelFilterAll {
		return "", nil
	}
	return value, nil
}

// validFlowSortByValues lists valid values for sort_by (flows).
var validFlowSortByValues = []string{"timestamp", "duration_ms"}

// validFuzzResultSortByValues lists valid values for sort_by (fuzz_results).
var validFuzzResultSortByValues = []string{"index_num", "status_code", "duration_ms", "response_length"}

// validateEnum checks whether value is in the allowed set and returns an error with valid values listed.
func validateEnum(param, value string, valid []string) error {
	if value == "" {
		return nil
	}
	for _, v := range valid {
		if value == v {
			return nil
		}
	}
	return fmt.Errorf("invalid %s %q: valid values are %s", param, value, strings.Join(valid, ", "))
}

// validateFlowFilters validates enum filter parameters for the flows resource.
func validateFlowFilters(input queryInput) error {
	if input.Filter != nil {
		if err := validateEnum("protocol", input.Filter.Protocol, validFilterProtocols); err != nil {
			return err
		}
		if err := validateSchemeFilter(input.Filter.Scheme); err != nil {
			return err
		}
		if err := validateEnum("state", input.Filter.State, validFilterStates); err != nil {
			return err
		}
		if err := validateEnum("blocked_by", input.Filter.BlockedBy, validFilterBlockedBy); err != nil {
			return err
		}
		if err := validateEnum("origin", input.Filter.Origin, validFilterOrigins); err != nil {
			return err
		}
		// http_version uses a pointer to keep the empty-string sentinel
		// available; only validate against the enum when a non-empty
		// value is supplied.
		if v := input.Filter.HTTPVersion; v != nil && *v != "" {
			if err := validateEnum("http_version", *v, validFilterHTTPVersions); err != nil {
				return err
			}
		}
		// USK-921: validate the wire_level filter at the flows entry
		// point so callers see the canonical enum error before any
		// per-flow message lookup. The same resolver runs inside
		// handleQueryFlows when building the per-flow opts so an
		// unset value still gets the semantic default.
		if _, err := resolveWireLevelFilter(input.Filter); err != nil {
			return err
		}
	}
	if err := validateEnum("sort_by", input.SortBy, validFlowSortByValues); err != nil {
		return err
	}
	return nil
}

// validateMessageFilters validates enum filter parameters for the messages
// and flow resources (USK-921). Both handlers consume filter.wire_level to
// control overlay visibility; the dedicated validator surfaces the canonical
// enum error before the SQL fetch happens.
func validateMessageFilters(input queryInput) error {
	if input.Filter == nil {
		return nil
	}
	if _, err := resolveWireLevelFilter(input.Filter); err != nil {
		return err
	}
	return nil
}

// validateFuzzJobFilters validates enum filter parameters for the fuzz_jobs resource.
func validateFuzzJobFilters(input queryInput) error {
	if input.Filter != nil {
		if err := validateEnum("status", input.Filter.Status, validFilterFuzzJobStatuses); err != nil {
			return err
		}
	}
	return nil
}

// validateFuzzResultFilters validates enum filter parameters for the fuzz_results resource.
func validateFuzzResultFilters(input queryInput) error {
	if err := validateEnum("sort_by", input.SortBy, validFuzzResultSortByValues); err != nil {
		return err
	}
	return nil
}

// registerQuery registers the query MCP tool.
func (s *Server) registerQuery() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "query",
		Description: "Unified read-only query: flows, flow detail, messages, status, config, ca_cert, " +
			"intercept_queue, macros, macro, fuzz_jobs, fuzz_results. " +
			"Set 'resource' to one of those values; 'id' supplies the flow/macro/messages ID and 'fuzz_id' " +
			"supplies the fuzz job ID. 'filter' / 'fields' / 'sort_by' / 'limit' / 'offset' shape result sets. " +
			"Protocol filter accepts canonical Message-type families (http, ws, grpc, grpc-web, sse, raw, tls-handshake) " +
			"each expanding across all wire spellings; use scheme=https to find all TLS flows regardless of HTTP version. " +
			"Modified flows surface both original and modified variants (variant=original|modified). " +
			"For large bodies that would exceed the MCP token cap on flow / messages, pass " +
			"include_bodies=false (metadata only) or body_max_bytes=N (per-side byte cap). " +
			"See yorishiro://help/query for the full filter / field / sort reference.",
	}, s.handleQuery)
}

// validateQueryInput dispatches enum validation by resource type.
func validateQueryInput(input queryInput) error {
	switch input.Resource {
	case "flows":
		return validateFlowFilters(input)
	case "flow", "messages":
		// USK-921: the flow / messages handlers also honour
		// filter.wire_level; surface the enum error at the dispatch
		// boundary so the per-handler GetFlows call sees a validated
		// value (or the semantic default).
		return validateMessageFilters(input)
	case "fuzz_jobs":
		return validateFuzzJobFilters(input)
	case "fuzz_results":
		return validateFuzzResultFilters(input)
	default:
		return nil
	}
}

// handleQuery dispatches the query request to the appropriate resource handler.
func (s *Server) handleQuery(ctx context.Context, req *gomcp.CallToolRequest, input queryInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "query",
		"resource", input.Resource,
		"id", input.ID,
		"fuzz_id", input.FuzzID,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "query",
			"resource", input.Resource,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateQueryInput(input); err != nil {
		return nil, nil, err
	}
	switch input.Resource {
	case "flows":
		return s.handleQueryFlows(ctx, input)
	case "flow":
		return s.handleQueryFlow(ctx, input)
	case "messages":
		return s.handleQueryMessages(ctx, input)
	case "status":
		return s.handleQueryStatus(ctx)
	case "config":
		return s.handleQueryConfig()
	case "ca_cert":
		return s.handleQueryCACert()
	case "intercept_queue":
		return s.handleQueryInterceptQueue(input)
	case "macros":
		return s.handleQueryMacros(ctx)
	case "macro":
		return s.handleQueryMacro(ctx, input)
	case "fuzz_jobs":
		return s.handleQueryFuzzJobs(ctx, input)
	case "fuzz_results":
		return s.handleQueryFuzzResults(ctx, input)
	case "":
		return nil, nil, fmt.Errorf("resource is required: available resources are %s", strings.Join(availableResources, ", "))
	default:
		return nil, nil, fmt.Errorf("unknown resource %q: available resources are %s", input.Resource, strings.Join(availableResources, ", "))
	}
}

// --- anomaly extraction ---

// queryAnomaly represents a structured anomaly entry extracted from flow tags.
// Anomalies are HTTP protocol-level deviations detected during parsing, such as
// CL/TE conflicts, duplicate Content-Length headers, or header injection attempts.
type queryAnomaly struct {
	// Type is the anomaly classification (e.g., "CLTE", "DuplicateCL", "HeaderInjection").
	Type string `json:"type"`
	// Detail provides a human-readable description of the anomaly.
	Detail string `json:"detail"`
}

// smugglingTagToAnomalyType maps smuggling tag keys to their anomaly type names.
var smugglingTagToAnomalyType = map[string]string{
	"smuggling:cl_te_conflict":   "CLTE",
	"smuggling:duplicate_cl":     "DuplicateCL",
	"smuggling:ambiguous_te":     "AmbiguousTE",
	"smuggling:invalid_te":       "InvalidTE",
	"smuggling:header_injection": "HeaderInjection",
	"smuggling:obs_fold":         "ObsFold",
}

// flowMetadataAnomalyKeyToType maps per-flow Metadata anomaly keys (set by
// pipeline.RecordStep projections — USK-656 SSE, USK-659 gRPC-Web,
// USK-849 HTTP) back to their canonical envelope.AnomalyType string. The
// map is closed for known producers; unknown `*_anomaly_*` keys still
// surface via a stable namespaced fallback in extractAnomaliesFromFlows
// so future producers do not require a synchronous patch here.
var flowMetadataAnomalyKeyToType = map[string]string{
	// HTTP/1.x parser anomalies (USK-849).
	"http_anomaly_cl_te":                   string(envelope.AnomalyCLTE),
	"http_anomaly_duplicate_cl":            string(envelope.AnomalyDuplicateCL),
	"http_anomaly_invalid_te":              string(envelope.AnomalyInvalidTE),
	"http_anomaly_header_injection":        string(envelope.AnomalyHeaderInjection),
	"http_anomaly_ambiguous_te":            string(envelope.AnomalyAmbiguousTE),
	"http_anomaly_obs_fold":                string(envelope.AnomalyObsFold),
	"http_anomaly_trailer_pseudo_header":   string(envelope.AnomalyTrailerPseudoHeader),
	"http_anomaly_trailer_forbidden":       string(envelope.AnomalyTrailerForbidden),
	"http_anomaly_trailers_in_passthrough": string(envelope.AnomalyTrailersInPassthrough),
	"http_anomaly_raw_body_truncated":      string(envelope.AnomalyRawBodyTruncated),
	// HTTP/2 receive-side anomalies.
	"http_anomaly_h2_duplicate_pseudo_header":      string(envelope.H2DuplicatePseudoHeader),
	"http_anomaly_h2_pseudo_header_after_regular":  string(envelope.H2PseudoHeaderAfterRegular),
	"http_anomaly_h2_invalid_pseudo_header":        string(envelope.H2InvalidPseudoHeader),
	"http_anomaly_h2_uppercase_header_name":        string(envelope.H2UppercaseHeaderName),
	"http_anomaly_h2_connection_specific_header":   string(envelope.H2ConnectionSpecificHeader),
	"http_anomaly_h2_trailers_after_passthrough":   string(envelope.H2TrailersAfterPassthrough),
	"http_anomaly_h2_push_promise":                 string(envelope.H2PushPromise),
	"http_anomaly_h2_unsupported_connect_protocol": string(envelope.H2UnsupportedConnectProtocol),
	// HTTP/2 send-side strip mirror (USK-840).
	"http_anomaly_h2_connection_specific_header_stripped_on_send": string(envelope.H2ConnectionSpecificHeaderStrippedOnSend),
	// gRPC-Web anomalies (USK-659).
	"grpc_anomaly_malformed_base64":           string(envelope.AnomalyMalformedGRPCWebBase64),
	"grpc_anomaly_malformed_lpm":              string(envelope.AnomalyMalformedGRPCWebLPM),
	"grpc_anomaly_malformed_trailer":          string(envelope.AnomalyMalformedGRPCWebTrailer),
	"grpc_anomaly_missing_trailer":            string(envelope.AnomalyMissingGRPCWebTrailer),
	"grpc_anomaly_unexpected_request_trailer": string(envelope.AnomalyUnexpectedGRPCWebRequestTrailer),
	// SSE anomalies (USK-656).
	"sse_anomaly_missing_data": string(envelope.AnomalySSEMissingData),
	"sse_anomaly_truncated":    string(envelope.AnomalySSETruncated),
	"sse_anomaly_duplicate_id": string(envelope.AnomalySSEDuplicateID),
}

// anomalyMetadataPrefixes lists the per-flow Metadata key prefixes that
// extractAnomaliesFromFlows scans. New protocols (or new producers) that
// adopt the `<proto>_anomaly_<type>` projection only need to append a
// prefix here — the existing fallback path surfaces the entry verbatim
// even if flowMetadataAnomalyKeyToType has not been updated.
var anomalyMetadataPrefixes = []string{"http_anomaly_", "grpc_anomaly_", "sse_anomaly_"}

// extractAnomalies converts smuggling:* tags into a structured anomaly list.
// Returns nil if no anomalies are present, avoiding unnecessary JSON array allocation.
//
// This path is the legacy stream-tag rollup; it is kept for backward
// compatibility with pre-USK-849 captures that may carry smuggling:* tags
// on the Stream row. The current production projection writes per-flow
// Metadata keys consumed by extractAnomaliesFromFlows.
func extractAnomalies(tags map[string]string) []queryAnomaly {
	if len(tags) == 0 {
		return nil
	}

	var anomalies []queryAnomaly
	warnings := tags["smuggling:warnings"]

	for tagKey, anomalyType := range smugglingTagToAnomalyType {
		if tags[tagKey] == "true" {
			detail := ""
			if warnings != "" {
				detail = warnings
			}
			anomalies = append(anomalies, queryAnomaly{
				Type:   anomalyType,
				Detail: detail,
			})
		}
	}

	if len(anomalies) == 0 {
		return nil
	}

	// Sort for deterministic output.
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Type < anomalies[j].Type
	})
	return anomalies
}

// extractAnomaliesFromFlows rolls up per-flow Metadata keys with the
// known anomaly prefixes (`http_anomaly_*` / `grpc_anomaly_*` /
// `sse_anomaly_*`) into structured queryAnomaly entries (USK-849).
//
// Each matching key is mapped to its canonical envelope.AnomalyType
// string via flowMetadataAnomalyKeyToType. Unknown keys (added by a
// future producer) surface under a stable namespaced Type derived from
// the key suffix — better to show an unknown anomaly than to silently
// drop it (MITM Principle #5).
//
// Output is sorted by Type for deterministic JSON across runs. Returns
// nil when no per-flow anomaly keys are present so the caller can leave
// `anomalies,omitempty` absent.
func extractAnomaliesFromFlows(flows []*flow.Flow) []queryAnomaly {
	if len(flows) == 0 {
		return nil
	}

	// Use a map keyed on Type to dedupe identical anomalies projected
	// onto multiple flows (e.g. an HTTP/1.x request anomaly is
	// associated with the request flow only — but a future producer
	// could record the same anomaly on both Send and Receive). Last
	// non-empty Detail wins; map iteration is sorted on the way out.
	dedup := make(map[string]string)
	for _, fl := range flows {
		if fl == nil || len(fl.Metadata) == 0 {
			continue
		}
		for key, detail := range fl.Metadata {
			if !hasAnomalyPrefix(key) {
				continue
			}
			typeName, ok := flowMetadataAnomalyKeyToType[key]
			if !ok {
				// Unknown but recognised-prefix key: surface as the
				// raw key string so the analyst can still find it.
				typeName = key
			}
			if existing, present := dedup[typeName]; present && detail == "" {
				// Don't overwrite a meaningful Detail with empty.
				_ = existing
				continue
			}
			dedup[typeName] = detail
		}
	}

	if len(dedup) == 0 {
		return nil
	}

	out := make([]queryAnomaly, 0, len(dedup))
	for typeName, detail := range dedup {
		out = append(out, queryAnomaly{Type: typeName, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// hasAnomalyPrefix reports whether key carries one of the known anomaly
// Metadata prefixes.
func hasAnomalyPrefix(key string) bool {
	for _, p := range anomalyMetadataPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// mergeAnomalies concatenates two queryAnomaly slices, deduping on Type
// (later entries win on Detail), and returns the merged slice sorted by
// Type. Returns nil when both inputs are empty so the JSON `omitempty`
// path holds.
func mergeAnomalies(a, b []queryAnomaly) []queryAnomaly {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	dedup := make(map[string]string, len(a)+len(b))
	for _, e := range a {
		dedup[e.Type] = e.Detail
	}
	for _, e := range b {
		if existing, present := dedup[e.Type]; present && e.Detail == "" {
			_ = existing
			continue
		}
		dedup[e.Type] = e.Detail
	}
	out := make([]queryAnomaly, 0, len(dedup))
	for typeName, detail := range dedup {
		out = append(out, queryAnomaly{Type: typeName, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// --- flows resource ---

// queryFlowsEntry is a single flow entry in the flows query response.
type queryFlowsEntry struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Scheme   string `json:"scheme,omitempty"`
	State    string `json:"state"`
	// FailureReason carries the canonical layer.ErrorCode label
	// (refused / canceled / aborted / internal_error / protocol_error)
	// or one of the recorder-specific labels (e.g. "upstream_tls_error",
	// "client_tls_error") when state == "error". Empty for state != "error"
	// or for errored streams that did not surface a classifiable signal
	// (USK-797 makes this column visible to MCP clients).
	FailureReason string `json:"failure_reason,omitempty"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	// MessageCount is the number of canonical L7 semantic envelopes
	// recorded for the flow. Wire-level overlay rows (h2-frame,
	// h1-chunk, grpc-lpm-frame, grpcweb-base64) are excluded by default
	// — pass filter.wire_level="all" to include them, or one of the
	// overlay values to count only that overlay (USK-921).
	MessageCount    int               `json:"message_count"`
	BlockedBy       string            `json:"blocked_by,omitempty"`
	ProtocolSummary map[string]string `json:"protocol_summary,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	Anomalies       []queryAnomaly    `json:"anomalies,omitempty"`
	Timestamp       string            `json:"timestamp"`
	DurationMs      int64             `json:"duration_ms"`
	SendMs          *int64            `json:"send_ms,omitempty"`
	WaitMs          *int64            `json:"wait_ms,omitempty"`
	ReceiveMs       *int64            `json:"receive_ms,omitempty"`
}

// queryFlowsResult is the response for the flows resource.
type queryFlowsResult struct {
	Flows []queryFlowsEntry `json:"flows"`
	Count int               `json:"count"`
	Total int               `json:"total"`
	// WireLevelAdvisory carries a structured hint when the default
	// semantic wire_level filter hid overlay rows on the listed streams
	// AND the caller did NOT opt in via filter.wire_level. Counts are
	// summed across every Stream in the response so the operator-visible
	// inflation signal (per-Stream MessageCount) is matched at the
	// result level rather than per-row (USK-931).
	WireLevelAdvisory *wireLevelAdvisory `json:"wire_level_advisory,omitempty"`
}

// buildFlowListOptions constructs flow.StreamListOptions from query input parameters.
func buildFlowListOptions(input queryInput) flow.StreamListOptions {
	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := flow.StreamListOptions{
		Limit:  limit,
		Offset: input.Offset,
		SortBy: input.SortBy,
	}
	if input.Filter != nil {
		// Filter.Protocol accepts canonical Envelope.Protocol values only
		// (http, ws, grpc, grpc-web, sse, raw, tls-handshake). Unknown
		// values are rejected upstream by validateEnum.
		if p := input.Filter.Protocol; p != "" {
			opts.Protocol = p
		}
		opts.Scheme = input.Filter.Scheme
		opts.HTTPVersion = input.Filter.HTTPVersion
		opts.Method = input.Filter.Method
		opts.URLPattern = input.Filter.URLPattern
		opts.StatusCode = input.Filter.StatusCode
		opts.BlockedBy = input.Filter.BlockedBy
		opts.State = input.Filter.State
		opts.Origin = flow.Origin(input.Filter.Origin)
		opts.ConnID = input.Filter.ConnID
		opts.Host = input.Filter.Host
	}
	return opts
}

// extractFlowSummary extracts the effective method, URL, and status code from flow messages.
// It prefers "modified" variant messages as they represent the actually transmitted data.
func extractFlowSummary(msgs []*flow.Flow) (method, urlStr string, statusCode int) {
	for _, msg := range msgs {
		if msg.Direction == "send" {
			variant := msg.Metadata["variant"]
			if method == "" || variant == "modified" {
				method = msg.Method
				if msg.URL != nil {
					urlStr = msg.URL.String()
				}
			}
		}
		if msg.Direction == "receive" {
			variant := msg.Metadata["variant"]
			if statusCode == 0 || variant == "modified" {
				statusCode = msg.StatusCode
			}
		}
	}
	return method, urlStr, statusCode
}

// handleQueryFlows returns a paginated list of flows with message summary data.
func (s *Server) handleQueryFlows(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowsResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	opts := buildFlowListOptions(input)

	flowList, err := s.flowStore.store.ListStreams(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list flows: %w", err)
	}

	total, err := s.flowStore.store.CountStreams(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count flows: %w", err)
	}

	// USK-921: default to flow.WireLevelSemantic so per-flow MessageCount /
	// summary derivations only see canonical L7 envelopes — overlay rows
	// (h2-frame, h1-chunk, grpc-lpm-frame, grpcweb-base64) would otherwise
	// inflate message_count by 2-4x for gRPC / WS / SSE / gRPC-Web flows.
	// Callers opt in via filter.wire_level={overlay value | all}.
	wireLevel, err := resolveWireLevelFilter(input.Filter)
	if err != nil {
		return nil, nil, err
	}
	msgListOpts := flow.FlowListOptions{WireLevel: wireLevel}

	entries := make([]queryFlowsEntry, 0, len(flowList))
	// USK-931: accumulate overlay-row counts across every Stream in the
	// page so the result-level WireLevelAdvisory reflects the AI-visible
	// inflation signal (per-Stream MessageCount). Accept the N+1 cost
	// here per the design review — per-Stream MessageCount IS the
	// operator-visible signal that motivates the advisory.
	hiddenAggregate := map[string]int{}
	for _, fl := range flowList {
		// Fetch messages for method/url/status_code/message_count via JOIN data.
		msgs, err := s.flowStore.store.GetFlows(ctx, fl.ID, msgListOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("get messages for flow %s: %w", fl.ID, err)
		}

		method, urlStr, statusCode := extractFlowSummary(msgs)
		summary := buildProtocolSummary(fl.Protocol, msgs)

		entries = append(entries, queryFlowsEntry{
			ID:              fl.ID,
			Protocol:        fl.Protocol,
			Scheme:          fl.Scheme,
			State:           fl.State,
			FailureReason:   fl.FailureReason,
			Method:          method,
			URL:             urlStr,
			StatusCode:      statusCode,
			MessageCount:    len(msgs),
			BlockedBy:       fl.BlockedBy,
			ProtocolSummary: summary,
			Tags:            fl.Tags,
			// USK-849: merge the legacy stream-tag rollup with the
			// per-flow Metadata projection so HTTP / gRPC-Web / SSE
			// typed anomalies surface alongside the older smuggling:*
			// stream-tag path. Both inputs are deterministic-sorted; the
			// merge dedupes on Type.
			Anomalies:  mergeAnomalies(extractAnomalies(fl.Tags), extractAnomaliesFromFlows(msgs)),
			Timestamp:  fl.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			DurationMs: fl.Duration.Milliseconds(),
			SendMs:     fl.SendMs,
			WaitMs:     fl.WaitMs,
			ReceiveMs:  fl.ReceiveMs,
		})

		// USK-931: per-Stream overlay count contributes to the
		// result-level hidden map. Errors are non-fatal — the advisory
		// is informational and a failed sub-query should not block the
		// rest of the response.
		hidden, advisoryErr := s.collectHiddenOverlayCounts(ctx, fl.ID, flow.FlowListOptions{})
		if advisoryErr != nil {
			// Log + continue: do not block the AI agent from seeing
			// the listing because the advisory could not be computed.
			slog.DebugContext(ctx, "wire_level_advisory: hidden count failed",
				"flow_id", fl.ID, "error", advisoryErr)
			continue
		}
		for wl, n := range hidden {
			hiddenAggregate[wl] += n
		}
	}

	result := &queryFlowsResult{
		Flows:             entries,
		Count:             len(entries),
		Total:             total,
		WireLevelAdvisory: buildWireLevelAdvisory(input.Filter, hiddenAggregate),
	}
	return nil, result, nil
}

// --- flow resource ---

// queryFlowResult is the response for the flow resource.
type queryFlowResult struct {
	ID       string `json:"id"`
	ConnID   string `json:"conn_id"`
	Protocol string `json:"protocol"`
	Scheme   string `json:"scheme,omitempty"`
	// HTTPVersion is the wire-observed HTTP protocol version stamped on
	// the request flow (USK-788). Canonical lowercased values:
	// "http/1.0", "http/1.1", "h2", "h2c". Empty for non-HTTP flows and
	// for any pre-USK-788 stored row. Populated from the request-side
	// flow when present; otherwise from the response-side flow as a
	// fallback so observability holds even when the request is missing
	// (e.g. partial captures).
	HTTPVersion string `json:"http_version,omitempty"`
	State       string `json:"state"`
	// FailureReason carries the canonical layer.ErrorCode label
	// (refused / canceled / aborted / internal_error / protocol_error)
	// or one of the recorder-specific labels (e.g. "upstream_tls_error",
	// "client_tls_error") when state == "error". Empty otherwise. The
	// full err.Error() string for the same event is available under
	// tags["error"] (USK-797).
	FailureReason         string              `json:"failure_reason,omitempty"`
	Method                string              `json:"method"`
	URL                   string              `json:"url"`
	RequestHeaders        map[string][]string `json:"request_headers"`
	RequestBody           string              `json:"request_body"`
	RequestBodyEncoding   string              `json:"request_body_encoding"`
	ResponseStatusCode    int                 `json:"response_status_code"`
	ResponseHeaders       map[string][]string `json:"response_headers"`
	ResponseBody          string              `json:"response_body"`
	ResponseBodyEncoding  string              `json:"response_body_encoding"`
	RequestBodyTruncated  bool                `json:"request_body_truncated"`
	ResponseBodyTruncated bool                `json:"response_body_truncated"`
	// RequestBodyDecoded holds the request body after Content-Encoding decode
	// (gzip / deflate / br / zstd). Empty when decode is disabled, the body
	// has no Content-Encoding (or `identity`), or decode failed (see
	// RequestBodyDecodeAnomaly).
	RequestBodyDecoded string `json:"request_body_decoded,omitempty"`
	// RequestBodyDecodedEncoding is "text" or "base64" describing the
	// transport encoding of RequestBodyDecoded (matches RequestBodyEncoding
	// semantics).
	RequestBodyDecodedEncoding string `json:"request_body_decoded_encoding,omitempty"`
	// RequestBodyEncodingApplied names the codec applied (e.g. "gzip", "br").
	// Empty when no decode happened.
	RequestBodyEncodingApplied string `json:"request_body_encoding_applied,omitempty"`
	// RequestBodyDecodeAnomaly is set when Content-Encoding decode was
	// attempted but rejected or failed; the wire-form body is preserved in
	// RequestBody.
	RequestBodyDecodeAnomaly *queryDecodeAnomaly `json:"request_body_decode_anomaly,omitempty"`
	// ResponseBodyDecoded mirrors RequestBodyDecoded for the response side.
	ResponseBodyDecoded         string              `json:"response_body_decoded,omitempty"`
	ResponseBodyDecodedEncoding string              `json:"response_body_decoded_encoding,omitempty"`
	ResponseBodyEncodingApplied string              `json:"response_body_encoding_applied,omitempty"`
	ResponseBodyDecodeAnomaly   *queryDecodeAnomaly `json:"response_body_decode_anomaly,omitempty"`
	Timestamp                   string              `json:"timestamp"`
	DurationMs                  int64               `json:"duration_ms"`
	SendMs                      *int64              `json:"send_ms,omitempty"`
	WaitMs                      *int64              `json:"wait_ms,omitempty"`
	ReceiveMs                   *int64              `json:"receive_ms,omitempty"`
	Tags                        map[string]string   `json:"tags,omitempty"`
	Anomalies                   []queryAnomaly      `json:"anomalies,omitempty"`
	BlockedBy                   string              `json:"blocked_by,omitempty"`
	RawRequest                  string              `json:"raw_request,omitempty"`
	RawResponse                 string              `json:"raw_response,omitempty"`
	ConnInfo                    *connInfoResult     `json:"conn_info,omitempty"`
	// MessageCount is the number of canonical L7 semantic envelopes
	// recorded for the flow. Wire-level overlay rows (h2-frame,
	// h1-chunk, grpc-lpm-frame, grpcweb-base64) are excluded by default
	// — pass filter.wire_level="all" to include them, or one of the
	// overlay values to count only that overlay (USK-921). The same
	// filter governs which envelopes appear in MessagePreview.
	MessageCount    int                 `json:"message_count"`
	ProtocolSummary map[string]string   `json:"protocol_summary,omitempty"`
	MessagePreview  []queryMessageEntry `json:"message_preview,omitempty"`
	// OriginalRequest holds the original (pre-modification) request data
	// when a variant exists (intercept/transform modified the request).
	// Only populated when the flow contains variant messages.
	OriginalRequest *queryVariantRequest `json:"original_request,omitempty"`
	// OriginalResponse holds the original (pre-modification) response data
	// when a variant exists (intercept modified the response).
	// Only populated when the flow contains variant receive messages.
	OriginalResponse *queryVariantResponse `json:"original_response,omitempty"`

	// RequestBodyTruncatedByQuery / ResponseBodyTruncatedByQuery are set when
	// the response-time include_bodies / body_max_bytes params suppressed or
	// capped the bytes returned in request_body / response_body (or their
	// *_body_decoded siblings). This is distinct from the record-time
	// request_body_truncated / response_body_truncated flags above.
	RequestBodyTruncatedByQuery  bool `json:"request_body_truncated_by_query,omitempty"`
	ResponseBodyTruncatedByQuery bool `json:"response_body_truncated_by_query,omitempty"`
	// RequestBodyOriginalSize / ResponseBodyOriginalSize record the pre-truncation
	// byte length of the stored wire-form Body when the query-time cap fired.
	// Only emitted when the corresponding *_truncated_by_query is true.
	RequestBodyOriginalSize  int `json:"request_body_original_size,omitempty"`
	ResponseBodyOriginalSize int `json:"response_body_original_size,omitempty"`
	// RequestBodyDecodedOriginalSize / ResponseBodyDecodedOriginalSize record
	// the pre-truncation byte length of the decoded (post-Content-Encoding)
	// body. body_max_bytes is applied to body and body_decoded independently;
	// gzip / br can expand the decoded form well beyond the wire size.
	RequestBodyDecodedOriginalSize  int `json:"request_body_decoded_original_size,omitempty"`
	ResponseBodyDecodedOriginalSize int `json:"response_body_decoded_original_size,omitempty"`
	// Advisory carries a one-line hint when the caller did not pass either
	// include_bodies or body_max_bytes and the unbounded response contains a
	// body above oversizeAdvisoryThreshold. Empty otherwise.
	Advisory string `json:"advisory,omitempty"`
	// WireLevelAdvisory carries a structured hint when the default
	// semantic wire_level filter hid overlay rows on this Stream AND the
	// caller did NOT opt in via filter.wire_level. Sibling of Advisory —
	// additive, omitempty, does NOT mutate the existing oversize hint
	// (USK-931).
	WireLevelAdvisory *wireLevelAdvisory `json:"wire_level_advisory,omitempty"`
}

// queryDecodeAnomaly is a structured anomaly entry surfaced when
// Content-Encoding decode is rejected or fails. Wire-form bytes are always
// preserved in the sibling *_body field.
type queryDecodeAnomaly struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
}

// queryVariantRequest represents the original request before intercept/transform modification.
type queryVariantRequest struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
	// BodyTruncated mirrors Flow.BodyTruncated for the original send message —
	// set at record time when the pipeline RecordStep cap fired. Symmetric with
	// queryVariantResponse.BodyTruncated so the UI can render the modified-vs-
	// original diff without dropping the request-side truncation signal
	// (USK-965).
	BodyTruncated       bool                `json:"body_truncated"`
	BodyDecoded         string              `json:"body_decoded,omitempty"`
	BodyDecodedEncoding string              `json:"body_decoded_encoding,omitempty"`
	BodyEncodingApplied string              `json:"body_encoding_applied,omitempty"`
	BodyDecodeAnomaly   *queryDecodeAnomaly `json:"body_decode_anomaly,omitempty"`
}

// queryVariantResponse represents the original response before intercept modification.
type queryVariantResponse struct {
	StatusCode          int                 `json:"status_code"`
	Headers             map[string][]string `json:"headers"`
	Body                string              `json:"body"`
	BodyEncoding        string              `json:"body_encoding"`
	BodyTruncated       bool                `json:"body_truncated"`
	BodyDecoded         string              `json:"body_decoded,omitempty"`
	BodyDecodedEncoding string              `json:"body_decoded_encoding,omitempty"`
	BodyEncodingApplied string              `json:"body_encoding_applied,omitempty"`
	BodyDecodeAnomaly   *queryDecodeAnomaly `json:"body_decode_anomaly,omitempty"`
}

// streamPreviewLimit is the maximum number of messages to include in a streaming flow preview.
const streamPreviewLimit = 10

// categorizedMessages holds messages split by direction with variant resolution.
type categorizedMessages struct {
	// sendMsg is the effective send message (modified variant if present).
	sendMsg *flow.Flow
	// originalSendMsg is the original send message before modification (nil if no variant).
	originalSendMsg *flow.Flow
	// recvMsg is the effective receive message (modified variant if present).
	recvMsg *flow.Flow
	// originalRecvMsg is the original receive message before modification (nil if no variant).
	originalRecvMsg *flow.Flow
}

// categorizeMessages splits messages by direction and resolves variant pairs.
// For each direction, if multiple messages exist, the "modified" variant is the effective
// message and the "original" variant is preserved for diff display.
func categorizeMessages(msgs []*flow.Flow) categorizedMessages {
	var sendMsgs []*flow.Flow
	var recvMsgs []*flow.Flow
	for _, msg := range msgs {
		if msg.Direction == "send" {
			sendMsgs = append(sendMsgs, msg)
		}
		if msg.Direction == "receive" {
			recvMsgs = append(recvMsgs, msg)
		}
	}

	var result categorizedMessages
	result.sendMsg, result.originalSendMsg = resolveVariantPair(sendMsgs)
	result.recvMsg, result.originalRecvMsg = resolveVariantPair(recvMsgs)
	return result
}

// resolveHTTPVersion returns the wire-observed HTTP version for a flow
// detail projection (USK-788). The request flow is authoritative —
// downstream filters key on the request side; we fall back to the
// response flow only when the send side is missing or carries no
// HTTPVersion (partial capture / pre-USK-788 row). Empty result is the
// "unknown" sentinel and projects as the omitted JSON field.
func resolveHTTPVersion(cat categorizedMessages) string {
	if cat.sendMsg != nil && cat.sendMsg.HTTPVersion != "" {
		return cat.sendMsg.HTTPVersion
	}
	if cat.recvMsg != nil {
		return cat.recvMsg.HTTPVersion
	}
	return ""
}

// resolveVariantPair determines the effective and original messages from a slice of
// directional messages. If variants exist, "modified" is the effective message and
// "original" is preserved for diff display.
func resolveVariantPair(msgs []*flow.Flow) (effective, original *flow.Flow) {
	if len(msgs) == 0 {
		return nil, nil
	}
	if len(msgs) == 1 {
		return msgs[0], nil
	}
	for _, m := range msgs {
		variant := m.Metadata["variant"]
		if variant == "modified" {
			effective = m
		} else if variant == "original" {
			original = m
		}
	}
	// Fallback: if no variant metadata, use the last as effective and first as original.
	if effective == nil {
		effective = msgs[len(msgs)-1]
		original = msgs[0]
	}
	return effective, original
}

// decodedBodyView is the additive body-decoded form produced from a stored
// Flow.Body. The wire-form encoded fields (Body / BodyEncoding) are computed
// separately by encodeBody on the original (compressed) bytes and remain
// unchanged for backward compatibility (CLAUDE.md MITM principle #1).
type decodedBodyView struct {
	Body         string
	BodyEncoding string
	Applied      string
	Anomaly      *queryDecodeAnomaly
}

// findContentEncoding case-insensitively returns the first value of the
// Content-Encoding header from a flow's Headers map. Empty when absent.
func findContentEncoding(headers map[string][]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Encoding") && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// computeDecodedBodyWithLimit attempts to decode rawBody using the Content-Encoding
// header value, then applies SafetyFilter output masking on the plaintext —
// closing the bug where the masking step previously ran on compressed bytes
// that no PII regex could ever match. Returns the zero view when decode is
// disabled, the body has no Content-Encoding (or `identity`), rawBody is
// empty, or the decoded form would simply duplicate rawBody.
//
// When max > 0 and the decoded plaintext exceeds max bytes, the byte slice is
// truncated to max BEFORE base64 encoding so we never split mid-quadruple;
// originalSize reports the pre-truncation byte length. originalSize is zero
// when no truncation fired (caller treats zero as "not capped"). Decode
// anomalies behave identically to the unsized variant.
func (s *Server) computeDecodedBodyWithLimit(rawBody []byte, headers map[string][]string, decodeEnabled, truncated bool, max int) (view decodedBodyView, originalSize int) {
	if !decodeEnabled || len(rawBody) == 0 {
		return decodedBodyView{}, 0
	}
	contentEncoding := findContentEncoding(headers)
	decoded, applied, anomaly := bodydecode.Decode(rawBody, contentEncoding, bodydecode.DefaultMaxDecodedSize)
	if anomaly == nil && applied == "" {
		// identity / no CE: decoded form equals rawBody, so do not duplicate.
		return decodedBodyView{}, 0
	}
	if anomaly != nil {
		// Mid-stream truncation often manifests as a malformed gzip/zstd
		// tail. Reclassify so callers can distinguish a corrupted upstream
		// body from a truncated-at-storage condition.
		out := decodedBodyView{}
		if anomaly.Type == bodydecode.AnomalyMalformed && truncated {
			out.Anomaly = &queryDecodeAnomaly{
				Type:   "truncated_decode",
				Detail: "decode failed because body was truncated at storage time",
			}
		} else {
			out.Anomaly = &queryDecodeAnomaly{Type: anomaly.Type, Detail: anomaly.Detail}
		}
		return out, 0
	}
	masked := s.filterOutputBody(decoded)
	preSize := len(masked)
	capped, fired := limitBodyBytes(masked, max)
	bodyStr, bodyEnc := encodeBody(capped)
	out := decodedBodyView{
		Body:         bodyStr,
		BodyEncoding: bodyEnc,
		Applied:      applied,
	}
	if fired {
		return out, preSize
	}
	return out, 0
}

// isGRPCDataMessage reports whether the flow's metadata identifies it as a
// gRPC DATA envelope. Detection mirrors projectGRPCData in
// internal/pipeline/record_step.go which stamps grpc_event=data on every
// GRPCDataMessage flow. GRPCStart (headers) and GRPCEnd (trailers) carry
// different grpc_event values and are intentionally excluded — only Data
// envelopes hold proto wire bytes worth decoding into a schemaless JSON
// projection (USK-922).
func isGRPCDataMessage(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}
	return metadata["grpc_event"] == "data"
}

// computeDecodedGRPCBodyWithLimit decodes a gRPC Data envelope's stored
// payload. rawBody is the L7 payload — already decompressed and
// LPM-stripped at record time by projectGRPCData (record_step.go writes
// fl.Body = m.Payload). Do NOT pass Envelope.Raw / Flow.RawBytes here;
// those hold the wire-form LPM frame.
//
// direction is the recorded Flow.Direction ("send" or "receive") and
// selects which descriptor in the registered schema matches the wire
// bytes: send → input descriptor, receive → output descriptor. When
// direction is empty (legacy callers / synthetic envelopes), the input
// descriptor is tried first, then the output descriptor.
//
// USK-923 schema-aware path: when metadata carries grpc_service and
// grpc_method AND a matching schema is registered, the body is decoded
// via protoreflect.DynamicMessage + protojson with real field names
// (BodyEncoding="proto-json", Applied="proto-json"). On a schema-hit
// parse failure, the schemaless fallback still runs and a
// queryDecodeAnomaly{Type:"proto_schema_mismatch"} anomaly is attached.
//
// USK-922 schemaless path: when no schema matches OR the schema hit
// parse-failed, the body is decoded via internal/encoding/protobuf with
// the synthetic key shape "FFFF:OOOO:type"
// (BodyEncoding="proto-schemaless-json", Applied="proto-schemaless").
//
// In both cases the decoded JSON is masked via Output Filter
// (RFC-001 §3.7) and independently capped against body_max_bytes.
// Anomaly behaviour is preserved: malformed wire bytes (no schema or
// schemaless fallback fails too) surface queryDecodeAnomaly{Type:"proto_malformed"}.
func (s *Server) computeDecodedGRPCBodyWithLimit(rawBody []byte, metadata map[string]string, direction string, decodeEnabled bool, max int) (view decodedBodyView, originalSize int) {
	if !decodeEnabled || len(rawBody) == 0 {
		return decodedBodyView{}, 0
	}

	// Schema lookup by (service, method) from Flow.Metadata. Empty
	// strings fall through to the schemaless path immediately.
	service, method := grpcMethodFromMetadata(metadata)
	var schemaAnomaly *queryDecodeAnomaly
	if service != "" && method != "" {
		spec := s.lookupGRPCSchema(service, method)
		if spec != nil {
			primary, secondary := pickGRPCDescriptors(spec, direction)
			jsonStr, err := protoschema.Decode(rawBody, primary)
			if err != nil && secondary != nil {
				if alt, altErr := protoschema.Decode(rawBody, secondary); altErr == nil {
					jsonStr, err = alt, nil
				}
			}
			if err == nil {
				return s.finalizeDecodedGRPC([]byte(jsonStr), "proto-json", "proto-json", max)
			}
			schemaAnomaly = &queryDecodeAnomaly{Type: "proto_schema_mismatch", Detail: err.Error()}
		}
	}

	// Schemaless fallback. Either no schema is registered or the
	// schema-aware path failed; in the latter case we attach the
	// schema_mismatch anomaly so the caller sees both signals.
	jsonStr, err := protobuf.Decode(rawBody)
	if err != nil {
		v := decodedBodyView{
			Anomaly: &queryDecodeAnomaly{Type: "proto_malformed", Detail: err.Error()},
		}
		// Schema-hit-AND-schemaless-fail is rare in practice; surface
		// the schemaless error as the primary anomaly (callers care
		// about "can I see anything at all" first).
		return v, 0
	}
	out, preSize := s.finalizeDecodedGRPC([]byte(jsonStr), "proto-schemaless-json", "proto-schemaless", max)
	if schemaAnomaly != nil {
		out.Anomaly = schemaAnomaly
	}
	return out, preSize
}

// pickGRPCDescriptors selects the (primary, secondary) descriptor pair
// for a given recorded Flow.Direction. Send-direction data envelopes
// carry the RPC request, decoded against the method's input descriptor;
// receive-direction data envelopes carry the response, decoded against
// the output descriptor. Empty direction falls back to input-first.
func pickGRPCDescriptors(spec *protoschema.MethodSpec, direction string) (primary, secondary protoreflect.MessageDescriptor) {
	if direction == "receive" {
		return spec.OutputDesc, spec.InputDesc
	}
	return spec.InputDesc, spec.OutputDesc
}

// finalizeDecodedGRPC applies Output Filter masking, the body-max-bytes
// cap, and assembles the decodedBodyView. Shared by the schema-aware and
// schemaless gRPC decode paths.
func (s *Server) finalizeDecodedGRPC(plain []byte, bodyEncoding, applied string, max int) (decodedBodyView, int) {
	masked := s.filterOutputBody(plain)
	preSize := len(masked)
	capped, fired := limitBodyBytes(masked, max)
	out := decodedBodyView{
		Body:         string(capped),
		BodyEncoding: bodyEncoding,
		Applied:      applied,
	}
	if fired {
		return out, preSize
	}
	return out, 0
}

// grpcMethodFromMetadata extracts grpc_service and grpc_method from a
// flow's metadata. Returns empty strings when either is absent.
func grpcMethodFromMetadata(metadata map[string]string) (service, method string) {
	if metadata == nil {
		return "", ""
	}
	return metadata["grpc_service"], metadata["grpc_method"]
}

// lookupGRPCSchema returns the MethodSpec for (service, method) or nil
// when no schema is registered. nil-receiver-safe. Reads through
// grpcSchemaRegistry() so the pointer publication is synchronised with
// the Registry's lazy initialisation (USK-923 review F-2).
func (s *Server) lookupGRPCSchema(service, method string) *protoschema.MethodSpec {
	if s == nil {
		return nil
	}
	return s.grpcSchemaRegistry().LookupMethod(service, method)
}

// computeDecodedBodyForMessage dispatches between the HTTP Content-Encoding
// path (computeDecodedBodyWithLimit) and the gRPC proto path
// (computeDecodedGRPCBodyWithLimit) based on per-flow metadata. The gRPC
// branch fires for flows tagged grpc_event=data — i.e. native gRPC Data
// envelopes AND gRPC-Web Data envelopes (RFC-001 §3.2.3: gRPC-Web emits
// GRPCDataMessage via the same record_step path).
//
// direction is the recorded Flow.Direction; it picks the input vs output
// descriptor on the schema-aware gRPC path (USK-923). Empty for callers
// that have not threaded the direction through.
func (s *Server) computeDecodedBodyForMessage(rawBody []byte, headers map[string][]string, metadata map[string]string, direction string, decodeEnabled, truncated bool, max int) (view decodedBodyView, originalSize int) {
	if isGRPCDataMessage(metadata) {
		return s.computeDecodedGRPCBodyWithLimit(rawBody, metadata, direction, decodeEnabled, max)
	}
	return s.computeDecodedBodyWithLimit(rawBody, headers, decodeEnabled, truncated, max)
}

// resolveDecodeBodies returns the effective value of the decode_bodies query
// input flag, applying its default of true when omitted.
func resolveDecodeBodies(input queryInput) bool {
	if input.DecodeBodies == nil {
		return true
	}
	return *input.DecodeBodies
}

// resolveIncludeBodies returns the effective value of the include_bodies query
// input flag, applying its default of true when omitted. Mirrors
// manage.export_flows.include_bodies semantics.
func resolveIncludeBodies(input queryInput) bool {
	if input.IncludeBodies == nil {
		return true
	}
	return *input.IncludeBodies
}

// bodyLimitOptions carries the resolved include_bodies / body_max_bytes
// parameters threaded through the convert / handle paths.
type bodyLimitOptions struct {
	// includeBodies, when false, suppresses all body output fields and leaves
	// only metadata + headers + record-time truncation flags. Set the
	// per-entry body_truncated_by_query flag in that case.
	includeBodies bool
	// bodyMaxBytes, when > 0, caps the per-side body byte length. Applied to
	// the byte slice before base64 encoding (Q3) and to the decoded byte
	// slice independently (Q6). 0 means no cap.
	bodyMaxBytes int
	// explicitlyBounded reports whether the caller passed either size param
	// explicitly. Used to gate the Advisory hint.
	explicitlyBounded bool
}

// resolveBodyLimitOptions resolves include_bodies / body_max_bytes from the
// raw queryInput. explicitlyBounded tracks whether the caller explicitly
// passed either param so the Advisory hint can be suppressed.
func resolveBodyLimitOptions(input queryInput) bodyLimitOptions {
	return bodyLimitOptions{
		includeBodies:     resolveIncludeBodies(input),
		bodyMaxBytes:      input.BodyMaxBytes,
		explicitlyBounded: input.IncludeBodies != nil || input.BodyMaxBytes > 0,
	}
}

// limitBodyBytes returns the (possibly truncated) slice and a flag indicating
// whether the cap fired. When max <= 0 it is a no-op. The caller owns the
// pre-truncation length (len(b)) and is responsible for recording it on the
// response entry.
func limitBodyBytes(b []byte, max int) (out []byte, truncated bool) {
	if max <= 0 || len(b) <= max {
		return b, false
	}
	return b[:max], true
}

// buildOriginalRequest builds a queryVariantRequest from the original send message.
// Returns nil if originalMsg is nil. limit applies the same include_bodies /
// body_max_bytes semantics as the main flow body path.
func (s *Server) buildOriginalRequest(originalMsg *flow.Flow, decodeEnabled bool, limit bodyLimitOptions) *queryVariantRequest {
	if originalMsg == nil {
		return nil
	}
	var origURLStr string
	if originalMsg.URL != nil {
		origURLStr = originalMsg.URL.String()
	}
	v := &queryVariantRequest{
		Method:        originalMsg.Method,
		URL:           origURLStr,
		Headers:       originalMsg.Headers,
		BodyTruncated: originalMsg.BodyTruncated,
	}
	if !limit.includeBodies {
		// Bodies suppressed; leave Body / BodyEncoding / Body*Decoded zero.
		return v
	}
	capped, _ := limitBodyBytes(originalMsg.Body, limit.bodyMaxBytes)
	origBodyStr, origBodyEnc := encodeBody(capped)
	v.Body = origBodyStr
	v.BodyEncoding = origBodyEnc
	dec, _ := s.computeDecodedBodyForMessage(originalMsg.Body, originalMsg.Headers, originalMsg.Metadata, originalMsg.Direction, decodeEnabled, originalMsg.BodyTruncated, limit.bodyMaxBytes)
	v.BodyDecoded = dec.Body
	v.BodyDecodedEncoding = dec.BodyEncoding
	v.BodyEncodingApplied = dec.Applied
	v.BodyDecodeAnomaly = dec.Anomaly
	return v
}

// buildOriginalResponse builds a queryVariantResponse from the original receive message.
// Returns nil if originalMsg is nil. limit applies the same include_bodies /
// body_max_bytes semantics as the main flow body path.
func (s *Server) buildOriginalResponse(originalMsg *flow.Flow, decodeEnabled bool, limit bodyLimitOptions) *queryVariantResponse {
	if originalMsg == nil {
		return nil
	}
	v := &queryVariantResponse{
		StatusCode:    originalMsg.StatusCode,
		Headers:       originalMsg.Headers,
		BodyTruncated: originalMsg.BodyTruncated,
	}
	if !limit.includeBodies {
		// Bodies suppressed; leave Body / BodyEncoding / Body*Decoded zero.
		return v
	}
	capped, _ := limitBodyBytes(originalMsg.Body, limit.bodyMaxBytes)
	origBodyStr, origBodyEnc := encodeBody(capped)
	v.Body = origBodyStr
	v.BodyEncoding = origBodyEnc
	dec, _ := s.computeDecodedBodyForMessage(originalMsg.Body, originalMsg.Headers, originalMsg.Metadata, originalMsg.Direction, decodeEnabled, originalMsg.BodyTruncated, limit.bodyMaxBytes)
	v.BodyDecoded = dec.Body
	v.BodyDecodedEncoding = dec.BodyEncoding
	v.BodyEncodingApplied = dec.Applied
	v.BodyDecodeAnomaly = dec.Anomaly
	return v
}

// buildMessagePreview creates a preview of messages for streaming flows, limited to streamPreviewLimit.
func (s *Server) buildMessagePreview(msgs []*flow.Flow, decodeEnabled bool, limit bodyLimitOptions) []queryMessageEntry {
	previewLimit := streamPreviewLimit
	if previewLimit > len(msgs) {
		previewLimit = len(msgs)
	}
	return s.convertMessagesToEntries(msgs[:previewLimit], decodeEnabled, limit)
}

// handleQueryFlow returns detailed information about a single flow.
func (s *Server) handleQueryFlow(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for flow resource")
	}
	if input.BodyMaxBytes < 0 {
		return nil, nil, fmt.Errorf("body_max_bytes must be >= 0, got %d", input.BodyMaxBytes)
	}

	fl, err := s.flowStore.store.GetStream(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}
	// USK-921: default to flow.WireLevelSemantic so MessageCount /
	// message_preview only see canonical L7 envelopes — overlay rows
	// (h2-frame, h1-chunk, grpc-lpm-frame, grpcweb-base64) would
	// otherwise inflate the counts and the preview window for gRPC / WS
	// / SSE / gRPC-Web flows. Callers opt in via filter.wire_level=
	// {overlay value | all}.
	wireLevel, err := resolveWireLevelFilter(input.Filter)
	if err != nil {
		return nil, nil, err
	}
	msgs, err := s.flowStore.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{WireLevel: wireLevel})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	cat := categorizeMessages(msgs)
	decodeEnabled := resolveDecodeBodies(input)
	limit := resolveBodyLimitOptions(input)

	reqSide := s.projectFlowSide(cat.sendMsg, decodeEnabled, limit)
	respSide := s.projectFlowSide(cat.recvMsg, decodeEnabled, limit)

	connInfo := buildConnInfoResult(fl.ConnInfo)
	summary := buildProtocolSummary(fl.Protocol, msgs)

	result := &queryFlowResult{
		ID:                              fl.ID,
		ConnID:                          fl.ConnID,
		Protocol:                        fl.Protocol,
		Scheme:                          fl.Scheme,
		HTTPVersion:                     resolveHTTPVersion(cat),
		State:                           fl.State,
		FailureReason:                   fl.FailureReason,
		Method:                          reqSide.method,
		URL:                             reqSide.url,
		RequestHeaders:                  reqSide.headers,
		RequestBody:                     reqSide.bodyStr,
		RequestBodyEncoding:             reqSide.bodyEnc,
		RequestBodyDecoded:              reqSide.decoded.Body,
		RequestBodyDecodedEncoding:      reqSide.decoded.BodyEncoding,
		RequestBodyEncodingApplied:      reqSide.decoded.Applied,
		RequestBodyDecodeAnomaly:        reqSide.decoded.Anomaly,
		ResponseStatusCode:              respSide.statusCode,
		ResponseHeaders:                 respSide.headers,
		ResponseBody:                    respSide.bodyStr,
		ResponseBodyEncoding:            respSide.bodyEnc,
		ResponseBodyDecoded:             respSide.decoded.Body,
		ResponseBodyDecodedEncoding:     respSide.decoded.BodyEncoding,
		ResponseBodyEncodingApplied:     respSide.decoded.Applied,
		ResponseBodyDecodeAnomaly:       respSide.decoded.Anomaly,
		RequestBodyTruncated:            reqSide.recordTruncated,
		ResponseBodyTruncated:           respSide.recordTruncated,
		RequestBodyTruncatedByQuery:     reqSide.queryTruncated,
		ResponseBodyTruncatedByQuery:    respSide.queryTruncated,
		RequestBodyOriginalSize:         reqSide.originalSize,
		ResponseBodyOriginalSize:        respSide.originalSize,
		RequestBodyDecodedOriginalSize:  reqSide.decodedOriginalSize,
		ResponseBodyDecodedOriginalSize: respSide.decodedOriginalSize,
		Timestamp:                       fl.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs:                      fl.Duration.Milliseconds(),
		SendMs:                          fl.SendMs,
		WaitMs:                          fl.WaitMs,
		ReceiveMs:                       fl.ReceiveMs,
		Tags:                            fl.Tags,
		// USK-849: see handleQueryFlows comment — same rollup policy.
		Anomalies:        mergeAnomalies(extractAnomalies(fl.Tags), extractAnomaliesFromFlows(msgs)),
		BlockedBy:        fl.BlockedBy,
		RawRequest:       reqSide.rawStr,
		RawResponse:      respSide.rawStr,
		ConnInfo:         connInfo,
		MessageCount:     len(msgs),
		ProtocolSummary:  summary,
		OriginalRequest:  s.buildOriginalRequest(cat.originalSendMsg, decodeEnabled, limit),
		OriginalResponse: s.buildOriginalResponse(cat.originalRecvMsg, decodeEnabled, limit),
	}

	// Apply output filter to original request/response variants.
	s.filterOutputVariantRequest(result.OriginalRequest)
	s.filterOutputVariantResponse(result.OriginalResponse)

	// For streaming protocols, include a message preview instead of full request/response.
	// Streams with more than 2 flows are streaming (unary has exactly 1 send + 1 receive).
	if len(msgs) > 2 {
		result.MessagePreview = s.buildMessagePreview(msgs, decodeEnabled, limit)
		s.filterOutputMessages(result.MessagePreview)
	}

	// Advisory: emit only when the caller did not explicitly bound the
	// response and at least one stored body is above the heuristic threshold.
	if !limit.explicitlyBounded && flowHasOversizedBody(cat, msgs) {
		result.Advisory = oversizeAdvisoryMessage
	}

	// USK-931: surface the per-Stream overlay breakdown when the
	// semantic default suppressed any rows. The hidden map is empty
	// when the caller opted in (filter.wire_level != "") so the
	// advisory is suppressed by buildWireLevelAdvisory's first gate.
	hidden, advisoryErr := s.collectHiddenOverlayCounts(ctx, fl.ID, flow.FlowListOptions{})
	if advisoryErr != nil {
		slog.DebugContext(ctx, "wire_level_advisory: hidden count failed",
			"flow_id", fl.ID, "error", advisoryErr)
	} else {
		result.WireLevelAdvisory = buildWireLevelAdvisory(input.Filter, hidden)
	}

	return nil, result, nil
}

// flowSideProjection captures the per-side (send / receive) projection that
// handleQueryFlow needs after applying the include_bodies / body_max_bytes
// limits and the SafetyFilter masking. Extracted so handleQueryFlow stays
// under the gocyclo threshold.
type flowSideProjection struct {
	method, url         string
	statusCode          int
	headers             map[string][]string
	bodyStr, bodyEnc    string
	rawStr              string
	decoded             decodedBodyView
	recordTruncated     bool
	queryTruncated      bool
	originalSize        int
	decodedOriginalSize int
}

// projectFlowSide builds a flowSideProjection from a single send / receive
// message (nil-safe). It runs header / body / raw-bytes filtering, applies
// the response-time body limits, and decodes Content-Encoding into the
// additive decoded view. The returned headers map is never nil so the JSON
// projection serializes {} rather than null.
func (s *Server) projectFlowSide(msg *flow.Flow, decodeEnabled bool, limit bodyLimitOptions) flowSideProjection {
	out := flowSideProjection{headers: map[string][]string{}}
	if msg == nil {
		return out
	}
	out.method = msg.Method
	if msg.URL != nil {
		out.url = msg.URL.String()
	}
	out.statusCode = msg.StatusCode
	out.headers = map[string][]string(s.filterOutputHeaders(http.Header(msg.Headers)))
	if out.headers == nil {
		out.headers = map[string][]string{}
	}
	out.recordTruncated = msg.BodyTruncated

	if !limit.includeBodies {
		out.queryTruncated = true
		if n := len(msg.Body); n > 0 {
			out.originalSize = n
		}
		out.bodyStr, out.bodyEnc = "", ""
		return out
	}

	body := s.filterOutputBody(msg.Body)
	capped, fired := limitBodyBytes(body, limit.bodyMaxBytes)
	if fired {
		out.queryTruncated = true
		out.originalSize = len(body)
	}
	out.bodyStr, out.bodyEnc = encodeBody(capped)
	if len(msg.RawBytes) > 0 {
		out.rawStr = base64.StdEncoding.EncodeToString(s.filterOutputBody(msg.RawBytes))
	}
	// Decode against the original (pre-mask) body so the codec sees the real
	// wire bytes — the SafetyFilter on compressed bytes is a no-op today, but
	// if a future filter mutates them the decoder would fail. The dispatcher
	// routes gRPC Data envelopes (msg.Metadata["grpc_event"]=="data") through
	// the schemaless-proto path (USK-922) — or the schema-aware proto-json
	// path (USK-923) when a matching schema is registered — and everything
	// else through the Content-Encoding path.
	dec, decOrig := s.computeDecodedBodyForMessage(msg.Body, msg.Headers, msg.Metadata, msg.Direction, decodeEnabled, msg.BodyTruncated, limit.bodyMaxBytes)
	out.decoded = dec
	if decOrig > 0 {
		out.queryTruncated = true
		out.decodedOriginalSize = decOrig
	}
	return out
}

// buildConnInfoResult is the nil-safe ConnectionInfo → connInfoResult mapping
// shared by handleQueryFlow.
func buildConnInfoResult(ci *flow.ConnectionInfo) *connInfoResult {
	if ci == nil {
		return nil
	}
	return &connInfoResult{
		ClientAddr:           ci.ClientAddr,
		ServerAddr:           ci.ServerAddr,
		TLSVersion:           ci.TLSVersion,
		TLSCipher:            ci.TLSCipher,
		TLSALPN:              ci.TLSALPN,
		TLSServerCertSubject: ci.TLSServerCertSubject,
	}
}

// flowHasOversizedBody reports whether the categorized send/recv messages
// (request/response) or any per-message body in the streaming preview window
// carries a stored body larger than oversizeAdvisoryThreshold. Used to gate
// the Advisory hint on the flow resource.
func flowHasOversizedBody(cat categorizedMessages, msgs []*flow.Flow) bool {
	if cat.sendMsg != nil && len(cat.sendMsg.Body) > oversizeAdvisoryThreshold {
		return true
	}
	if cat.recvMsg != nil && len(cat.recvMsg.Body) > oversizeAdvisoryThreshold {
		return true
	}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		if len(m.Body) > oversizeAdvisoryThreshold || len(m.RawBytes) > oversizeAdvisoryThreshold {
			return true
		}
	}
	return false
}

// --- messages resource ---

// queryMessageEntry is a single message in the messages query response.
type queryMessageEntry struct {
	ID                  string              `json:"id"`
	Sequence            int                 `json:"sequence"`
	Direction           string              `json:"direction"`
	Method              string              `json:"method,omitempty"`
	URL                 string              `json:"url,omitempty"`
	StatusCode          int                 `json:"status_code,omitempty"`
	Headers             map[string][]string `json:"headers,omitempty"`
	Body                string              `json:"body"`
	BodyEncoding        string              `json:"body_encoding"`
	BodyDecoded         string              `json:"body_decoded,omitempty"`
	BodyDecodedEncoding string              `json:"body_decoded_encoding,omitempty"`
	BodyEncodingApplied string              `json:"body_encoding_applied,omitempty"`
	BodyDecodeAnomaly   *queryDecodeAnomaly `json:"body_decode_anomaly,omitempty"`
	// BodyTruncated mirrors Flow.BodyTruncated — set at record time when the
	// pipeline RecordStep cap fired. Distinct from BodyTruncatedByQuery.
	BodyTruncated bool `json:"body_truncated,omitempty"`
	// BodyTruncatedByQuery is set when the response-time include_bodies /
	// body_max_bytes params suppressed or capped Body / BodyDecoded.
	BodyTruncatedByQuery bool `json:"body_truncated_by_query,omitempty"`
	// BodyOriginalSize / BodyDecodedOriginalSize record the pre-truncation
	// byte lengths when the query-time cap fired on each side independently.
	BodyOriginalSize        int               `json:"body_original_size,omitempty"`
	BodyDecodedOriginalSize int               `json:"body_decoded_original_size,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
	// WireLevel mirrors flow.Flow.WireLevel — "semantic" for canonical
	// L7 envelopes, or one of the overlay discriminators (h2-frame,
	// h1-chunk, grpc-lpm-frame, grpcweb-base64) when the caller opted
	// in to overlay rows via filter.wire_level (USK-921). Omitted when
	// empty so the default semantic-only response stays compact.
	WireLevel string `json:"wire_level,omitempty"`
	Timestamp string `json:"timestamp"`
}

// queryMessagesResult is the response for the messages resource.
type queryMessagesResult struct {
	Messages []queryMessageEntry `json:"messages"`
	Count    int                 `json:"count"`
	Total    int                 `json:"total"`
	// Advisory carries a one-line hint when the caller did not pass either
	// include_bodies or body_max_bytes and the unbounded response contains a
	// message body above oversizeAdvisoryThreshold. Empty otherwise.
	Advisory string `json:"advisory,omitempty"`
	// WireLevelAdvisory carries a structured hint when the default
	// semantic wire_level filter hid overlay rows on the paged Stream
	// AND the caller did NOT opt in via filter.wire_level (USK-931).
	WireLevelAdvisory *wireLevelAdvisory `json:"wire_level_advisory,omitempty"`
}

// convertMessagesToEntries converts flow messages to queryMessageEntry slice.
// It uses Body for text content and falls back to RawBytes for binary protocols.
// When decodeEnabled is true, HTTP Content-Encoding (gzip/br/deflate/zstd) is
// decoded into the additive *_decoded fields; the wire-form body in `body`
// is preserved unchanged.
//
// limit gates response-time body suppression / truncation: include_bodies=false
// drops all body fields and sets body_truncated_by_query=true with the original
// byte length; body_max_bytes=N caps the byte slice before base64 encoding so
// the response never splits mid-quadruple. Decoded body is capped independently
// (gzip / br plaintext can far exceed wire size).
func (s *Server) convertMessagesToEntries(msgs []*flow.Flow, decodeEnabled bool, limit bodyLimitOptions) []queryMessageEntry {
	entries := make([]queryMessageEntry, 0, len(msgs))
	for _, msg := range msgs {
		bodyData := msg.Body
		usedRawBytes := false
		if len(bodyData) == 0 && len(msg.RawBytes) > 0 {
			bodyData = msg.RawBytes
			usedRawBytes = true
		}

		var urlStr string
		if msg.URL != nil {
			urlStr = msg.URL.String()
		}

		entry := queryMessageEntry{
			ID:         msg.ID,
			Sequence:   msg.Sequence,
			Direction:  msg.Direction,
			Method:     msg.Method,
			URL:        urlStr,
			StatusCode: msg.StatusCode,
			Headers:    msg.Headers,
			// body_truncated mirrors record-time Flow.BodyTruncated and is
			// always populated independently of the response-time limit
			// params so callers can tell the two truncation classes apart.
			BodyTruncated: msg.BodyTruncated,
			Metadata:      msg.Metadata,
			// USK-921: surface the wire_level discriminator so callers
			// who opted in to overlay rows (filter.wire_level=h2-frame /
			// grpc-lpm-frame / ...) can tell which framing view each
			// entry represents. Default-semantic responses get an empty
			// string here and the field omits from JSON via omitempty.
			WireLevel: nonSemanticWireLevel(msg.WireLevel),
			Timestamp: msg.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		}

		switch {
		case !limit.includeBodies:
			// include_bodies=false: drop every body field but record the
			// original byte length so the caller knows what was suppressed.
			entry.BodyTruncatedByQuery = true
			if len(bodyData) > 0 {
				entry.BodyOriginalSize = len(bodyData)
			}
		default:
			capped, fired := limitBodyBytes(bodyData, limit.bodyMaxBytes)
			if fired {
				entry.BodyTruncatedByQuery = true
				entry.BodyOriginalSize = len(bodyData)
			}
			bodyStr, bodyEnc := encodeBody(capped)
			entry.Body = bodyStr
			entry.BodyEncoding = bodyEnc
			// Only decode the L7-parsed Body. RawBytes are wire bytes and must
			// not be reinterpreted (Content-Encoding decoding presumes the
			// parser has already extracted the L7 payload). gRPC Data envelopes
			// route through computeDecodedBodyForMessage to surface the proto
			// wire bytes as schemaless JSON (USK-922).
			if !usedRawBytes {
				dec, decOriginal := s.computeDecodedBodyForMessage(msg.Body, msg.Headers, msg.Metadata, msg.Direction, decodeEnabled, msg.BodyTruncated, limit.bodyMaxBytes)
				entry.BodyDecoded = dec.Body
				entry.BodyDecodedEncoding = dec.BodyEncoding
				entry.BodyEncodingApplied = dec.Applied
				entry.BodyDecodeAnomaly = dec.Anomaly
				if decOriginal > 0 {
					entry.BodyTruncatedByQuery = true
					entry.BodyDecodedOriginalSize = decOriginal
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// buildMessageListOptions validates and builds message list options from query input.
// Returns an error if the direction or wire_level filter value is invalid.
//
// USK-921: when filter.wire_level is empty / unset, the resolver injects
// flow.WireLevelSemantic so the default messages response hides wire-level
// overlay rows (h2-frame, h1-chunk, grpc-lpm-frame, grpcweb-base64). Pass
// filter.wire_level="all" to receive every wire_level, or one of the
// overlay values to isolate a single diagnostic view.
func buildMessageListOptions(input queryInput) (flow.FlowListOptions, error) {
	opts := flow.FlowListOptions{}
	if input.Filter != nil && input.Filter.Direction != "" {
		if input.Filter.Direction != "send" && input.Filter.Direction != "receive" {
			return opts, fmt.Errorf("direction filter must be \"send\" or \"receive\", got %q", input.Filter.Direction)
		}
		opts.Direction = input.Filter.Direction
	}
	wireLevel, err := resolveWireLevelFilter(input.Filter)
	if err != nil {
		return opts, err
	}
	opts.WireLevel = wireLevel
	return opts, nil
}

// paginateMessages applies offset and limit to a message slice, returning the page.
func paginateMessages(msgs []*flow.Flow, offset, limit int) []*flow.Flow {
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	if offset > len(msgs) {
		offset = len(msgs)
	}
	end := offset + limit
	if end > len(msgs) {
		end = len(msgs)
	}
	return msgs[offset:end]
}

// handleQueryMessages returns paginated messages for a flow.
func (s *Server) handleQueryMessages(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryMessagesResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for messages resource")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}
	if input.BodyMaxBytes < 0 {
		return nil, nil, fmt.Errorf("body_max_bytes must be >= 0, got %d", input.BodyMaxBytes)
	}

	// Verify the flow exists and resolve prefix IDs.
	fl, err := s.flowStore.store.GetStream(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	// Get total message count for pagination.
	total, err := s.flowStore.store.CountFlows(ctx, fl.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("count messages: %w", err)
	}

	msgOpts, err := buildMessageListOptions(input)
	if err != nil {
		return nil, nil, err
	}

	allMsgs, err := s.flowStore.store.GetFlows(ctx, fl.ID, msgOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	// Use filtered count as total for pagination when direction or
	// wire_level filtering reduced the result set (USK-921: the
	// flow.CountFlows aggregate returns every wire_level row but the
	// MCP default filter is "semantic"; without this branch the Total
	// field would over-report by the overlay-row count).
	filteredTotal := total
	if msgOpts.Direction != "" || msgOpts.WireLevel != "" {
		filteredTotal = len(allMsgs)
	}

	pageMsgs := paginateMessages(allMsgs, input.Offset, input.Limit)
	limit := resolveBodyLimitOptions(input)
	entries := s.convertMessagesToEntries(pageMsgs, resolveDecodeBodies(input), limit)

	// Apply SafetyFilter output masking to message bodies and headers.
	s.filterOutputMessages(entries)

	result := &queryMessagesResult{
		Messages: entries,
		Count:    len(entries),
		Total:    filteredTotal,
	}

	// Advisory: emit only when the caller did not explicitly bound the
	// response and at least one body in the page exceeded the threshold.
	if !limit.explicitlyBounded && messagesHaveOversizedBody(pageMsgs) {
		result.Advisory = oversizeAdvisoryMessage
	}

	// USK-931: scope the overlay-count to the same direction filter the
	// caller applied to the page so the advisory reflects what was
	// actually suppressed. msgOpts.Direction may be empty (count both
	// sides), "send", or "receive".
	hidden, advisoryErr := s.collectHiddenOverlayCounts(ctx, fl.ID, flow.FlowListOptions{Direction: msgOpts.Direction})
	if advisoryErr != nil {
		slog.DebugContext(ctx, "wire_level_advisory: hidden count failed",
			"flow_id", fl.ID, "error", advisoryErr)
	} else {
		result.WireLevelAdvisory = buildWireLevelAdvisory(input.Filter, hidden)
	}

	return nil, result, nil
}

// messagesHaveOversizedBody reports whether any message in the page carries a
// stored Body (or RawBytes fallback for binary protocols) above
// oversizeAdvisoryThreshold. Used to gate the Advisory hint on the messages
// resource.
func messagesHaveOversizedBody(msgs []*flow.Flow) bool {
	for _, m := range msgs {
		if m == nil {
			continue
		}
		if len(m.Body) > oversizeAdvisoryThreshold || len(m.RawBytes) > oversizeAdvisoryThreshold {
			return true
		}
	}
	return false
}

// --- status resource ---

// queryListenerStatusEntry is a single listener entry in the status response.
//
// UpstreamProxy (USK-826) carries the redacted per-listener upstream-proxy
// URL; an empty string means "direct dial" or "inherits the global / boot-time
// fallback". Multi-listener chained MITM is the canonical multi-value case.
type queryListenerStatusEntry struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	UpstreamProxy     string `json:"upstream_proxy,omitempty"`
}

// queryStatusResult is the response for the status resource.
type queryStatusResult struct {
	Running           bool                       `json:"running"`
	ListenAddr        string                     `json:"listen_addr"`
	Listeners         []queryListenerStatusEntry `json:"listeners,omitempty"`
	ListenerCount     int                        `json:"listener_count"`
	UpstreamProxy     string                     `json:"upstream_proxy"`
	ActiveConnections int                        `json:"active_connections"`
	MaxConnections    int                        `json:"max_connections"`
	PeekTimeoutMs     int64                      `json:"peek_timeout_ms"`
	RequestTimeoutMs  int64                      `json:"request_timeout_ms"`
	TotalFlows        int                        `json:"total_flows"`
	DBSizeBytes       int64                      `json:"db_size_bytes"`
	UptimeSeconds     int64                      `json:"uptime_seconds"`
	CAInitialized     bool                       `json:"ca_initialized"`
	SOCKS5Enabled     bool                       `json:"socks5_enabled"`
	SOCKS5Auth        string                     `json:"socks5_auth,omitempty"`
	TLSFingerprint    string                     `json:"tls_fingerprint"`
	RateLimits        *queryRateLimitStatus      `json:"rate_limits,omitempty"`
	Budget            *queryBudgetStatus         `json:"budget,omitempty"`
}

// queryRateLimitStatus holds rate limit information for the status response.
type queryRateLimitStatus struct {
	Effective connector.RateLimitConfig `json:"effective"`
	Enabled   bool                      `json:"enabled"`
}

// queryBudgetStatus holds budget information for the status response.
type queryBudgetStatus struct {
	Effective    connector.BudgetConfig `json:"effective"`
	Enabled      bool                   `json:"enabled"`
	RequestCount int64                  `json:"request_count"`
	StopReason   string                 `json:"stop_reason,omitempty"`
}

// populateManagerStatus fills manager-related fields in the status result.
func (s *Server) populateManagerStatus(result *queryStatusResult) {
	if managerIsNil(s.connector.manager) {
		return
	}
	running, addr := s.connector.manager.Status()
	result.Running = running
	result.ListenAddr = addr
	result.UpstreamProxy = connector.RedactProxyURL(s.connector.manager.UpstreamProxy())
	result.ActiveConnections = s.connector.manager.ActiveConnections()
	result.MaxConnections = s.connector.manager.MaxConnections()
	result.PeekTimeoutMs = s.connector.manager.PeekTimeout().Milliseconds()
	result.UptimeSeconds = int64(s.connector.manager.Uptime().Seconds())
	result.ListenerCount = s.connector.manager.ListenerCount()

	// Populate per-listener statuses.
	statuses := listenerStatuses(s.connector.manager)
	if len(statuses) > 0 {
		result.Listeners = make([]queryListenerStatusEntry, 0, len(statuses))
		for _, st := range statuses {
			// USK-826: redact per-listener upstream_proxy at publish time
			// (the manager keeps the raw form for in-process inspection).
			entry := queryListenerStatusEntry{
				Name:              st.Name,
				ListenAddr:        st.ListenAddr,
				ActiveConnections: st.ActiveConnections,
				UptimeSeconds:     st.UptimeSeconds,
				UpstreamProxy:     connector.RedactProxyURL(st.UpstreamProxy),
			}
			result.Listeners = append(result.Listeners, entry)
		}
		// Update Running to true if any listener is running (not just default).
		if !result.Running && len(statuses) > 0 {
			result.Running = true
		}
	}
}

// handleQueryStatus returns the current proxy status and health metrics.
func (s *Server) handleQueryStatus(ctx context.Context) (*gomcp.CallToolResult, *queryStatusResult, error) {
	result := &queryStatusResult{
		DBSizeBytes: -1,
	}

	s.populateManagerStatus(result)

	// Report request timeout from the first registered handler.
	if rt := s.currentRequestTimeout(); rt > 0 {
		result.RequestTimeoutMs = rt.Milliseconds()
	} else {
		// Default request timeout when no handler is registered.
		result.RequestTimeoutMs = defaultRequestTimeoutMs
	}

	if s.flowStore.store != nil {
		count, err := s.flowStore.store.CountStreams(ctx, flow.StreamListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("count flows: %w", err)
		}
		result.TotalFlows = count
	}

	if s.misc.dbPath != "" {
		info, err := os.Stat(s.misc.dbPath)
		if err == nil {
			result.DBSizeBytes = info.Size()
		}
	}

	if s.misc.ca != nil && s.misc.ca.Certificate() != nil {
		result.CAInitialized = true
	}

	// SOCKS5 availability: when the setter exposes the runtime-state
	// extension (USK-770), report whether any authenticator is currently
	// configured (global or per-listener). Older setters without the
	// extension surface "is the wire-up present" — preserves the legacy
	// reading for tests that inject a stub.
	if s.connector.socks5AuthSetter != nil {
		if q, ok := s.connector.socks5AuthSetter.(socks5AuthQuerier); ok {
			result.SOCKS5Enabled = q.HasAnyAuth()
		} else {
			result.SOCKS5Enabled = true
		}
	}

	result.TLSFingerprint = s.currentTLSFingerprint()

	if s.misc.rateLimiter != nil {
		effective := s.misc.rateLimiter.EffectiveLimits()
		result.RateLimits = &queryRateLimitStatus{
			Effective: effective,
			Enabled:   s.misc.rateLimiter.HasLimits(),
		}
	}

	if s.misc.budgetManager != nil {
		effective := s.misc.budgetManager.EffectiveBudget()
		result.Budget = &queryBudgetStatus{
			Effective:    effective,
			Enabled:      s.misc.budgetManager.HasBudget(),
			RequestCount: s.misc.budgetManager.RequestCount(),
			StopReason:   s.misc.budgetManager.ShutdownReason(),
		}
	}

	return nil, result, nil
}

// --- config resource ---

// queryConfigResult is the response for the config resource.
type queryConfigResult struct {
	UpstreamProxy    string                           `json:"upstream_proxy"`
	TLSPassthrough   *queryPassthroughResult          `json:"tls_passthrough"`
	TCPForwards      map[string]*config.ForwardConfig `json:"tcp_forwards,omitempty"`
	SOCKS5Enabled    bool                             `json:"socks5_enabled"`
	ClientCert       *queryClientCertResult           `json:"client_cert,omitempty"`
	SafetyFilter     *querySafetyFilterResult         `json:"safety_filter,omitempty"`
	MaxConnections   int                              `json:"max_connections"`
	PeekTimeoutMs    int64                            `json:"peek_timeout_ms"`
	RequestTimeoutMs int64                            `json:"request_timeout_ms"`
	TLSFingerprint   string                           `json:"tls_fingerprint"`
	// MaxRawCaptureSize echoes the per-message HTTP/1.x raw-bytes capture
	// cap configured via Config.MaxRawCaptureSize (USK-800). Zero / omitted
	// means the layer default (config.DefaultMaxRawCaptureSize, 2 MiB) is
	// in effect. First protocol-layer cap exposed via this resource;
	// USK-807 added the remaining seven caps (max_body_size,
	// body_spill_threshold, body_spill_dir, ws_max_frame_size,
	// grpc_max_message_size, sse_max_event_size,
	// grpc_max_messages_per_stream, sse_max_events_per_stream) so the
	// introspection surface is now uniform.
	MaxRawCaptureSize int64 `json:"max_raw_capture_size,omitempty"`
	// MaxBodySize echoes the absolute body-size cap configured via
	// Config.MaxBodySize (USK-799 / USK-807). Zero / omitted means the
	// layer default (config.MaxBodySize, 254 MiB) is in effect.
	MaxBodySize int64 `json:"max_body_size,omitempty"`
	// BodySpillThreshold echoes the body memory→disk spill threshold
	// configured via Config.BodySpillThreshold (USK-807). Zero / omitted
	// means the layer default (config.DefaultBodySpillThreshold, 10 MiB)
	// is in effect.
	BodySpillThreshold int64 `json:"body_spill_threshold,omitempty"`
	// BodySpillDir echoes the directory used for body-spill temp files,
	// configured via Config.BodySpillDir (USK-807). Empty / omitted means
	// the bodybuf package falls back to os.TempDir() — that is the
	// resolver default and a normal operating mode, not a missing value.
	BodySpillDir string `json:"body_spill_dir,omitempty"`
	// WSMaxFrameSize echoes the per-frame WebSocket payload cap
	// configured via Config.WebSocket (USK-807). Zero / omitted means the
	// layer default (config.MaxWebSocketFrameSize, 16 MiB) is in effect.
	WSMaxFrameSize int64 `json:"ws_max_frame_size,omitempty"`
	// GRPCMaxMessageSize echoes the per-LPM gRPC / gRPC-Web payload cap
	// configured via Config.GRPC (USK-807). Zero / omitted means the
	// layer default (config.MaxGRPCMessageSize, 254 MiB) is in effect.
	GRPCMaxMessageSize uint32 `json:"grpc_max_message_size,omitempty"`
	// SSEMaxEventSize echoes the per-event SSE raw-byte cap configured
	// via Config.SSE (USK-807). Zero / omitted means the layer default is
	// in effect.
	SSEMaxEventSize int `json:"sse_max_event_size,omitempty"`
	// GRPCMaxMessagesPerStream echoes the per-stream RecordStep cap on
	// GRPCDataMessage envelopes configured via Config.GRPC (USK-802 /
	// USK-807). Zero / omitted means the RecordStep default
	// (config.MaxGRPCMessagesPerStream, 10000) is in effect.
	GRPCMaxMessagesPerStream int `json:"grpc_max_messages_per_stream,omitempty"`
	// SSEMaxEventsPerStream echoes the per-stream RecordStep cap on
	// SSEMessage envelopes configured via Config.SSE (USK-802 / USK-807).
	// Zero / omitted means the RecordStep default
	// (config.MaxSSEEventsPerStream, 100000) is in effect.
	SSEMaxEventsPerStream int `json:"sse_max_events_per_stream,omitempty"`
	// CaptureScope echoes the current recording-only observability
	// filter (USK-776). Always present (an empty struct means
	// "capture every flow"). target_scope is intentionally NOT
	// echoed here — that surface is owned by the `security` MCP tool
	// (different lifecycle and audit semantics).
	CaptureScope *queryCaptureScopeResult `json:"capture_scope"`
}

// queryCaptureScopeResult is the JSON shape returned for the
// capture_scope field of the config resource. Includes / Excludes are
// always non-nil arrays so the field shape is stable for clients.
type queryCaptureScopeResult struct {
	Includes []scopeRuleInput `json:"includes"`
	Excludes []scopeRuleInput `json:"excludes"`
}

// querySafetyFilterResult holds SafetyFilter status in the config response.
type querySafetyFilterResult struct {
	Enabled     bool `json:"enabled"`
	InputRules  int  `json:"input_rules"`
	OutputRules int  `json:"output_rules"`
}

// queryClientCertResult holds client certificate info in the config response.
type queryClientCertResult struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// queryPassthroughResult holds TLS passthrough patterns in the config response.
type queryPassthroughResult struct {
	Patterns []string `json:"patterns"`
	Count    int      `json:"count"`
}

// handleQueryConfig returns the current configuration (TLS passthrough + connector knobs).
func (s *Server) handleQueryConfig() (*gomcp.CallToolResult, *queryConfigResult, error) {
	result := &queryConfigResult{}

	if !managerIsNil(s.connector.manager) {
		result.UpstreamProxy = connector.RedactProxyURL(s.connector.manager.UpstreamProxy())
	}

	if s.connector.passthrough != nil {
		patterns := s.connector.passthrough.List()
		sort.Strings(patterns)
		result.TLSPassthrough = &queryPassthroughResult{
			Patterns: patterns,
			Count:    len(patterns),
		}
	} else {
		result.TLSPassthrough = &queryPassthroughResult{
			Patterns: []string{},
			Count:    0,
		}
	}

	if len(s.connector.tcpForwards) > 0 {
		result.TCPForwards = s.connector.tcpForwards
	}

	if s.connector.socks5AuthSetter != nil {
		if q, ok := s.connector.socks5AuthSetter.(socks5AuthQuerier); ok {
			result.SOCKS5Enabled = q.HasAnyAuth()
		} else {
			result.SOCKS5Enabled = true
		}
	}

	certPath, keyPath := s.currentClientCert()
	if certPath != "" {
		result.ClientCert = &queryClientCertResult{
			CertPath: certPath,
			KeyPath:  keyPath,
		}
	}

	if s.pipeline.safetyEngine != nil {
		result.SafetyFilter = &querySafetyFilterResult{
			Enabled:     true,
			InputRules:  len(s.pipeline.safetyEngine.InputRules()),
			OutputRules: len(s.pipeline.safetyEngine.OutputRules()),
		}
	} else {
		result.SafetyFilter = &querySafetyFilterResult{
			Enabled: false,
		}
	}

	if !managerIsNil(s.connector.manager) {
		result.MaxConnections = s.connector.manager.MaxConnections()
		result.PeekTimeoutMs = s.connector.manager.PeekTimeout().Milliseconds()
		result.MaxRawCaptureSize = s.connector.manager.MaxRawCaptureSize()
		result.MaxBodySize = s.connector.manager.MaxBodySize()
		result.BodySpillThreshold = s.connector.manager.BodySpillThreshold()
		result.BodySpillDir = s.connector.manager.BodySpillDir()
		result.WSMaxFrameSize = s.connector.manager.WSMaxFrameSize()
		result.GRPCMaxMessageSize = s.connector.manager.GRPCMaxMessageSize()
		result.SSEMaxEventSize = s.connector.manager.SSEMaxEventSize()
		result.GRPCMaxMessagesPerStream = s.connector.manager.GRPCMaxMessagesPerStream()
		result.SSEMaxEventsPerStream = s.connector.manager.SSEMaxEventsPerStream()
	}

	if rt := s.currentRequestTimeout(); rt > 0 {
		result.RequestTimeoutMs = rt.Milliseconds()
	} else {
		// Default request timeout when no handler is registered.
		result.RequestTimeoutMs = defaultRequestTimeoutMs
	}

	result.TLSFingerprint = s.currentTLSFingerprint()
	result.CaptureScope = s.currentCaptureScope()

	return nil, result, nil
}

// currentCaptureScope returns a JSON-friendly snapshot of the active
// capture-scope filter (USK-776). Always returns a non-nil result so
// the response shape is stable; an unconfigured scope yields empty
// arrays.
func (s *Server) currentCaptureScope() *queryCaptureScopeResult {
	out := &queryCaptureScopeResult{
		Includes: []scopeRuleInput{},
		Excludes: []scopeRuleInput{},
	}
	if s.flowStore == nil || s.flowStore.recordScope == nil {
		return out
	}
	includes, excludes := s.flowStore.recordScope.Rules()
	out.Includes = scopeRulesInputFromFlow(includes)
	out.Excludes = scopeRulesInputFromFlow(excludes)
	return out
}

// --- ca_cert resource ---

// queryCACertResult is the response for the ca_cert resource.
type queryCACertResult struct {
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Persisted   bool   `json:"persisted"`
	CertPath    string `json:"cert_path,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
}

// handleQueryCACert returns the CA certificate PEM and metadata.
func (s *Server) handleQueryCACert() (*gomcp.CallToolResult, *queryCACertResult, error) {
	if s.misc.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized: no CA has been configured for this server")
	}

	cert := s.misc.ca.Certificate()
	if cert == nil {
		return nil, nil, fmt.Errorf("CA certificate is not available: CA has not been generated or loaded")
	}

	certPEM := s.misc.ca.CertPEM()
	if certPEM == nil {
		return nil, nil, fmt.Errorf("CA certificate PEM is not available")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	source := s.misc.ca.Source()
	result := &queryCACertResult{
		PEM:         string(certPEM),
		Fingerprint: fingerprintHex,
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Persisted:   source.Persisted,
		CertPath:    source.CertPath,
	}

	if source.Persisted && source.CertPath != "" {
		result.InstallHint = "Install the CA certificate from " + source.CertPath + " into your OS/browser trust store for HTTPS interception"
	}

	return nil, result, nil
}

// --- intercept_queue resource ---

// queryInterceptQueueEntry is a single entry in the intercept queue query
// response. The shape mirrors the held envelope: a per-Message-type union
// (HTTP / WS / GRPCStart / GRPCData / GRPCEnd / Raw) plus the wire-bytes
// snapshot. Headers are projected as ordered []headerKV (RFC-001
// wire-fidelity, no map normalization).
type queryInterceptQueueEntry struct {
	// ID is the held envelope's unique identifier.
	ID string `json:"id"`
	// Protocol discriminates the populated per-Message-type field.
	// One of: http, websocket, grpc_start, grpc_data, grpc_end, raw, unknown.
	Protocol string `json:"protocol"`
	// Direction is the envelope direction: "send" or "receive".
	Direction string `json:"direction"`
	// HeldAt is the ISO-8601 timestamp when the envelope was held.
	HeldAt string `json:"held_at"`
	// MatchedRules lists the rule IDs that matched.
	MatchedRules []string `json:"matched_rules,omitempty"`
	// FlowID identifies the per-stream flow on the held envelope.
	FlowID string `json:"flow_id,omitempty"`
	// StreamID identifies the multiplexed stream on the held envelope.
	StreamID string `json:"stream_id,omitempty"`

	// Per-protocol union — exactly one is non-nil, matching Protocol.
	HTTP      *httpEntryView      `json:"http,omitempty"`
	WS        *wsEntryView        `json:"ws,omitempty"`
	GRPCStart *grpcStartEntryView `json:"grpc_start,omitempty"`
	GRPCData  *grpcDataEntryView  `json:"grpc_data,omitempty"`
	GRPCEnd   *grpcEndEntryView   `json:"grpc_end,omitempty"`
	Raw       *rawEntryView       `json:"raw,omitempty"`

	// Wire-bytes snapshot from Envelope.Raw.
	RawBytesAvailable bool   `json:"raw_bytes_available"`
	RawBytesSize      int    `json:"raw_bytes_size,omitempty"`
	RawBytesEncoding  string `json:"raw_bytes_encoding,omitempty"`
	RawBytes          string `json:"raw_bytes,omitempty"`
}

// httpEntryView is the per-entry projection of an HTTPMessage envelope.
// Headers and Trailers are order- and case-preserved per RFC-001.
type httpEntryView struct {
	Method       string     `json:"method,omitempty"`
	Scheme       string     `json:"scheme,omitempty"`
	Authority    string     `json:"authority,omitempty"`
	Path         string     `json:"path,omitempty"`
	RawQuery     string     `json:"raw_query,omitempty"`
	Status       int        `json:"status,omitempty"`
	StatusReason string     `json:"status_reason,omitempty"`
	Headers      []headerKV `json:"headers,omitempty"`
	Trailers     []headerKV `json:"trailers,omitempty"`
	BodyEncoding string     `json:"body_encoding,omitempty"`
	Body         string     `json:"body,omitempty"`
}

// wsEntryView is the per-entry projection of a WSMessage envelope.
type wsEntryView struct {
	Opcode          string `json:"opcode,omitempty"`
	Fin             bool   `json:"fin,omitempty"`
	Masked          bool   `json:"masked,omitempty"`
	Compressed      bool   `json:"compressed,omitempty"`
	CloseCode       uint16 `json:"close_code,omitempty"`
	CloseReason     string `json:"close_reason,omitempty"`
	PayloadEncoding string `json:"payload_encoding,omitempty"`
	Payload         string `json:"payload,omitempty"`
}

// grpcStartEntryView is the per-entry projection of a GRPCStartMessage envelope.
type grpcStartEntryView struct {
	Service     string     `json:"service,omitempty"`
	Method      string     `json:"method,omitempty"`
	Encoding    string     `json:"encoding,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Metadata    []headerKV `json:"metadata,omitempty"`
}

// grpcDataEntryView is the per-entry projection of a GRPCDataMessage envelope.
type grpcDataEntryView struct {
	Service         string `json:"service,omitempty"`
	Method          string `json:"method,omitempty"`
	Compressed      bool   `json:"compressed,omitempty"`
	EndStream       bool   `json:"end_stream,omitempty"`
	WireLength      uint32 `json:"wire_length,omitempty"`
	PayloadEncoding string `json:"payload_encoding,omitempty"`
	Payload         string `json:"payload,omitempty"`
}

// grpcEndEntryView is the per-entry projection of a GRPCEndMessage envelope.
type grpcEndEntryView struct {
	Status   uint32     `json:"status"`
	Message  string     `json:"message,omitempty"`
	Trailers []headerKV `json:"trailers,omitempty"`
}

// rawEntryView is the per-entry projection of a RawMessage envelope.
type rawEntryView struct {
	BytesEncoding string `json:"bytes_encoding,omitempty"`
	Bytes         string `json:"bytes,omitempty"`
}

// queryInterceptQueueResult is the response for the intercept_queue resource.
type queryInterceptQueueResult struct {
	// Items contains the currently held envelopes.
	Items []queryInterceptQueueEntry `json:"items"`
	// Count is the number of items returned.
	Count int `json:"count"`
}

// handleQueryInterceptQueue returns the list of currently held envelopes
// from the HoldQueue, projecting each via type-switch on env.Message.
func (s *Server) handleQueryInterceptQueue(input queryInput) (*gomcp.CallToolResult, *queryInterceptQueueResult, error) {
	if s.pipeline.holdQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}

	items := s.pipeline.holdQueue.List()

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].HeldAt.Before(items[j].HeldAt)
	})

	if len(items) > limit {
		items = items[:limit]
	}

	entries := make([]queryInterceptQueueEntry, 0, len(items))
	for _, it := range items {
		entries = append(entries, s.projectHeldEntry(it))
	}

	return nil, &queryInterceptQueueResult{
		Items: entries,
		Count: len(entries),
	}, nil
}

// projectHeldEntry projects one HoldQueue HeldEntry onto a JSON-friendly
// queryInterceptQueueEntry. The per-Message-type dispatch fans out into
// project*View helpers; SafetyEngine output masking is applied inline so
// each protocol view can mask the right headers/body shape.
func (s *Server) projectHeldEntry(it *common.HeldEntry) queryInterceptQueueEntry {
	env := it.Envelope
	entry := queryInterceptQueueEntry{
		ID:           it.ID,
		Protocol:     holdQueueProtocolKind(env),
		Direction:    env.Direction.String(),
		HeldAt:       it.HeldAt.UTC().Format("2006-01-02T15:04:05Z"),
		MatchedRules: it.MatchedRules,
		FlowID:       env.FlowID,
		StreamID:     env.StreamID,
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		entry.HTTP = s.projectHTTPView(m)
	case *envelope.WSMessage:
		entry.WS = s.projectWSView(m)
	case *envelope.GRPCStartMessage:
		entry.GRPCStart = s.projectGRPCStartView(m)
	case *envelope.GRPCDataMessage:
		entry.GRPCData = s.projectGRPCDataView(m)
	case *envelope.GRPCEndMessage:
		entry.GRPCEnd = s.projectGRPCEndView(m)
	case *envelope.RawMessage:
		entry.Raw = s.projectRawView(m)
	}

	if len(env.Raw) > 0 {
		entry.RawBytesAvailable = true
		entry.RawBytesSize = len(env.Raw)
		filtered := s.filterOutputBody(env.Raw)
		entry.RawBytes, entry.RawBytesEncoding = encodeBody(filtered)
	}

	return entry
}

// projectHTTPView projects an HTTPMessage with output filter applied to
// body and headers/trailers (preserving order and casing).
func (s *Server) projectHTTPView(m *envelope.HTTPMessage) *httpEntryView {
	body := s.filterOutputBody(m.Body)
	bodyStr, bodyEncoding := encodeBody(body)
	return &httpEntryView{
		Method:       m.Method,
		Scheme:       m.Scheme,
		Authority:    m.Authority,
		Path:         m.Path,
		RawQuery:     m.RawQuery,
		Status:       m.Status,
		StatusReason: m.StatusReason,
		Headers:      s.filterOutputHeaderKVs(m.Headers),
		Trailers:     s.filterOutputHeaderKVs(m.Trailers),
		BodyEncoding: bodyEncoding,
		Body:         bodyStr,
	}
}

// projectWSView projects a WSMessage with output filter applied to payload.
func (s *Server) projectWSView(m *envelope.WSMessage) *wsEntryView {
	payload := s.filterOutputBody(m.Payload)
	payStr, payEncoding := encodeBody(payload)
	return &wsEntryView{
		Opcode:          wsOpcodeName(m.Opcode),
		Fin:             m.Fin,
		Masked:          m.Masked,
		Compressed:      m.Compressed,
		CloseCode:       m.CloseCode,
		CloseReason:     m.CloseReason,
		PayloadEncoding: payEncoding,
		Payload:         payStr,
	}
}

// projectGRPCStartView projects a GRPCStartMessage with metadata filtered.
func (s *Server) projectGRPCStartView(m *envelope.GRPCStartMessage) *grpcStartEntryView {
	return &grpcStartEntryView{
		Service:     m.Service,
		Method:      m.Method,
		Encoding:    m.Encoding,
		ContentType: m.ContentType,
		Metadata:    s.filterOutputHeaderKVs(m.Metadata),
	}
}

// projectGRPCDataView projects a GRPCDataMessage with output filter on payload.
func (s *Server) projectGRPCDataView(m *envelope.GRPCDataMessage) *grpcDataEntryView {
	payload := s.filterOutputBody(m.Payload)
	payStr, payEncoding := encodeBody(payload)
	return &grpcDataEntryView{
		Service:         m.Service,
		Method:          m.Method,
		Compressed:      m.Compressed,
		EndStream:       m.EndStream,
		WireLength:      m.WireLength,
		PayloadEncoding: payEncoding,
		Payload:         payStr,
	}
}

// projectGRPCEndView projects a GRPCEndMessage with trailers filtered.
func (s *Server) projectGRPCEndView(m *envelope.GRPCEndMessage) *grpcEndEntryView {
	return &grpcEndEntryView{
		Status:   m.Status,
		Message:  m.Message,
		Trailers: s.filterOutputHeaderKVs(m.Trailers),
	}
}

// projectRawView projects a RawMessage with output filter on bytes.
func (s *Server) projectRawView(m *envelope.RawMessage) *rawEntryView {
	bytesFiltered := s.filterOutputBody(m.Bytes)
	bytesStr, bytesEncoding := encodeBody(bytesFiltered)
	return &rawEntryView{
		BytesEncoding: bytesEncoding,
		Bytes:         bytesStr,
	}
}

// filterOutputHeaderKVs applies SafetyEngine output masking to a list of
// envelope.KeyValue headers and projects onto the order-preserving
// []headerKV shape used by the MCP intercept_queue response. Returns nil
// when the input is nil or empty.
func (s *Server) filterOutputHeaderKVs(kvs []envelope.KeyValue) []headerKV {
	if len(kvs) == 0 {
		return nil
	}
	out := make([]headerKV, 0, len(kvs))
	if s.pipeline.safetyEngine == nil {
		for _, kv := range kvs {
			out = append(out, headerKV{Name: kv.Name, Value: kv.Value})
		}
		return out
	}
	filtered, _ := s.pipeline.safetyEngine.FilterOutputHeaders(kvs)
	for _, kv := range filtered {
		out = append(out, headerKV{Name: kv.Name, Value: kv.Value})
	}
	return out
}

// --- macros resource ---

// queryMacrosEntry is a single macro entry in the macros query response.
type queryMacrosEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StepCount   int    `json:"step_count"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// queryMacrosResult is the response for the macros resource.
type queryMacrosResult struct {
	Macros []queryMacrosEntry `json:"macros"`
	Count  int                `json:"count"`
}

// handleQueryMacros returns a list of all stored macro definitions.
func (s *Server) handleQueryMacros(ctx context.Context) (*gomcp.CallToolResult, *queryMacrosResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	records, err := s.flowStore.store.ListMacros(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list macros: %w", err)
	}

	entries := make([]queryMacrosEntry, 0, len(records))
	for _, rec := range records {
		stepCount := 0
		var cfg macroConfig
		if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err == nil {
			stepCount = len(cfg.Steps)
		}

		entries = append(entries, queryMacrosEntry{
			Name:        rec.Name,
			Description: rec.Description,
			StepCount:   stepCount,
			CreatedAt:   rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	return nil, &queryMacrosResult{
		Macros: entries,
		Count:  len(entries),
	}, nil
}

// --- macro resource ---

// queryMacroResult is the response for the macro resource (single macro detail).
type queryMacroResult struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Steps       []macroStepInput  `json:"steps"`
	InitialVars map[string]string `json:"initial_vars,omitempty"`
	TimeoutMs   int               `json:"timeout_ms,omitempty"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// handleQueryMacro returns detailed information about a single macro definition.
func (s *Server) handleQueryMacro(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryMacroResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for macro resource (macro name)")
	}

	rec, err := s.flowStore.store.GetMacro(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get macro: %w", err)
	}

	var cfg macroConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse macro config: %w", err)
	}

	result := &queryMacroResult{
		Name:        rec.Name,
		Description: rec.Description,
		Steps:       cfg.Steps,
		InitialVars: cfg.InitialVars,
		TimeoutMs:   cfg.TimeoutMs,
		CreatedAt:   rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return nil, result, nil
}
