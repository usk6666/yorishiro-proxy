package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// manageInput is the typed input for the manage tool.
type manageInput struct {
	// Action specifies the management action to execute.
	// Available actions: delete_flows, export_flows, import_flows, regenerate_ca_cert.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params manageParams `json:"params"`
}

// manageParams holds the union of all manage action-specific parameters.
// Only the fields relevant to the specified action are used.
type manageParams struct {
	// StreamID is used by delete_flows (single deletion).
	StreamID string `json:"flow_id,omitempty" jsonschema:"flow ID for single deletion"`

	// delete_flows parameters
	OlderThanDays *int   `json:"older_than_days,omitempty" jsonschema:"delete flows older than this many days"`
	Confirm       bool   `json:"confirm,omitempty" jsonschema:"confirm bulk deletion"`
	Protocol      string `json:"protocol,omitempty" jsonschema:"protocol filter for delete_flows; matches Stream.Protocol exactly (canonical values: http, ws, grpc, grpc-web, sse, raw, tls-handshake). Mirrors query tool filter.protocol semantics."`
	// Scheme filters delete_flows by Stream.Scheme — the wire-observed
	// handshake transport ("http", "https", "tcp"). Per USK-848,
	// WebSocket Streams keep the handshake transport across the WS
	// Protocol retag; they do NOT record "ws"/"wss". To target WebSocket
	// flows, use protocol="ws"; combine with scheme="https" for
	// WS-over-TLS only. Mirrors the query tool's filter.scheme axis.
	Scheme string `json:"scheme,omitempty" jsonschema:"scheme filter for delete_flows — wire-observed handshake transport (http, https, tcp). For WebSocket flows use protocol=\"ws\"; combine with scheme=\"https\" for WS-over-TLS only. Mirrors query tool filter.scheme semantics."`
	// HTTPVersion filters delete_flows by an associated Flow's
	// http_version. Canonical lowercased values: http/1.0, http/1.1,
	// h2, h2c. Use a pointer so callers can request a literal
	// empty-string filter (matches pre-USK-788 rows that lack a
	// recorded version) by sending "" explicitly. Omit the key to
	// disable the predicate. Mirrors query tool filter semantics.
	HTTPVersion *string `json:"http_version,omitempty" jsonschema:"http_version filter for delete_flows; matches Flow.http_version (canonical values: http/1.0, http/1.1, h2, h2c). Empty-string explicit value matches pre-USK-788 rows."`

	// export_flows parameters
	Format        string        `json:"format,omitempty" jsonschema:"export format: jsonl (default) or har (HTTP Archive 1.2)"`
	Filter        *exportFilter `json:"filter,omitempty" jsonschema:"flow filter for export"`
	IncludeBodies *bool         `json:"include_bodies,omitempty" jsonschema:"include message bodies in export (default: true)"`
	OutputPath    string        `json:"output_path,omitempty" jsonschema:"file path to write export data"`

	// import_flows parameters
	InputPath  string `json:"input_path,omitempty" jsonschema:"file path to read import data"`
	OnConflict string `json:"on_conflict,omitempty" jsonschema:"conflict policy: skip or replace (default: skip)"`
}

// exportFilter holds filter parameters for the export_flows action.
// Filter axes mirror the query MCP tool's filter so analysts can
// archive / drop the same set of flows they were inspecting (USK-792).
type exportFilter struct {
	// Protocol matches Stream.Protocol exactly. Canonical lowercased
	// values: http, ws, grpc, grpc-web, sse, raw, tls-handshake.
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter; matches Stream.Protocol exactly (canonical values: http, ws, grpc, grpc-web, sse, raw, tls-handshake). Mirrors query tool filter.protocol semantics."`
	// Scheme matches Stream.Scheme exactly — the wire-observed
	// handshake transport ("http", "https", "tcp"). Per USK-848,
	// WebSocket Streams keep the handshake transport across the WS
	// Protocol retag; they do NOT record "ws"/"wss". To target WebSocket
	// flows, use protocol="ws"; combine with scheme="https" for
	// WS-over-TLS only. Mirrors the query tool's filter.scheme axis.
	// Use scheme=https to export HTTPS flows regardless of HTTP version.
	Scheme string `json:"scheme,omitempty" jsonschema:"scheme filter — wire-observed handshake transport (http, https, tcp). For WebSocket flows use protocol=\"ws\"; combine with scheme=\"https\" for WS-over-TLS only. Mirrors query tool filter.scheme semantics."`
	// HTTPVersion matches Flow.http_version via an EXISTS subquery on
	// the flows table. Canonical lowercased values: http/1.0,
	// http/1.1, h2, h2c. Pointer so an explicit empty string can
	// request the pre-USK-788 (unknown-version) bucket; omitting the
	// key disables the predicate.
	HTTPVersion *string `json:"http_version,omitempty" jsonschema:"http_version filter; matches Flow.http_version (canonical values: http/1.0, http/1.1, h2, h2c). Empty-string explicit value matches pre-USK-788 rows."`
	URLPattern  string  `json:"url_pattern,omitempty"`
	TimeAfter   string  `json:"time_after,omitempty"`
	TimeBefore  string  `json:"time_before,omitempty"`
}

// availableManageActions lists the valid action names for the manage tool.
var availableManageActions = []string{"delete_flows", "export_flows", "import_flows", "regenerate_ca_cert"}

// registerManage registers the manage MCP tool.
func (s *Server) registerManage() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "manage",
		Description: "Manage flow data and CA certificates. Actions: " +
			"'delete_flows' (by ID, age, top-level protocol/scheme/http_version, or params.filter " +
			"url_pattern / time_after / time_before — all with confirm — or all); " +
			"'export_flows' (JSONL or HAR 1.2, optionally filtered by protocol / scheme / http_version / url_pattern / time, with/without bodies); " +
			"'import_flows' (JSONL with skip/replace on ID conflict); " +
			"'regenerate_ca_cert' (depends on CA persistence mode). " +
			"Filter axes (protocol / scheme / http_version / url_pattern / time) mirror the query tool's filter so analysts can " +
			"export / delete the same set of flows they were inspecting. " +
			"For delete_flows, top-level protocol/scheme/http_version and params.filter cannot be combined in a single call; supply one form. " +
			"See yorishiro://help/manage.",
	}, s.handleManage)
}

// handleManage routes the manage tool invocation to the appropriate action handler.
func (s *Server) handleManage(ctx context.Context, _ *gomcp.CallToolRequest, input manageInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "manage",
		"action", input.Action,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "manage",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableManageActions, ", "))
	case "delete_flows":
		return s.handleManageDeleteFlows(ctx, input.Params)
	case "regenerate_ca_cert":
		return s.handleManageRegenerateCA()
	case "export_flows":
		result, err := s.handleManageExportFlows(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "import_flows":
		result, err := s.handleManageImportFlows(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableManageActions, ", "))
	}
}

// --- Delete flows ---

// executeDeleteFlowsResult is the structured output of the delete_flows action.
type executeDeleteFlowsResult struct {
	DeletedCount int64  `json:"deleted_count"`
	CutoffTime   string `json:"cutoff_time,omitempty"`
}

// handleManageDeleteFlows handles the delete_flows action within the manage tool.
func (s *Server) handleManageDeleteFlows(ctx context.Context, params manageParams) (*gomcp.CallToolResult, *executeDeleteFlowsResult, error) {
	if s.flowStore.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if params.OlderThanDays != nil {
		days := *params.OlderThanDays
		if days < 1 {
			return nil, nil, fmt.Errorf("older_than_days must be >= 1, got %d", days)
		}
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with age-based deletion")
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		n, err := s.flowStore.store.DeleteStreamsOlderThan(ctx, cutoff)
		if err != nil {
			return nil, nil, fmt.Errorf("delete old flows: %w", err)
		}
		return nil, &executeDeleteFlowsResult{
			DeletedCount: n,
			CutoffTime:   cutoff.Format(time.RFC3339),
		}, nil
	}

	if params.StreamID != "" {
		fl, err := s.flowStore.store.GetStream(ctx, params.StreamID)
		if err != nil {
			return nil, nil, fmt.Errorf("flow not found: %s", params.StreamID)
		}
		if err := s.flowStore.store.DeleteStream(ctx, fl.ID); err != nil {
			return nil, nil, fmt.Errorf("delete flow: %w", err)
		}
		return nil, &executeDeleteFlowsResult{DeletedCount: 1}, nil
	}

	// Bulk filter-based deletion: any combination of protocol / scheme /
	// http_version (top-level) OR url_pattern / time_after / time_before
	// inside params.filter (USK-822). Mixing the two forms is rejected
	// for unambiguous semantics. All non-zero filter fields within the
	// chosen form combine with AND. A confirm guard is required because
	// the filter can match many streams. Empty filter falls through to
	// the unconditional delete-all branch below.
	deleteFilter, err := buildDeleteFilter(params)
	if err != nil {
		return nil, nil, err
	}
	if !deleteFilter.IsZero() {
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with filter-based deletion")
		}
		slog.DebugContext(ctx, "delete_flows filter applied",
			"protocol", deleteFilter.Protocol,
			"scheme", deleteFilter.Scheme,
			"http_version", debugHTTPVersionPtr(deleteFilter.HTTPVersion),
			"url_pattern", deleteFilter.URLPattern,
			"time_after", debugTimePtr(deleteFilter.TimeAfter),
			"time_before", debugTimePtr(deleteFilter.TimeBefore),
		)
		n, err := s.flowStore.store.DeleteStreamsByFilter(ctx, deleteFilter)
		if err != nil {
			return nil, nil, fmt.Errorf("delete flows by filter: %w", err)
		}
		return nil, &executeDeleteFlowsResult{DeletedCount: n}, nil
	}

	if params.Confirm {
		n, err := s.flowStore.store.DeleteAllStreams(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all flows: %w", err)
		}
		// Mass delete is the most destructive control-plane action; log
		// at Info so operators see "what happened" without enabling
		// debug. Mirrors CLAUDE.md log-level guidance for a security
		// event that warrants attention. The filter-applied branch
		// above stays at Debug because the count is bounded by the
		// supplied predicates.
		slog.InfoContext(ctx, "delete_flows: deleted all streams",
			"deleted_count", n,
		)
		return nil, &executeDeleteFlowsResult{DeletedCount: n}, nil
	}

	return nil, nil, fmt.Errorf("delete_flows requires one of: flow_id, older_than_days, filter (protocol/scheme/http_version OR params.filter url_pattern/time_after/time_before with confirm), or confirm=true for all deletion")
}

// buildDeleteFilter assembles a flow.StreamDeleteFilter from the manage
// params, validating that supplied values match the canonical
// MCP-tool enums (mirror of the query tool). An empty filter (no
// top-level axes and no params.filter) returns a zero filter so the
// caller can treat that as "delete all" rather than a degenerate
// single-axis predicate.
//
// USK-822: delete_flows now accepts the same params.filter shape as
// export_flows (url_pattern / time_after / time_before). Mixing the
// top-level axes (protocol / scheme / http_version) with params.filter
// is rejected to keep semantics unambiguous — analysts pick one form.
func buildDeleteFilter(params manageParams) (flow.StreamDeleteFilter, error) {
	hasTopLevel := params.Protocol != "" || params.Scheme != "" || params.HTTPVersion != nil
	hasFilter := params.Filter != nil && !exportFilterIsZero(params.Filter)
	if hasTopLevel && hasFilter {
		return flow.StreamDeleteFilter{}, fmt.Errorf("delete_flows: cannot mix params.filter with top-level protocol/scheme/http_version filters; supply only one form")
	}

	if hasFilter {
		return buildDeleteFilterFromExportFilter(params.Filter)
	}

	if err := validateManageDeleteFilter(params); err != nil {
		return flow.StreamDeleteFilter{}, err
	}
	return flow.StreamDeleteFilter{
		Protocol:    params.Protocol,
		Scheme:      params.Scheme,
		HTTPVersion: params.HTTPVersion,
	}, nil
}

// buildDeleteFilterFromExportFilter validates and converts the
// params.filter (export-style) shape into a flow.StreamDeleteFilter.
// It mirrors buildExportOptions's time parsing exactly — same RFC3339
// format, same wrapped-error shape — so callers see identical errors
// across the export and delete surfaces (USK-822).
func buildDeleteFilterFromExportFilter(filter *exportFilter) (flow.StreamDeleteFilter, error) {
	if err := validateManageExportFilter(filter); err != nil {
		return flow.StreamDeleteFilter{}, err
	}
	out := flow.StreamDeleteFilter{
		Protocol:    filter.Protocol,
		Scheme:      filter.Scheme,
		HTTPVersion: filter.HTTPVersion,
		URLPattern:  filter.URLPattern,
	}
	if filter.TimeAfter != "" {
		t, err := time.Parse(time.RFC3339, filter.TimeAfter)
		if err != nil {
			return flow.StreamDeleteFilter{}, fmt.Errorf("invalid time_after format (expected RFC3339): %w", err)
		}
		out.TimeAfter = &t
	}
	if filter.TimeBefore != "" {
		t, err := time.Parse(time.RFC3339, filter.TimeBefore)
		if err != nil {
			return flow.StreamDeleteFilter{}, fmt.Errorf("invalid time_before format (expected RFC3339): %w", err)
		}
		out.TimeBefore = &t
	}
	return out, nil
}

// exportFilterIsZero reports whether the export-style filter struct has
// every field at its zero value. Used by delete_flows to distinguish
// "no filter supplied" from "empty filter object explicitly set" — the
// latter would otherwise silently fall through to the delete-all
// branch the bug in USK-822 was about. The check mirrors the axes the
// jsonschema tags expose on exportFilter.
func exportFilterIsZero(f *exportFilter) bool {
	if f == nil {
		return true
	}
	return f.Protocol == "" &&
		f.Scheme == "" &&
		f.HTTPVersion == nil &&
		f.URLPattern == "" &&
		f.TimeAfter == "" &&
		f.TimeBefore == ""
}

// validateManageDeleteFilter validates the delete_flows filter values
// against the canonical MCP enum sets so callers get the same error
// messages as the query tool. http_version uses a pointer with the
// non-nil empty-string sentinel meaning "match pre-USK-788 rows", so
// only non-empty pointer values are checked against the enum.
func validateManageDeleteFilter(params manageParams) error {
	if err := validateEnum("protocol", params.Protocol, validFilterProtocols); err != nil {
		return err
	}
	if err := validateSchemeFilter(params.Scheme); err != nil {
		return err
	}
	if v := params.HTTPVersion; v != nil && *v != "" {
		if err := validateEnum("http_version", *v, validFilterHTTPVersions); err != nil {
			return err
		}
	}
	return nil
}

// validateManageExportFilter validates the export_flows filter values
// against the same canonical MCP enum sets used by the query tool and
// delete_flows path.
func validateManageExportFilter(filter *exportFilter) error {
	if err := validateEnum("protocol", filter.Protocol, validFilterProtocols); err != nil {
		return err
	}
	if err := validateSchemeFilter(filter.Scheme); err != nil {
		return err
	}
	if v := filter.HTTPVersion; v != nil && *v != "" {
		if err := validateEnum("http_version", *v, validFilterHTTPVersions); err != nil {
			return err
		}
	}
	return nil
}

// debugHTTPVersionPtr formats a *string http_version filter for slog
// without panicking on nil. Nil is rendered as "<unset>" so debug
// readers can distinguish "predicate omitted" from "match empty
// http_version".
func debugHTTPVersionPtr(p *string) string {
	if p == nil {
		return "<unset>"
	}
	return *p
}

// debugTimePtr formats a *time.Time bound for slog without panicking
// on nil. Nil renders as "<unset>" so debug readers can distinguish
// "predicate omitted" from "match a specific instant".
func debugTimePtr(p *time.Time) string {
	if p == nil {
		return "<unset>"
	}
	return p.UTC().Format(time.RFC3339Nano)
}

// --- Regenerate CA cert ---

// executeRegenerateCACertResult is the structured output of the regenerate_ca_cert action.
type executeRegenerateCACertResult struct {
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Persisted   bool   `json:"persisted"`
	CertPath    string `json:"cert_path,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
}

// handleManageRegenerateCA regenerates the CA certificate.
func (s *Server) handleManageRegenerateCA() (*gomcp.CallToolResult, *executeRegenerateCACertResult, error) {
	if s.misc.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized")
	}

	source := s.misc.ca.Source()

	if source.Explicit {
		return nil, nil, fmt.Errorf("cannot regenerate user-provided CA (loaded from %s); provide new files via -ca-cert/-ca-key flags instead", source.CertPath)
	}

	if err := s.misc.ca.Generate(); err != nil {
		return nil, nil, fmt.Errorf("regenerate CA: %w", err)
	}

	if s.misc.issuer != nil {
		s.misc.issuer.ClearCache()
	}

	if source.Persisted && source.CertPath != "" {
		if err := s.misc.ca.Save(source.CertPath, source.KeyPath); err != nil {
			slog.Warn("failed to save regenerated CA, continuing with ephemeral CA",
				"cert_path", source.CertPath, "error", err)
			s.misc.ca.SetSource(cert.CASource{})
		} else {
			s.misc.ca.SetSource(source)
		}
	}

	newCert := s.misc.ca.Certificate()
	fingerprint := sha256.Sum256(newCert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	newSource := s.misc.ca.Source()
	result := &executeRegenerateCACertResult{
		Fingerprint: fingerprintHex,
		Subject:     newCert.Subject.String(),
		NotAfter:    newCert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Persisted:   newSource.Persisted,
		CertPath:    newSource.CertPath,
	}

	if newSource.Persisted && newSource.CertPath != "" {
		result.InstallHint = "CA certificate has been regenerated. Please re-install the CA from " + newSource.CertPath + " into your trust store"
	} else {
		result.InstallHint = "CA certificate has been regenerated in memory. It will be lost on restart"
	}

	return nil, result, nil
}

// --- Export/import flows ---

// maxInlineExportFlows is the maximum number of flows returned inline.
const maxInlineExportFlows = 100

// validateFilePath sanitises and validates a user-supplied file path.
func validateFilePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path must not be empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}
	cleaned := filepath.Clean(abs)
	info, err := os.Lstat(cleaned)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("file path must not be a symbolic link: %s", cleaned)
		}
	}
	return cleaned, nil
}

// executeExportFlowsResult is the structured output of the export_flows action.
type executeExportFlowsResult struct {
	ExportedCount int    `json:"exported_count"`
	Format        string `json:"format"`
	OutputPath    string `json:"output_path,omitempty"`
	Data          string `json:"data,omitempty"`
}

// handleManageExportFlows handles the export_flows action within the manage tool.
func (s *Server) handleManageExportFlows(ctx context.Context, params manageParams) (*executeExportFlowsResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}

	format := params.Format
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "har" {
		return nil, fmt.Errorf("unsupported export format %q: supported formats are \"jsonl\" and \"har\"", format)
	}

	opts, err := buildExportOptions(params)
	if err != nil {
		return nil, err
	}

	if format == "har" {
		if params.OutputPath == "" {
			return nil, fmt.Errorf("HAR export requires output_path: HAR is a single JSON object and cannot be returned inline")
		}
		return s.exportFlowsToHARFile(ctx, params.OutputPath, opts)
	}

	if params.OutputPath != "" {
		return s.exportFlowsToFile(ctx, params.OutputPath, format, opts)
	}

	return s.exportFlowsInline(ctx, format, opts)
}

// buildExportOptions constructs flow.ExportOptions from the manage params.
func buildExportOptions(params manageParams) (flow.ExportOptions, error) {
	includeBodies := true
	if params.IncludeBodies != nil {
		includeBodies = *params.IncludeBodies
	}

	opts := flow.ExportOptions{
		IncludeBodies: includeBodies,
	}

	if params.Filter != nil {
		if err := validateManageExportFilter(params.Filter); err != nil {
			return flow.ExportOptions{}, err
		}
		opts.Filter.Protocol = params.Filter.Protocol
		opts.Filter.Scheme = params.Filter.Scheme
		opts.Filter.HTTPVersion = params.Filter.HTTPVersion
		opts.Filter.URLPattern = params.Filter.URLPattern

		if params.Filter.TimeAfter != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeAfter)
			if err != nil {
				return flow.ExportOptions{}, fmt.Errorf("invalid time_after format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeAfter = &t
		}
		if params.Filter.TimeBefore != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeBefore)
			if err != nil {
				return flow.ExportOptions{}, fmt.Errorf("invalid time_before format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeBefore = &t
		}
	}

	return opts, nil
}

// writeToFileAtomic validates the output path and atomically writes content
// via a temp file. The writeFn callback receives the temp file to write to and
// returns the number of items written.
func writeToFileAtomic(outputPath string, writeFn func(f *os.File) (int, error)) (cleanPath string, n int, err error) {
	cleanPath, err = validateFilePath(outputPath)
	if err != nil {
		return "", 0, fmt.Errorf("invalid output_path: %w", err)
	}

	dir := filepath.Dir(cleanPath)
	tmpFile, err := os.CreateTemp(dir, ".yorishiro-export-*.tmp")
	if err != nil {
		return "", 0, fmt.Errorf("create temp file for export: %w", err)
	}
	tmpPath := tmpFile.Name()
	success := false
	defer func() {
		tmpFile.Close()
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		return "", 0, fmt.Errorf("set file permissions: %w", err)
	}

	n, err = writeFn(tmpFile)
	if err != nil {
		return "", 0, err
	}

	if err := tmpFile.Close(); err != nil {
		return "", 0, fmt.Errorf("close temp file: %w", err)
	}

	if info, statErr := os.Lstat(cleanPath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("output_path must not be a symbolic link: %s", cleanPath)
		}
	}

	if err := os.Rename(tmpPath, cleanPath); err != nil {
		return "", 0, fmt.Errorf("rename temp file to output: %w", err)
	}
	success = true

	return cleanPath, n, nil
}

// exportFlowsToFile exports flows to a file at the given output path.
func (s *Server) exportFlowsToFile(ctx context.Context, outputPath, format string, opts flow.ExportOptions) (*executeExportFlowsResult, error) {
	cleanPath, n, err := writeToFileAtomic(outputPath, func(f *os.File) (int, error) {
		count, err := flow.ExportStreams(ctx, s.flowStore.store, f, opts)
		if err != nil {
			return 0, fmt.Errorf("export flows: %w", err)
		}
		return count, nil
	})
	if err != nil {
		return nil, err
	}

	return &executeExportFlowsResult{
		ExportedCount: n,
		Format:        format,
		OutputPath:    cleanPath,
	}, nil
}

// exportFlowsInline exports flows and returns them inline in the result.
func (s *Server) exportFlowsInline(ctx context.Context, format string, opts flow.ExportOptions) (*executeExportFlowsResult, error) {
	opts.MaxFlows = maxInlineExportFlows
	var buf bytes.Buffer
	n, err := flow.ExportStreams(ctx, s.flowStore.store, &buf, opts)
	if err != nil {
		return nil, fmt.Errorf("export flows: %w", err)
	}

	// Apply output filter to the serialized export data.
	maskedData := string(s.filterOutputBody(buf.Bytes()))

	return &executeExportFlowsResult{
		ExportedCount: n,
		Format:        format,
		Data:          maskedData,
	}, nil
}

// exportFlowsToHARFile exports flows to a HAR file at the given output path.
func (s *Server) exportFlowsToHARFile(ctx context.Context, outputPath string, opts flow.ExportOptions) (*executeExportFlowsResult, error) {
	cleanPath, n, err := writeToFileAtomic(outputPath, func(f *os.File) (int, error) {
		count, err := flow.ExportHAR(ctx, s.flowStore.store, f, opts, s.version)
		if err != nil {
			return 0, fmt.Errorf("export HAR: %w", err)
		}
		return count, nil
	})
	if err != nil {
		return nil, err
	}

	return &executeExportFlowsResult{
		ExportedCount: n,
		Format:        "har",
		OutputPath:    cleanPath,
	}, nil
}

// executeImportFlowsResult is the structured output of the import_flows action.
type executeImportFlowsResult struct {
	Imported     int                `json:"imported"`
	Skipped      int                `json:"skipped"`
	Errors       int                `json:"errors"`
	Source       string             `json:"source"`
	ErrorDetails []flow.ImportError `json:"error_details,omitempty"`
}

// handleManageImportFlows handles the import_flows action within the manage tool.
func (s *Server) handleManageImportFlows(ctx context.Context, params manageParams) (*executeImportFlowsResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}

	if params.InputPath == "" {
		return nil, fmt.Errorf("input_path is required for import_flows action")
	}

	cleanPath, err := validateFilePath(params.InputPath)
	if err != nil {
		return nil, fmt.Errorf("invalid input_path: %w", err)
	}

	conflict := flow.ConflictSkip
	if params.OnConflict != "" {
		switch params.OnConflict {
		case "skip":
			conflict = flow.ConflictSkip
		case "replace":
			conflict = flow.ConflictReplace
		default:
			return nil, fmt.Errorf("invalid on_conflict value %q: must be \"skip\" or \"replace\"", params.OnConflict)
		}
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	result, err := flow.ImportStreams(ctx, s.flowStore.store, f, flow.ImportOptions{
		OnConflict:       conflict,
		MaxScannerBuffer: config.ResolveMaxImportScannerBuffer(s.connector.proxyDefaults),
		ValidateIDs:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("import flows: %w", err)
	}

	return &executeImportFlowsResult{
		Imported:     result.Imported,
		Skipped:      result.Skipped,
		Errors:       result.Errors,
		Source:       cleanPath,
		ErrorDetails: result.ErrorDetails,
	}, nil
}
