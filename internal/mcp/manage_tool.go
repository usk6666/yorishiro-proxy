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
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// manageInput is the typed input for the manage tool.
type manageInput struct {
	// Action specifies the management action to execute.
	// Available actions: delete_sessions, export_sessions, import_sessions, regenerate_ca_cert.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params manageParams `json:"params"`
}

// manageParams holds the union of all manage action-specific parameters.
// Only the fields relevant to the specified action are used.
type manageParams struct {
	// SessionID is used by delete_sessions (single deletion).
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID for single deletion"`

	// delete_sessions parameters
	OlderThanDays *int   `json:"older_than_days,omitempty" jsonschema:"delete sessions older than this many days"`
	Confirm       bool   `json:"confirm,omitempty" jsonschema:"confirm bulk deletion"`
	Protocol      string `json:"protocol,omitempty" jsonschema:"protocol filter for delete_sessions (e.g. HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP)"`

	// export_sessions parameters
	Format        string        `json:"format,omitempty" jsonschema:"export format (jsonl)"`
	Filter        *exportFilter `json:"filter,omitempty" jsonschema:"session filter for export"`
	IncludeBodies *bool         `json:"include_bodies,omitempty" jsonschema:"include message bodies in export (default: true)"`
	OutputPath    string        `json:"output_path,omitempty" jsonschema:"file path to write export data"`

	// import_sessions parameters
	InputPath  string `json:"input_path,omitempty" jsonschema:"file path to read import data"`
	OnConflict string `json:"on_conflict,omitempty" jsonschema:"conflict policy: skip or replace (default: skip)"`
}

// exportFilter holds filter parameters for the export_sessions action.
type exportFilter struct {
	Protocol   string `json:"protocol,omitempty"`
	URLPattern string `json:"url_pattern,omitempty"`
	TimeAfter  string `json:"time_after,omitempty"`
	TimeBefore string `json:"time_before,omitempty"`
}

// availableManageActions lists the valid action names for the manage tool.
var availableManageActions = []string{"delete_sessions", "export_sessions", "import_sessions", "regenerate_ca_cert"}

// registerManage registers the manage MCP tool.
func (s *Server) registerManage() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "manage",
		Description: "Manage session data and CA certificates. " +
			"Available actions: " +
			"'delete_sessions' deletes sessions by ID, by age (older_than_days), by protocol, or all (confirm required); " +
			"'export_sessions' exports sessions to JSONL format (optionally filtered, with or without bodies, to file or inline); " +
			"'import_sessions' imports sessions from a JSONL file (supports skip/replace on ID conflict); " +
			"'regenerate_ca_cert' regenerates the CA certificate (auto-persist mode: saves to disk; ephemeral mode: in-memory only; explicit mode: error).",
	}, s.handleManage)
}

// handleManage routes the manage tool invocation to the appropriate action handler.
func (s *Server) handleManage(ctx context.Context, _ *gomcp.CallToolRequest, input manageInput) (*gomcp.CallToolResult, any, error) {
	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableManageActions, ", "))
	case "delete_sessions":
		return s.handleManageDeleteSessions(ctx, input.Params)
	case "regenerate_ca_cert":
		return s.handleManageRegenerateCA()
	case "export_sessions":
		result, err := s.handleManageExportSessions(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "import_sessions":
		result, err := s.handleManageImportSessions(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableManageActions)
	}
}

// --- Delete sessions ---

// executeDeleteSessionsResult is the structured output of the delete_sessions action.
type executeDeleteSessionsResult struct {
	DeletedCount int64  `json:"deleted_count"`
	CutoffTime   string `json:"cutoff_time,omitempty"`
}

// handleManageDeleteSessions handles the delete_sessions action within the manage tool.
func (s *Server) handleManageDeleteSessions(ctx context.Context, params manageParams) (*gomcp.CallToolResult, *executeDeleteSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
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
		n, err := s.store.DeleteSessionsOlderThan(ctx, cutoff)
		if err != nil {
			return nil, nil, fmt.Errorf("delete old sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{
			DeletedCount: n,
			CutoffTime:   cutoff.Format(time.RFC3339),
		}, nil
	}

	if params.SessionID != "" {
		if _, err := s.store.GetSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("session not found: %s", params.SessionID)
		}
		if err := s.store.DeleteSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("delete session: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: 1}, nil
	}

	if params.Protocol != "" {
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with protocol-based deletion")
		}
		n, err := s.store.DeleteSessionsByProtocol(ctx, params.Protocol)
		if err != nil {
			return nil, nil, fmt.Errorf("delete sessions by protocol: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	if params.Confirm {
		n, err := s.store.DeleteAllSessions(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	return nil, nil, fmt.Errorf("delete_sessions requires one of: session_id, older_than_days, protocol (with confirm), or confirm=true for all deletion")
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
	if s.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized")
	}

	source := s.ca.Source()

	if source.Explicit {
		return nil, nil, fmt.Errorf("cannot regenerate user-provided CA (loaded from %s); provide new files via -ca-cert/-ca-key flags instead", source.CertPath)
	}

	if err := s.ca.Generate(); err != nil {
		return nil, nil, fmt.Errorf("regenerate CA: %w", err)
	}

	if s.issuer != nil {
		s.issuer.ClearCache()
	}

	if source.Persisted && source.CertPath != "" {
		if err := s.ca.Save(source.CertPath, source.KeyPath); err != nil {
			slog.Warn("failed to save regenerated CA, continuing with ephemeral CA",
				"cert_path", source.CertPath, "error", err)
			s.ca.SetSource(cert.CASource{})
		} else {
			s.ca.SetSource(source)
		}
	}

	newCert := s.ca.Certificate()
	fingerprint := sha256.Sum256(newCert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	newSource := s.ca.Source()
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

// --- Export/import sessions ---

// maxInlineExportSessions is the maximum number of sessions returned inline.
const maxInlineExportSessions = 100

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

// executeExportSessionsResult is the structured output of the export_sessions action.
type executeExportSessionsResult struct {
	ExportedCount int    `json:"exported_count"`
	Format        string `json:"format"`
	OutputPath    string `json:"output_path,omitempty"`
	Data          string `json:"data,omitempty"`
}

// handleManageExportSessions handles the export_sessions action within the manage tool.
func (s *Server) handleManageExportSessions(ctx context.Context, params manageParams) (*executeExportSessionsResult, error) {
	if s.store == nil {
		return nil, fmt.Errorf("session store is not initialized")
	}

	format := params.Format
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" {
		return nil, fmt.Errorf("unsupported export format %q: only \"jsonl\" is supported", format)
	}

	includeBodies := true
	if params.IncludeBodies != nil {
		includeBodies = *params.IncludeBodies
	}

	opts := session.ExportOptions{
		IncludeBodies: includeBodies,
	}

	if params.Filter != nil {
		opts.Filter.Protocol = params.Filter.Protocol
		opts.Filter.URLPattern = params.Filter.URLPattern

		if params.Filter.TimeAfter != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeAfter)
			if err != nil {
				return nil, fmt.Errorf("invalid time_after format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeAfter = &t
		}
		if params.Filter.TimeBefore != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeBefore)
			if err != nil {
				return nil, fmt.Errorf("invalid time_before format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeBefore = &t
		}
	}

	if params.OutputPath != "" {
		cleanPath, err := validateFilePath(params.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("invalid output_path: %w", err)
		}

		dir := filepath.Dir(cleanPath)
		tmpFile, err := os.CreateTemp(dir, ".yorishiro-export-*.tmp")
		if err != nil {
			return nil, fmt.Errorf("create temp file for export: %w", err)
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
			return nil, fmt.Errorf("set file permissions: %w", err)
		}

		n, err := session.ExportSessions(ctx, s.store, tmpFile, opts)
		if err != nil {
			return nil, fmt.Errorf("export sessions: %w", err)
		}

		if err := tmpFile.Close(); err != nil {
			return nil, fmt.Errorf("close temp file: %w", err)
		}

		if info, statErr := os.Lstat(cleanPath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("output_path must not be a symbolic link: %s", cleanPath)
			}
		}

		if err := os.Rename(tmpPath, cleanPath); err != nil {
			return nil, fmt.Errorf("rename temp file to output: %w", err)
		}
		success = true

		return &executeExportSessionsResult{
			ExportedCount: n,
			Format:        format,
			OutputPath:    cleanPath,
		}, nil
	}

	opts.MaxSessions = maxInlineExportSessions
	var buf bytes.Buffer
	n, err := session.ExportSessions(ctx, s.store, &buf, opts)
	if err != nil {
		return nil, fmt.Errorf("export sessions: %w", err)
	}

	return &executeExportSessionsResult{
		ExportedCount: n,
		Format:        format,
		Data:          buf.String(),
	}, nil
}

// executeImportSessionsResult is the structured output of the import_sessions action.
type executeImportSessionsResult struct {
	Imported     int                   `json:"imported"`
	Skipped      int                   `json:"skipped"`
	Errors       int                   `json:"errors"`
	Source       string                `json:"source"`
	ErrorDetails []session.ImportError `json:"error_details,omitempty"`
}

// handleManageImportSessions handles the import_sessions action within the manage tool.
func (s *Server) handleManageImportSessions(ctx context.Context, params manageParams) (*executeImportSessionsResult, error) {
	if s.store == nil {
		return nil, fmt.Errorf("session store is not initialized")
	}

	if params.InputPath == "" {
		return nil, fmt.Errorf("input_path is required for import_sessions action")
	}

	cleanPath, err := validateFilePath(params.InputPath)
	if err != nil {
		return nil, fmt.Errorf("invalid input_path: %w", err)
	}

	conflict := session.ConflictSkip
	if params.OnConflict != "" {
		switch params.OnConflict {
		case "skip":
			conflict = session.ConflictSkip
		case "replace":
			conflict = session.ConflictReplace
		default:
			return nil, fmt.Errorf("invalid on_conflict value %q: must be \"skip\" or \"replace\"", params.OnConflict)
		}
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	result, err := session.ImportSessions(ctx, s.store, f, session.ImportOptions{
		OnConflict:       conflict,
		MaxScannerBuffer: config.MaxImportScannerBuffer,
		ValidateIDs:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("import sessions: %w", err)
	}

	return &executeImportSessionsResult{
		Imported:     result.Imported,
		Skipped:      result.Skipped,
		Errors:       result.Errors,
		Source:       cleanPath,
		ErrorDetails: result.ErrorDetails,
	}, nil
}
