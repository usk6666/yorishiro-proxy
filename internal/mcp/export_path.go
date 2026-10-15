package mcp

import (
	"path/filepath"
)

// WithExportDir sets the directory that confines manage export_flows /
// import_flows file paths (USK-1127).
func WithExportDir(dir string) ServerOption {
	return func(s *Server) {
		s.misc.exportDir = dir
	}
}

// exportPath is a caller-supplied output_path / input_path mapped onto the
// export directory.
type exportPath struct {
	// rel is the clean, export-directory-relative path.
	rel string
	// abs is the absolute path reported back to the caller.
	abs string
}

// resolveExportPath maps requested onto exportDir.
//
// SCAFFOLDING (USK-1127 red phase): no confinement yet.
func resolveExportPath(exportDir, requested string) (exportPath, error) {
	if filepath.IsAbs(requested) {
		return exportPath{rel: requested, abs: requested}, nil
	}
	return exportPath{rel: requested, abs: filepath.Join(exportDir, requested)}, nil
}

// exportPathOutsideError reports a path that resolves outside the export
// directory.
type exportPathOutsideError struct {
	requested string
	root      string
}

func (e *exportPathOutsideError) Error() string {
	return "path " + e.requested + " resolves outside export directory " + e.root
}
