package setup

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

//go:embed skilldata
var skillFS embed.FS

// InstallSkills copies embedded yorishiro skill files to the project's
// .claude/skills/yorishiro/ directory. If the directory already exists,
// existing files are backed up before overwriting.
func InstallSkills(projectDir string, now time.Time) (installed []string, backupPath string, err error) {
	targetDir := filepath.Join(projectDir, ".claude", "skills", "yorishiro")

	// Check if skills already exist and back up if needed.
	if info, statErr := os.Stat(targetDir); statErr == nil && info.IsDir() {
		// Back up the existing directory by recording its path.
		backupDir := targetDir + ".bak." + now.Format("20060102-150405")
		if err := os.Rename(targetDir, backupDir); err != nil {
			return nil, "", fmt.Errorf("backup existing skills directory: %w", err)
		}
		backupPath = backupDir
	}

	// Create target directory.
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, backupPath, fmt.Errorf("create skills directory: %w", err)
	}

	// Walk embedded files and copy them.
	err = fs.WalkDir(skillFS, "skilldata", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Compute relative path under skilldata/.
		relPath, err := filepath.Rel("skilldata", path)
		if err != nil {
			return fmt.Errorf("compute relative path: %w", err)
		}
		if relPath == "." {
			return nil
		}

		targetPath := filepath.Join(targetDir, relPath)

		if d.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		data, err := skillFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded file %s: %w", path, err)
		}

		if err := os.WriteFile(targetPath, data, 0644); err != nil {
			return fmt.Errorf("write skill file %s: %w", targetPath, err)
		}

		installed = append(installed, relPath)
		return nil
	})
	if err != nil {
		return installed, backupPath, fmt.Errorf("install skills: %w", err)
	}

	return installed, backupPath, nil
}
