package safety

import (
	"fmt"
	"regexp"
)

// Built-in preset names.
const (
	PresetDestructiveSQL       = "destructive-sql"
	PresetDestructiveOSCommand = "destructive-os-command"
)

// destructiveSQLRules defines rules that detect destructive SQL operations.
// Diagnostic payloads used for vulnerability assessment (e.g. UNION SELECT,
// OR 1=1) are intentionally excluded — only operations that can cause data
// loss or schema damage are matched.
var destructiveSQLRules = []RuleConfig{
	{
		ID:      "destructive-sql:drop",
		Name:    "DROP statement",
		Pattern: `(?i)DROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\s+`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:truncate",
		Name:    "TRUNCATE TABLE",
		Pattern: `(?i)TRUNCATE\s+TABLE\s+`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:delete-no-where",
		Name:    "DELETE without WHERE clause",
		Pattern: `(?i)DELETE\s+FROM\s+\w+\s*($|;|--)`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:update-all",
		Name:    "UPDATE all rows (WHERE 1=1)",
		Pattern: `(?i)UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:alter-drop",
		Name:    "ALTER TABLE DROP",
		Pattern: `(?i)ALTER\s+TABLE\s+\w+\s+DROP\s+`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:exec-xp",
		Name:    "SQL Server extended stored procedure",
		Pattern: `(?i)(EXEC|EXECUTE)\s+xp_`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
}

// destructiveOSCommandRules defines rules that detect destructive OS commands.
var destructiveOSCommandRules = []RuleConfig{
	{
		ID:      "destructive-os:rm-rf",
		Name:    "rm -rf",
		Pattern: `rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r`,
		Targets: []Target{TargetBody},
	},
	{
		ID:      "destructive-os:shutdown",
		Name:    "Shutdown/reboot command",
		Pattern: `(?i)(shutdown|reboot|halt|poweroff)\s`,
		Targets: []Target{TargetBody},
	},
	{
		ID:      "destructive-os:mkfs",
		Name:    "Filesystem creation (mkfs)",
		Pattern: `mkfs\s`,
		Targets: []Target{TargetBody},
	},
	{
		ID:      "destructive-os:dd-if",
		Name:    "Disk write (dd)",
		Pattern: `dd\s+if=`,
		Targets: []Target{TargetBody},
	},
	{
		ID:      "destructive-os:format",
		Name:    "Windows format command",
		Pattern: `(?i)format\s+[a-zA-Z]:`,
		Targets: []Target{TargetBody},
	},
}

// presets maps preset names to their rule definitions.
var presets = map[string]Preset{
	PresetDestructiveSQL: {
		Name:  PresetDestructiveSQL,
		Rules: destructiveSQLRules,
	},
	PresetDestructiveOSCommand: {
		Name:  PresetDestructiveOSCommand,
		Rules: destructiveOSCommandRules,
	},
}

// LookupPreset returns the preset with the given name.
// It returns an error if the name is not recognised.
func LookupPreset(name string) (Preset, error) {
	p, ok := presets[name]
	if !ok {
		return Preset{}, fmt.Errorf("unknown preset: %q", name)
	}
	return p, nil
}

// PresetNames returns the names of all available presets in alphabetical order.
func PresetNames() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	// Sort for deterministic output.
	sortStrings(names)
	return names
}

// sortStrings sorts a slice of strings in ascending order.
// Avoids importing the sort package for a trivial operation.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// CompilePreset compiles a Preset's RuleConfig entries into Rules ready for
// evaluation. The caller supplies a default action to apply to all rules.
func CompilePreset(p Preset, action Action) ([]Rule, error) {
	rules := make([]Rule, 0, len(p.Rules))
	for _, rc := range p.Rules {
		re, err := compilePattern(rc.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rc.ID, err)
		}
		rules = append(rules, Rule{
			ID:       rc.ID,
			Name:     rc.Name,
			Pattern:  re,
			Targets:  rc.Targets,
			Action:   action,
			Category: p.Name,
		})
	}
	return rules, nil
}

// compilePattern compiles a regex pattern string and returns an error with
// context if compilation fails.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return re, nil
}
