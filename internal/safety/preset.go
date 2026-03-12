package safety

import (
	"fmt"
	"regexp"
	"slices"
)

// Built-in preset names.
const (
	PresetDestructiveSQL       = "destructive-sql"
	PresetDestructiveOSCommand = "destructive-os-command"
)

// sqlWS matches SQL whitespace including inline comments (/**/) which are a
// common WAF-bypass technique (CWE-185). Used in place of bare `\s+`.
const sqlWS = `(\s|/\*.*?\*/)+`

// sqlIdent matches SQL identifiers including schema-qualified names
// (schema.table) and quoted identifiers ("table", `table`).
const sqlIdent = `[\w."` + "`" + `]+`

// destructiveSQLRules defines rules that detect destructive SQL operations.
// Diagnostic payloads used for vulnerability assessment (e.g. UNION SELECT,
// OR 1=1) are intentionally excluded — only operations that can cause data
// loss or schema damage are matched.
var destructiveSQLRules = []RuleConfig{
	{
		ID:      "destructive-sql:drop",
		Name:    "DROP statement",
		Pattern: `(?i)DROP` + sqlWS + `(TABLE|DATABASE|INDEX|VIEW|SCHEMA)` + sqlWS,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:truncate",
		Name:    "TRUNCATE TABLE",
		Pattern: `(?i)TRUNCATE` + sqlWS + `TABLE` + sqlWS,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:delete-no-where",
		Name:    "DELETE without WHERE clause",
		Pattern: `(?i)DELETE` + sqlWS + `FROM` + sqlWS + sqlIdent + `\s*($|;|--|LIMIT|ORDER)`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:update-all",
		Name:    "UPDATE all rows (WHERE 1=1)",
		Pattern: `(?i)UPDATE` + sqlWS + sqlIdent + sqlWS + `SET` + sqlWS + `.*WHERE` + sqlWS + `1\s*=\s*1`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:alter-drop",
		Name:    "ALTER TABLE DROP",
		Pattern: `(?i)ALTER` + sqlWS + `TABLE` + sqlWS + sqlIdent + sqlWS + `DROP` + sqlWS,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-sql:exec-xp",
		Name:    "SQL Server extended stored procedure",
		Pattern: `(?i)(EXEC|EXECUTE)` + sqlWS + `xp_`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
}

// destructiveOSCommandRules defines rules that detect destructive OS commands.
var destructiveOSCommandRules = []RuleConfig{
	{
		ID:      "destructive-os:rm-rf",
		Name:    "rm -rf",
		Pattern: `rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r|rm\s+-r\s+-f|rm\s+-f\s+-r|rm\s+--recursive\s+--force|rm\s+--force\s+--recursive`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-os:shutdown",
		Name:    "Shutdown/reboot command",
		Pattern: `(?i)(shutdown|reboot|halt|poweroff)\s`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-os:mkfs",
		Name:    "Filesystem creation (mkfs)",
		Pattern: `mkfs[.\s]`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-os:dd-if",
		Name:    "Disk write (dd)",
		Pattern: `dd\s+if=`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
	},
	{
		ID:      "destructive-os:format",
		Name:    "Windows format command",
		Pattern: `(?i)format\s+[a-zA-Z]:`,
		Targets: []Target{TargetBody, TargetURL, TargetQuery},
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
	slices.Sort(names)
	return names
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
