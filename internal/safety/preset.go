package safety

// PresetRule defines a rule template embedded in the binary.
// Users can override Replacement when loading a preset.
type PresetRule struct {
	ID          string
	Name        string
	Pattern     string
	Targets     []Target
	Action      Action
	Replacement string
}

// Preset groups related rules under a named category.
type Preset struct {
	Name  string
	Rules []PresetRule
}

// builtinPresets holds all compiled-in preset definitions.
// Additional presets will be added in USK-305.
var builtinPresets = map[string]Preset{
	"destructive-sql": {
		Name: "destructive-sql",
		Rules: []PresetRule{
			{
				ID:      "destructive-sql-drop",
				Name:    "SQL DROP statement",
				Pattern: `(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b`,
				Targets: []Target{TargetBody, TargetQuery},
				Action:  ActionBlock,
			},
			{
				ID:      "destructive-sql-truncate",
				Name:    "SQL TRUNCATE statement",
				Pattern: `(?i)\bTRUNCATE\s+TABLE\b`,
				Targets: []Target{TargetBody, TargetQuery},
				Action:  ActionBlock,
			},
		},
	},
	"sensitive-data": {
		Name: "sensitive-data",
		Rules: []PresetRule{
			{
				ID:          "sensitive-data-credit-card",
				Name:        "Credit card number",
				Pattern:     `\b(?:\d[- ]*?){13,19}\b`,
				Targets:     []Target{TargetBody},
				Action:      ActionMask,
				Replacement: "[REDACTED-CC]",
			},
		},
	},
}

// LookupPreset returns the preset with the given name, or nil if not found.
func LookupPreset(name string) *Preset {
	p, ok := builtinPresets[name]
	if !ok {
		return nil
	}
	return &p
}

// PresetNames returns the names of all available built-in presets.
func PresetNames() []string {
	names := make([]string, 0, len(builtinPresets))
	for name := range builtinPresets {
		names = append(names, name)
	}
	return names
}
