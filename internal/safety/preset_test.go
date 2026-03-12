package safety

import (
	"regexp"
	"testing"
)

func TestDestructiveSQLRules_Match(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   string
		matched bool
	}{
		// destructive-sql:drop
		{"drop table", "destructive-sql:drop", "DROP TABLE users", true},
		{"drop database", "destructive-sql:drop", "drop database mydb", true},
		{"drop index", "destructive-sql:drop", "DROP INDEX idx_name", true},
		{"drop view", "destructive-sql:drop", "DROP VIEW v_users", true},
		{"drop schema", "destructive-sql:drop", "DROP SCHEMA public", true},
		{"drop mixed case", "destructive-sql:drop", "Drop Table accounts", true},
		{"select with drop substring", "destructive-sql:drop", "SELECT * FROM dropdown", false},
		{"select normal", "destructive-sql:drop", "SELECT * FROM users", false},

		// destructive-sql:truncate
		{"truncate table", "destructive-sql:truncate", "TRUNCATE TABLE users", true},
		{"truncate lowercase", "destructive-sql:truncate", "truncate table logs", true},
		{"truncate no table keyword", "destructive-sql:truncate", "TRUNCATE users", false},

		// destructive-sql:delete-no-where
		{"delete no where", "destructive-sql:delete-no-where", "DELETE FROM users", true},
		{"delete semicolon", "destructive-sql:delete-no-where", "DELETE FROM users;", true},
		{"delete comment", "destructive-sql:delete-no-where", "DELETE FROM users--", true},
		{"delete with limit", "destructive-sql:delete-no-where", "DELETE FROM users LIMIT 100", true},
		{"delete with order", "destructive-sql:delete-no-where", "DELETE FROM users ORDER BY id", true},
		{"delete schema-qualified", "destructive-sql:delete-no-where", "DELETE FROM public.users", true},
		{"delete quoted table", "destructive-sql:delete-no-where", `DELETE FROM "users"`, true},
		{"delete with where", "destructive-sql:delete-no-where", "DELETE FROM users WHERE id=1", false},

		// destructive-sql:update-all
		{"update where 1=1", "destructive-sql:update-all", "UPDATE users SET admin=1 WHERE 1=1", true},
		{"update where 1 = 1 spaces", "destructive-sql:update-all", "UPDATE users SET admin=1 WHERE 1 = 1", true},
		{"update schema-qualified", "destructive-sql:update-all", "UPDATE public.users SET admin=1 WHERE 1=1", true},
		{"update quoted table", "destructive-sql:update-all", `UPDATE "users" SET admin=1 WHERE 1=1`, true},
		{"update with condition", "destructive-sql:update-all", "UPDATE users SET admin=1 WHERE id=5", false},

		// destructive-sql:alter-drop
		{"alter drop column", "destructive-sql:alter-drop", "ALTER TABLE users DROP COLUMN email", true},
		{"alter drop lowercase", "destructive-sql:alter-drop", "alter table users drop column name", true},
		{"alter drop schema-qualified", "destructive-sql:alter-drop", "ALTER TABLE public.users DROP COLUMN email", true},
		{"alter add column", "destructive-sql:alter-drop", "ALTER TABLE users ADD COLUMN email VARCHAR(255)", false},

		// destructive-sql:exec-xp
		{"exec xp_cmdshell", "destructive-sql:exec-xp", "EXEC xp_cmdshell 'whoami'", true},
		{"execute xp_cmdshell", "destructive-sql:exec-xp", "EXECUTE xp_cmdshell 'dir'", true},
		{"exec normal proc", "destructive-sql:exec-xp", "EXEC sp_helpdb", false},

		// SQL inline comment bypass (S-4).
		{"drop with inline comment", "destructive-sql:drop", "DROP/**/TABLE users", true},
		{"truncate with inline comment", "destructive-sql:truncate", "TRUNCATE/**/TABLE users", true},
		{"delete with inline comment", "destructive-sql:delete-no-where", "DELETE/**/FROM/**/users", true},
		{"exec with inline comment", "destructive-sql:exec-xp", "EXEC/**/xp_cmdshell 'whoami'", true},

		// Diagnostic payloads must NOT match any destructive-sql rule.
		{"union select", "destructive-sql:drop", "UNION SELECT 1,2,3--", false},
		{"or 1=1", "destructive-sql:drop", "' OR 1=1--", false},
		{"select version", "destructive-sql:drop", "SELECT @@version", false},
	}

	ruleMap := buildRuleMap(t, destructiveSQLRules)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, ok := ruleMap[tt.ruleID]
			if !ok {
				t.Fatalf("rule %q not found", tt.ruleID)
			}
			got := re.MatchString(tt.input)
			if got != tt.matched {
				t.Errorf("rule %s on %q: got %v, want %v", tt.ruleID, tt.input, got, tt.matched)
			}
		})
	}
}

func TestDestructiveOSCommandRules_Match(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   string
		matched bool
	}{
		// destructive-os:rm-rf
		{"rm -rf /", "destructive-os:rm-rf", "rm -rf /", true},
		{"rm -rf dir", "destructive-os:rm-rf", "rm -rf /tmp/data", true},
		{"rm -fr", "destructive-os:rm-rf", "rm -fr /var/log", true},
		{"rm -r -f separated", "destructive-os:rm-rf", "rm -r -f /tmp/data", true},
		{"rm -f -r separated", "destructive-os:rm-rf", "rm -f -r /tmp/data", true},
		{"rm --recursive --force", "destructive-os:rm-rf", "rm --recursive --force /tmp/data", true},
		{"rm --force --recursive", "destructive-os:rm-rf", "rm --force --recursive /tmp/data", true},
		{"rm single file", "destructive-os:rm-rf", "rm file.txt", false},
		{"rm -r only", "destructive-os:rm-rf", "rm -r dir", false},

		// destructive-os:shutdown
		{"shutdown", "destructive-os:shutdown", "shutdown -h now", true},
		{"reboot", "destructive-os:shutdown", "reboot ", true},
		{"halt", "destructive-os:shutdown", "halt ", true},
		{"poweroff", "destructive-os:shutdown", "poweroff ", true},
		{"shutdown in text", "destructive-os:shutdown", "the shutdown process", true},
		{"shutdown no space", "destructive-os:shutdown", "shutdown", false},

		// destructive-os:mkfs
		{"mkfs ext4", "destructive-os:mkfs", "mkfs /dev/sda1", true},
		{"mkfs.ext4", "destructive-os:mkfs", "mkfs.ext4 /dev/sda1", true},
		{"mkfs.xfs", "destructive-os:mkfs", "mkfs.xfs /dev/sdb", true},

		// destructive-os:dd-if
		{"dd if=/dev/zero", "destructive-os:dd-if", "dd if=/dev/zero of=/dev/sda", true},
		{"dd without if", "destructive-os:dd-if", "dd of=/tmp/test", false},

		// destructive-os:format
		{"format C:", "destructive-os:format", "format C:", true},
		{"format D:", "destructive-os:format", "FORMAT D:", true},
		{"format text", "destructive-os:format", "format the document", false},

		// Safe commands must NOT match.
		{"ls", "destructive-os:rm-rf", "ls -la /tmp", false},
		{"cat", "destructive-os:rm-rf", "cat /etc/passwd", false},
		{"echo", "destructive-os:shutdown", "echo hello", false},
	}

	ruleMap := buildRuleMap(t, destructiveOSCommandRules)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, ok := ruleMap[tt.ruleID]
			if !ok {
				t.Fatalf("rule %q not found", tt.ruleID)
			}
			got := re.MatchString(tt.input)
			if got != tt.matched {
				t.Errorf("rule %s on %q: got %v, want %v", tt.ruleID, tt.input, got, tt.matched)
			}
		})
	}
}

func TestLookupPreset(t *testing.T) {
	t.Run("existing preset", func(t *testing.T) {
		p, err := LookupPreset(PresetDestructiveSQL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name != PresetDestructiveSQL {
			t.Errorf("name = %q, want %q", p.Name, PresetDestructiveSQL)
		}
		if len(p.Rules) == 0 {
			t.Error("expected rules, got none")
		}
	})

	t.Run("os-command preset", func(t *testing.T) {
		p, err := LookupPreset(PresetDestructiveOSCommand)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name != PresetDestructiveOSCommand {
			t.Errorf("name = %q, want %q", p.Name, PresetDestructiveOSCommand)
		}
		if len(p.Rules) == 0 {
			t.Error("expected rules, got none")
		}
	})

	t.Run("unknown preset", func(t *testing.T) {
		_, err := LookupPreset("nonexistent")
		if err == nil {
			t.Fatal("expected error for unknown preset")
		}
	})
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 presets, got %d", len(names))
	}
	// Should be sorted alphabetically.
	if names[0] != PresetDestructiveOSCommand {
		t.Errorf("names[0] = %q, want %q", names[0], PresetDestructiveOSCommand)
	}
	if names[1] != PresetDestructiveSQL {
		t.Errorf("names[1] = %q, want %q", names[1], PresetDestructiveSQL)
	}
}

func TestCompilePreset(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := LookupPreset(PresetDestructiveSQL)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		rules, err := CompilePreset(p, ActionBlock)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if len(rules) != len(p.Rules) {
			t.Fatalf("compiled %d rules, want %d", len(rules), len(p.Rules))
		}
		for _, r := range rules {
			if r.Pattern == nil {
				t.Errorf("rule %s has nil pattern", r.ID)
			}
			if r.Action != ActionBlock {
				t.Errorf("rule %s action = %d, want ActionBlock", r.ID, r.Action)
			}
			if r.Category != PresetDestructiveSQL {
				t.Errorf("rule %s category = %q, want %q", r.ID, r.Category, PresetDestructiveSQL)
			}
		}
	})

	t.Run("invalid pattern", func(t *testing.T) {
		bad := Preset{
			Name: "bad",
			Rules: []RuleConfig{
				{ID: "bad:1", Pattern: `(?P<name>[`, Targets: []Target{TargetBody}},
			},
		}
		_, err := CompilePreset(bad, ActionBlock)
		if err == nil {
			t.Fatal("expected error for invalid pattern")
		}
	})
}

func TestAllPresetPatternsCompile(t *testing.T) {
	for _, name := range PresetNames() {
		p, err := LookupPreset(name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		for _, rc := range p.Rules {
			t.Run(rc.ID, func(t *testing.T) {
				_, err := regexp.Compile(rc.Pattern)
				if err != nil {
					t.Errorf("pattern %q does not compile: %v", rc.Pattern, err)
				}
			})
		}
	}
}

func TestRuleConfigTargets(t *testing.T) {
	t.Run("sql rules have body+url+query targets", func(t *testing.T) {
		for _, rc := range destructiveSQLRules {
			if len(rc.Targets) != 3 {
				t.Errorf("rule %s: expected 3 targets, got %d", rc.ID, len(rc.Targets))
				continue
			}
			if rc.Targets[0] != TargetBody || rc.Targets[1] != TargetURL || rc.Targets[2] != TargetQuery {
				t.Errorf("rule %s: targets = %v, want [Body, URL, Query]", rc.ID, rc.Targets)
			}
		}
	})

	t.Run("os-command rules have body+url+query targets", func(t *testing.T) {
		for _, rc := range destructiveOSCommandRules {
			if len(rc.Targets) != 3 {
				t.Errorf("rule %s: expected 3 targets, got %d", rc.ID, len(rc.Targets))
				continue
			}
			if rc.Targets[0] != TargetBody || rc.Targets[1] != TargetURL || rc.Targets[2] != TargetQuery {
				t.Errorf("rule %s: targets = %v, want [Body, URL, Query]", rc.ID, rc.Targets)
			}
		}
	})
}

func TestRuleConfigIDs_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for _, name := range PresetNames() {
		p, _ := LookupPreset(name)
		for _, rc := range p.Rules {
			if seen[rc.ID] {
				t.Errorf("duplicate rule ID: %s", rc.ID)
			}
			seen[rc.ID] = true
		}
	}
}

func TestFalsePositives_CommonSQL(t *testing.T) {
	// Common SQL queries that should NOT trigger any destructive-sql rule.
	inputs := []string{
		"SELECT * FROM users WHERE id = 1",
		"INSERT INTO users (name, email) VALUES ('test', 'test@example.com')",
		"UPDATE users SET name = 'new' WHERE id = 5",
		"DELETE FROM users WHERE id = 10",
		"SELECT COUNT(*) FROM orders",
		"SELECT u.name FROM users u JOIN orders o ON u.id = o.user_id",
		"CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY)",
		// Diagnostic payloads for vulnerability assessment.
		"' OR 1=1--",
		"UNION SELECT 1,2,3,4--",
		"' AND SUBSTRING(@@version,1,1)='5",
		"SELECT LOAD_FILE('/etc/passwd')",
		"1; WAITFOR DELAY '0:0:5'--",
	}

	rules := compileRules(t, destructiveSQLRules)

	for _, input := range inputs {
		for _, r := range rules {
			if r.Pattern.MatchString(input) {
				t.Errorf("false positive: rule %s matched %q", r.ID, input)
			}
		}
	}
}

func TestFalsePositives_CommonShellCommands(t *testing.T) {
	// Common shell commands that should NOT trigger any destructive-os rule.
	inputs := []string{
		"ls -la /tmp",
		"cat /etc/passwd",
		"echo hello world",
		"grep -r pattern .",
		"curl https://example.com",
		"wget https://example.com/file",
		"rm file.txt",
		"rm -r empty_dir",
		"cp -r src dest",
		"mv old new",
		"chmod 644 file",
		"chown user:group file",
		"ps aux",
		"netstat -tlnp",
		"ifconfig eth0",
	}

	rules := compileRules(t, destructiveOSCommandRules)

	for _, input := range inputs {
		for _, r := range rules {
			if r.Pattern.MatchString(input) {
				t.Errorf("false positive: rule %s matched %q", r.ID, input)
			}
		}
	}
}

// buildRuleMap compiles RuleConfig entries into a map of ID -> compiled regexp.
func buildRuleMap(t *testing.T, configs []RuleConfig) map[string]*regexp.Regexp {
	t.Helper()
	m := make(map[string]*regexp.Regexp, len(configs))
	for _, rc := range configs {
		re, err := regexp.Compile(rc.Pattern)
		if err != nil {
			t.Fatalf("compile %s: %v", rc.ID, err)
		}
		m[rc.ID] = re
	}
	return m
}

// compileRules compiles RuleConfig entries into Rule structs for testing.
func compileRules(t *testing.T, configs []RuleConfig) []Rule {
	t.Helper()
	rules := make([]Rule, 0, len(configs))
	for _, rc := range configs {
		re, err := regexp.Compile(rc.Pattern)
		if err != nil {
			t.Fatalf("compile %s: %v", rc.ID, err)
		}
		rules = append(rules, Rule{
			ID:      rc.ID,
			Pattern: re,
		})
	}
	return rules
}
